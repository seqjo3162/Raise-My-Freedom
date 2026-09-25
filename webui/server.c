#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <dirent.h>
#include <poll.h>
#include <ctype.h>
#include "../src/plugin_api.h"

#define DEFAULT_PORT 8080
#define MAX_PLUGINS 64
#define LOG_MAX 1000
#define BUF_SIZE 65536
#define IO_TIMEOUT_MS 2000
#define PROXY_BIN "build/bin/rmf"
#define PLUGS_DIR "build/bin/plugs"
#define BACKUP_DIR "backups"

static volatile int running = 1;
static pid_t proxy_pid = 0;
static int proxy_pipe[2] = {-1, -1};
static int server_fd = -1;
static int listen_port = DEFAULT_PORT;

static void terminate_process(pid_t pid);

typedef struct {
    char name[128];
    pid_t pid;
    int active;
} plugin_proc_t;

static plugin_proc_t plugins[MAX_PLUGINS];
static int plugin_count = 0;

typedef struct {
    char lines[LOG_MAX][512];
    int count;
    int head;
} LogRing;

static LogRing log_ring = {0};

static char g_project_root[512];

static void log_add(const char *line) {
    snprintf(log_ring.lines[log_ring.head], 512, "%s", line);
    log_ring.head = (log_ring.head + 1) % LOG_MAX;
    if (log_ring.count < LOG_MAX) log_ring.count++;
}

// Фильтрованный вывод логов. tag — метка сервиса вида [discord], если она есть,
// иначе берётся первое слово строки. Остальное ищется как обычная подстрока.
static void log_read_filtered(const char *tag, const char *q, int limit, char *out, size_t out_size) {
    int n = log_ring.count < LOG_MAX ? log_ring.count : LOG_MAX;
    int start = (log_ring.count < LOG_MAX) ? 0 : log_ring.head;
    int emitted = 0;
    out[0] = '\0';
    strncat(out, "[", out_size - strlen(out) - 1);
    for (int i = 0; i < n; i++) {
        int idx = (start + i) % LOG_MAX;
        const char *line = log_ring.lines[idx];
        if (line[0] == '\0') continue;

        if (tag && tag[0]) {
            char needle[128];
            snprintf(needle, sizeof(needle), "[%s]", tag);
            if (!strstr(line, needle)) continue;
        }
        if (q && q[0] && !strstr(line, q)) continue;
        if (limit > 0 && emitted >= limit) break;

        if (emitted) strncat(out, ",", out_size - strlen(out) - 1);
        char esc[1024] = {0};
        int j = 0;
        for (const char *s = line; *s && j < 1022; s++) {
            if (*s == '"' || *s == '\\') esc[j++] = '\\';
            else if (*s == '\n') continue;
            esc[j++] = *s;
        }
        esc[j] = '\0';
        snprintf(out + strlen(out), out_size - strlen(out) - 1, "\"%s\"", esc);
        emitted++;
    }
    strncat(out, "]", out_size - strlen(out) - 1);
}

// ─────────── настройки MTProxy для telegram ───────────
static void send_json(int fd, const char *status, const char *json);
static int start_plugin(const char *name);
static int stop_plugin(const char *name);

// Конфиг держится рядом с сервером, чтобы его можно было править руками.
#define TG_CONF_REL "webui/telegram.conf"
static char g_tg_conf[560];

typedef struct {
    char secret[128];
    int port;
    int prefer_ipv6;
    int fake_tls;
    int ws;
} tg_settings;

static void tg_conf_path(void) {
    snprintf(g_tg_conf, sizeof(g_tg_conf), "%s/%s", g_project_root, TG_CONF_REL);
}

static void tg_conf_load(tg_settings *s) {
    tg_conf_path();
    strncpy(s->secret, "00000000000000000000000000000000", sizeof(s->secret) - 1);
    s->port = 1443;
    s->prefer_ipv6 = 1;
    s->fake_tls = 1;
    s->ws = 1;
    FILE *f = fopen(g_tg_conf, "r");
    if (!f) return;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char *v = eq + 1;
        char *nl = strpbrk(v, "\r\n");
        if (nl) *nl = '\0';
        if (!strcmp(line, "secret")) strncpy(s->secret, v, sizeof(s->secret) - 1);
        else if (!strcmp(line, "port")) s->port = atoi(v);
        else if (!strcmp(line, "prefer_ipv6")) s->prefer_ipv6 = atoi(v);
        else if (!strcmp(line, "fake_tls")) s->fake_tls = atoi(v);
        else if (!strcmp(line, "ws")) s->ws = atoi(v);
    }
    fclose(f);
}

static int tg_conf_save(const tg_settings *s) {
    FILE *f = fopen(g_tg_conf, "w");
    if (!f) return -1;
    fprintf(f, "secret=%s\nport=%d\nprefer_ipv6=%d\nfake_tls=%d\nws=%d\n",
            s->secret, s->port, s->prefer_ipv6, s->fake_tls, s->ws);
    fclose(f);
    return 0;
}

static void telegram_settings_json(int fd) {
    tg_settings s;
    tg_conf_load(&s);
    char json[512];
    // секрет отдаём замаскированным: наружу он не нужен, но длину видно
    char masked[128];
    size_t n = strlen(s.secret);
    snprintf(masked, sizeof(masked), "%.*s%s", (int)(n > 4 ? 4 : n), s.secret,
             n > 4 ? "..." : "");
    snprintf(json, sizeof(json),
             "{\"secret\":\"%s\",\"secret_len\":%zu,\"port\":%d,\"prefer_ipv6\":%d,\"fake_tls\":%d,\"ws\":%d}",
             masked, n, s.port, s.prefer_ipv6, s.fake_tls, s.ws);
    send_json(fd, "200 OK", json);
}

// Применяет настройки и по start=1 перезапускает модуль telegram,
// чтобы новые параметры гарантированно попали в процесс.
static int telegram_apply(const char *secret, int port, int v6, int tls, int ws, int start,
                          char *out, size_t out_size) {
    tg_settings s;
    tg_conf_load(&s);
    if (secret && secret[0]) {
        if (strlen(secret) < 32) {
            snprintf(out, out_size, "{\"ok\":false,\"error\":\"secret должен быть 32 hex-символа\"}");
            return -1;
        }
        for (const char *p = secret; *p; p++) {
            if (!isxdigit((unsigned char)*p)) {
                snprintf(out, out_size, "{\"ok\":false,\"error\":\"secret: только hex-символы\"}");
                return -1;
            }
        }
        strncpy(s.secret, secret, sizeof(s.secret) - 1);
    }
    if (port > 0) {
        if (port < 1024 || port > 65535) {
            snprintf(out, out_size, "{\"ok\":false,\"error\":\"port вне диапазона 1024-65535\"}");
            return -1;
        }
        s.port = port;
    }
    if (v6 >= 0) s.prefer_ipv6 = v6 ? 1 : 0;
    if (tls >= 0) s.fake_tls = tls ? 1 : 0;
    if (ws >= 0) s.ws = ws ? 1 : 0;

    if (tg_conf_save(&s) != 0) {
        snprintf(out, out_size, "{\"ok\":false,\"error\":\"не удалось записать %s\"}", TG_CONF_REL);
        return -1;
    }
    char msg[160];
    snprintf(msg, sizeof(msg), "[telegram] настройки сохранены: :%d, x6=%d, fake_tls=%d, ws=%d",
             s.port, s.prefer_ipv6, s.fake_tls, s.ws);
    log_add(msg);

    if (start) {
        stop_plugin("telegram");
        usleep(300000);
        int r = start_plugin("telegram");
        snprintf(msg, sizeof(msg), "[telegram] перезапуск после смены настроек: %s",
                 r == 0 ? "ok" : (r == -2 ? "уже запущен" : "ошибка"));
        log_add(msg);
    }
    snprintf(out, out_size, "{\"ok\":true,\"port\":%d,\"prefer_ipv6\":%d,\"fake_tls\":%d,\"ws\":%d}",
             s.port, s.prefer_ipv6, s.fake_tls, s.ws);
    return 0;
}


// Читает тело POST по Content-Length (данные могли прийти одним куском с заголовками).
static size_t read_body(int fd, char *buf, size_t used, char *out, size_t cap) {
    const char *cl = strcasestr(buf, "Content-Length:");
    if (!cl) return 0;
    size_t want = (size_t)strtoul(cl + 15, NULL, 10);
    if (want == 0 || want >= cap) return 0;
    const char *body = strstr(buf, "\r\n\r\n");
    if (!body) return 0;
    body += 4;
    size_t have = used - (size_t)(body - buf);
    if (have > want) have = want;
    memcpy(out, body, have);
    while (have < want) {
        ssize_t n = recv(fd, out + have, want - have, 0);
        if (n <= 0) break;
        have += (size_t)n;
    }
    out[have] = '\0';
    return have;
}

// ─────────── конструктор модулей ───────────
#define CTOR_DIR "webui/custom"
#define VALIDATOR_BIN "build/bin/mz-validate"

static void ctor_mkdir(void) { mkdir(CTOR_DIR, 0755); }

// прогоняет спецификацию через валидатор и кладёт его JSON в out
static int ctor_validate_json(const char *spec, char *out, size_t cap) {
    char tmp[] = "/tmp/mzspec-XXXXXX";
    int tf = mkstemp(tmp);
    if (tf < 0) return -1;
    ssize_t w = write(tf, spec, strlen(spec));
    close(tf);
    if (w < 0) { unlink(tmp); return -1; }
    char cmd[1200];
    snprintf(cmd, sizeof(cmd), "%s < %s 2>/dev/null", VALIDATOR_BIN, tmp);
    FILE *p = popen(cmd, "r");
    if (!p) { unlink(tmp); return -1; }
    size_t got = fread(out, 1, cap - 1, p);
    out[got] = '\0';
    pclose(p);
    unlink(tmp);
    return got ? 0 : -1;
}

static void ctor_list(int fd) {
    char json[8192];
    snprintf(json, sizeof(json), "{\"modules\":[");
    DIR *d = opendir(CTOR_DIR);
    int first = 1;
    if (d) {
        struct dirent *e;
        while ((e = readdir(d))) {
            size_t nl = strlen(e->d_name);
            if (nl < 6 || strcmp(e->d_name + nl - 5, ".json") != 0) continue;
            if (strcmp(e->d_name, "active.json") == 0) continue;
            char name[64];
            snprintf(name, sizeof(name), "%.*s", (int)(nl - 5), e->d_name);
            if (!first) strncat(json, ",", sizeof(json) - strlen(json) - 1);
            first = 0;
            snprintf(json + strlen(json), sizeof(json) - strlen(json) - 1,
                     "{\"name\":\"%s\"}", name);
        }
        closedir(d);
    }
    strncat(json, "]}", sizeof(json) - strlen(json) - 1);
    send_json(fd, "200 OK", json);
}

// сохраняет спецификацию в webui/custom/<name>.json, предварительно проверив
static int ctor_save(const char *spec, char *msg, size_t msg_size) {
    // имя берём из спецификации простым поиском
    char name[64] = {0};
    const char *k = strstr(spec, "\"name\"");
    if (k) {
        const char *q = strchr(k + 6, ':');
        if (q) {
            q = strchr(q + 1, '"');
            if (q) {
                q++;
                size_t i = 0;
                while (*q && *q != '"' && i < sizeof(name) - 1) {
                    if (isalnum((unsigned char)*q) || *q == '_' || *q == '-') name[i++] = *q;
                    else break;
                    q++;
                }
                name[i] = '\0';
            }
        }
    }
    if (!name[0]) { snprintf(msg, msg_size, "не удалось прочитать имя модуля"); return -1; }
    ctor_mkdir();
    char path[256];
    snprintf(path, sizeof(path), "%s/%s.json", CTOR_DIR, name);
    FILE *f = fopen(path, "w");
    if (!f) { snprintf(msg, msg_size, "не удалось записать %s", path); return -1; }
    fputs(spec, f);
    fclose(f);

    // та же спецификация становится активной для раннера custom.xo
    char active[256];
    snprintf(active, sizeof(active), "%s/active.json", CTOR_DIR);
    FILE *af = fopen(active, "w");
    if (af) { fputs(spec, af); fclose(af); }

    snprintf(msg, msg_size, "{\"ok\":true,\"name\":\"%s\",\"file\":\"%s\",\"active\":true}", name, path);
    return 0;
}

static void sig_handler(int sig) { (void)sig; running = 0; }
static void reap_children(void) {
    while (waitpid(-1, NULL, WNOHANG) > 0) {
    }
}

static int process_alive(pid_t pid) {
    if (pid <= 0) return 0;
    pid_t result;
    do {
        result = waitpid(pid, NULL, WNOHANG);
    } while (result < 0 && errno == EINTR);
    if (result == pid) return 0;
    if (result < 0 && errno == ECHILD) return 0;
    return kill(pid, 0) == 0;
}

static int port_listening(int port, int udp) {
    if (port <= 0 || port > 65535) return 0;
    const char *paths[] = {"/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"};
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        if ((i < 2) != (udp == 0)) continue;
        FILE *f = fopen(paths[i], "r");
        if (!f) continue;
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            unsigned long long local_ip = 0, local_port = 0;
            unsigned long long remote_ip = 0, remote_port = 0;
            unsigned int state = 0;
            if (sscanf(line, "%*d: %llX:%llX %llX:%llX %X",
                       &local_ip, &local_port, &remote_ip, &remote_port, &state) < 5)
                continue;
            if ((unsigned int)local_port != (unsigned int)port) continue;
            if (!udp && state != 0x0A) continue;
            fclose(f);
            return 1;
        }
        fclose(f);
    }
    return 0;
}

static int plugin_ports(const char *name, int *udp_port, int *tcp_port) {
    static const struct { const char *name; int udp; int tcp; } ports[] = {
        {"activision", 18562, 18462}, {"battlenet", 18563, 18463}, {"cloudflaredns", 0, 0},
        {"discord", 0, 18443}, {"electronicarts", 18564, 18464}, {"epicgames", 18565, 18465},
        {"github", 18590, 18490}, {"google", 0, 18445}, {"roblox", 18566, 18466}, {"soundcloud", 18567, 18467},
        {"speedtestbyookla", 0, 18447}, {"spotify", 18556, 18456}, {"steam", 18568, 18468},
        {"telegram", 0, 1443}, {"twitch", 18558, 18458}, {"vrchat", 15353, 18444},
        {"x", 0, 18446},
        {NULL, 0, 0}
    };
    for (int i = 0; ports[i].name; i++) {
        if (strcmp(ports[i].name, name) == 0) {
            if (udp_port) *udp_port = ports[i].udp;
            if (tcp_port) *tcp_port = ports[i].tcp;
            return 1;
        }
    }
    if (udp_port) *udp_port = 0;
    if (tcp_port) *tcp_port = 0;
    return 0;
}

static int wait_plugin_ready(const char *name, pid_t pid) {
    int udp_port = 0, tcp_port = 0;
    plugin_ports(name, &udp_port, &tcp_port);
    if (udp_port == 0 && tcp_port == 0) {
        for (int i = 0; i < 10; i++) {
            if (!process_alive(pid)) return -1;
            usleep(100000);
        }
        return process_alive(pid) ? 0 : -1;
    }
    for (int i = 0; i < 100; i++) {
        if (!process_alive(pid)) return -1;
        if ((udp_port <= 0 || port_listening(udp_port, 1)) &&
            (tcp_port <= 0 || port_listening(tcp_port, 0))) return 0;
        usleep(100000);
    }
    return -1;
}

static void drain_pipe(void) {
    if (proxy_pipe[0] < 0) return;
    char tmp[4096];
    for (int i = 0; i < 64; i++) {
        ssize_t r = read(proxy_pipe[0], tmp, sizeof(tmp) - 1);
        if (r == 0) {
            close(proxy_pipe[0]);
            proxy_pipe[0] = -1;
            return;
        }
        if (r < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            close(proxy_pipe[0]);
            proxy_pipe[0] = -1;
            return;
        }
        tmp[r] = '\0';
        char *line = strtok(tmp, "\n");
        while (line) { log_add(line); line = strtok(NULL, "\n"); }
    }
}

static int send_all(int fd, const void *data, size_t len) {
    const char *p = (const char *)data;
    while (len > 0) {
        ssize_t n = send(fd, p, len, MSG_NOSIGNAL);
        if (n > 0) {
            p += n;
            len -= (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        return -1;
    }
    return 0;
}

static void set_socket_timeouts(int fd) {
    struct timeval tv = { .tv_sec = IO_TIMEOUT_MS / 1000, .tv_usec = (IO_TIMEOUT_MS % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static ssize_t read_request(int fd, char *buf, size_t cap) {
    size_t used = 0;
    int complete = 0;
    struct timespec started;
    clock_gettime(CLOCK_MONOTONIC, &started);

    while (used + 1 < cap) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed = (now.tv_sec - started.tv_sec) * 1000L +
                       (now.tv_nsec - started.tv_nsec) / 1000000L;
        int remaining = IO_TIMEOUT_MS - (int)elapsed;
        if (remaining <= 0) return -1;

        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int pr = poll(&pfd, 1, remaining);
        if (pr == 0) return -1;
        if (pr < 0) {
            if (errno == EINTR) continue;
            return -1;
        }

        ssize_t n = recv(fd, buf + used, cap - used - 1, 0);
        if (n > 0) {
            used += (size_t)n;
            buf[used] = '\0';
            if (strstr(buf, "\r\n\r\n") || strstr(buf, "\n\n")) {
                complete = 1;
                break;
            }
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        if (n == 0) break;
        return -1;
    }

    buf[used] = '\0';
    return complete ? (ssize_t)used : -1;
}

static void send_response(int fd, const char *status, const char *ct, const char *body) {
    char hdr[512];
    size_t blen = strlen(body);
    int hlen = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
        "Connection: close\r\n\r\n",
        status, ct, blen);
    if (hlen < 0 || (size_t)hlen >= sizeof(hdr)) return;
    if (send_all(fd, hdr, (size_t)hlen) < 0) return;
    (void)send_all(fd, body, blen);
}

static void send_json(int fd, const char *status, const char *json) {
    send_response(fd, status, "application/json", json);
}

static void restore_dns(void) {
    FILE *fp = popen("ip route show default 2>/dev/null | awk '{print $5; exit}'", "r");
    char iface[64] = {0};
    if (fp) {
        if (!fgets(iface, sizeof(iface), fp)) iface[0] = '\0';
        pclose(fp);
    }
    iface[strcspn(iface, "\n")] = 0;
    if (!iface[0]) strncpy(iface, "enp42s0", sizeof(iface) - 1);
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "resolvectl dns %s 8.8.8.8 1.1.1.1 2>/dev/null", iface);
    int rc = system(cmd);
    (void)rc;
}

static void restore_dns_async(void) {
    pid_t pid = fork();
    if (pid == 0) {
        if (server_fd >= 0) close(server_fd);
        if (proxy_pipe[0] >= 0) close(proxy_pipe[0]);
        restore_dns();
        _exit(0);
    }
}

static int spawn_shell(const char *cmd) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        setsid();
        execl("/bin/sh", "sh", "-c", cmd, NULL);
        _exit(127);
    }
    return 0;
}

static int is_proxy_running(void) {
    if (proxy_pid <= 0) return 0;
    if (process_alive(proxy_pid)) return 1;
    proxy_pid = 0;
    if (proxy_pipe[0] >= 0) {
        close(proxy_pipe[0]);
        proxy_pipe[0] = -1;
    }
    return 0;
}

static int wait_proxy_ready(pid_t pid) {
    if (proxy_pipe[0] < 0) return -1;
    char buf[1024];
    for (int i = 0; i < 30; i++) {
        if (!process_alive(pid)) return -1;
        struct pollfd pfd = { .fd = proxy_pipe[0], .events = POLLIN };
        int pr = poll(&pfd, 1, 100);
        if (pr > 0) {
            ssize_t n = read(proxy_pipe[0], buf, sizeof(buf) - 1);
            if (n <= 0) return -1;
            buf[n] = '\0';
            char *line = strtok(buf, "\n");
            while (line) {
                log_add(line);
                if (strstr(line, "[PROXY] listening")) return 0;
                line = strtok(NULL, "\n");
            }
        } else if (pr < 0 && errno != EINTR) {
            return -1;
        }
    }
    return -1;
}

static int start_proxy(void) {
    if (is_proxy_running()) return 0;
    if (proxy_pipe[0] >= 0) {
        close(proxy_pipe[0]);
        proxy_pipe[0] = -1;
    }
    if (proxy_pipe[1] >= 0) {
        close(proxy_pipe[1]);
        proxy_pipe[1] = -1;
    }
    if (pipe2(proxy_pipe, O_CLOEXEC) < 0) return -1;
    fcntl(proxy_pipe[0], F_SETFL, O_NONBLOCK);

    pid_t pid = fork();
    if (pid < 0) {
        close(proxy_pipe[0]);
        proxy_pipe[0] = -1;
        close(proxy_pipe[1]);
        proxy_pipe[1] = -1;
        return -1;
    }
    if (pid == 0) {
        close(proxy_pipe[0]);
        if (dup2(proxy_pipe[1], STDOUT_FILENO) < 0 ||
            dup2(proxy_pipe[1], STDERR_FILENO) < 0)
            _exit(127);
        close(proxy_pipe[1]);
        execl(PROXY_BIN, PROXY_BIN, "proxy", "--port", "53",
              "--upstream", "1.1.1.1", "--fallback", "8.8.8.8", NULL);
        _exit(127);
    }
    close(proxy_pipe[1]);
    proxy_pipe[1] = -1;
    proxy_pid = pid;

    if (wait_proxy_ready(pid) < 0) {
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
        close(proxy_pipe[0]);
        proxy_pipe[0] = -1;
        proxy_pid = 0;
        return -1;
    }

    char timebuf[64];
    time_t now = time(NULL);
    strftime(timebuf, sizeof(timebuf), "%H:%M:%S", localtime(&now));
    char msg[256];
    snprintf(msg, sizeof(msg), "[%s] Proxy started PID %d", timebuf, pid);
    log_add(msg);
    return 0;
}

static void stop_proxy(void) {
    if (proxy_pid <= 0) return;
    pid_t pid = proxy_pid;
    proxy_pid = 0;
    terminate_process(pid);
    if (proxy_pipe[0] >= 0) { close(proxy_pipe[0]); proxy_pipe[0] = -1; }
    restore_dns_async();

    char timebuf[64];
    time_t now = time(NULL);
    strftime(timebuf, sizeof(timebuf), "%H:%M:%S", localtime(&now));
    char msg[256];
    snprintf(msg, sizeof(msg), "[%s] Proxy stopped, DNS restored", timebuf);
    log_add(msg);
}

static plugin_proc_t* find_plugin(const char *name) {
    const char *canonical_name = plugin_canonical_name(name);
    for (int i = 0; i < plugin_count; i++)
        if (strcmp(plugins[i].name, canonical_name) == 0) return &plugins[i];
    return NULL;
}

static plugin_proc_t* add_plugin(const char *name) {
    if (plugin_count >= MAX_PLUGINS) return NULL;
    plugin_proc_t *p = &plugins[plugin_count++];
    memset(p, 0, sizeof(*p));
    snprintf(p->name, sizeof(p->name), "%s", name);
    p->pid = 0;
    p->active = 0;
    return p;
}

static int is_plugin_running(plugin_proc_t *p) {
    if (!p || p->pid <= 0) return 0;
    if (process_alive(p->pid)) return 1;
    p->active = 0;
    p->pid = 0;
    return 0;
}

static void terminate_process(pid_t pid) {
    if (pid <= 0) return;
    kill(pid, SIGTERM);
    pid_t killer = fork();
    if (killer < 0) {
        kill(pid, SIGKILL);
        return;
    }
    if (killer == 0) {
        if (server_fd >= 0) close(server_fd);
        if (proxy_pipe[0] >= 0) close(proxy_pipe[0]);
        usleep(1000000);
        if (kill(pid, 0) == 0) kill(pid, SIGKILL);
        _exit(0);
    }
}

static int start_plugin(const char *name) {
    const char *canonical_name = plugin_canonical_name(name);
    if (!plugin_name_valid(canonical_name)) return -1;
    plugin_proc_t *p = find_plugin(canonical_name);
    if (!p) p = add_plugin(canonical_name);
    if (!p) return -1;
    if (is_plugin_running(p)) return -2;

    if (!is_proxy_running() && start_proxy() < 0) return -1;

    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        char arg[256];
        snprintf(arg, sizeof(arg), "--%s", canonical_name);
        execl(PROXY_BIN, PROXY_BIN, "plugin", arg, NULL);
        _exit(127);
    }
    p->pid = pid;
    p->active = 0;
    if (wait_plugin_ready(canonical_name, pid) < 0) {
        terminate_process(pid);
        waitpid(pid, NULL, 0);
        p->pid = 0;
        p->active = 0;
        return -1;
    }
    p->active = 1;

    char timebuf[64];
    time_t now = time(NULL);
    strftime(timebuf, sizeof(timebuf), "%H:%M:%S", localtime(&now));
    char msg[256];
    snprintf(msg, sizeof(msg), "[%s] Plugin %s started PID %d", timebuf, canonical_name, pid);
    log_add(msg);
    return 0;
}

static int stop_plugin(const char *name) {
    const char *canonical_name = plugin_canonical_name(name);
    if (!plugin_name_valid(canonical_name)) return 0;
    plugin_proc_t *p = find_plugin(canonical_name);
    if (!p) return 0;
    if (p->pid > 0) {
        pid_t pid = p->pid;
        p->pid = 0;
        p->active = 0;
        terminate_process(pid);

        char timebuf[64];
        time_t now = time(NULL);
        strftime(timebuf, sizeof(timebuf), "%H:%M:%S", localtime(&now));
        char msg[256];
        snprintf(msg, sizeof(msg), "[%s] Plugin %s stopped", timebuf, canonical_name);
        log_add(msg);
    }
    p->pid = 0;
    p->active = 0;
    return 0;
}

static void kill_all_rmf(void) {
    pid_t pid = fork();
    if (pid == 0) {
        execl("/usr/bin/pkill", "pkill", "-TERM", "-x", "rmf", (char *)NULL);
        _exit(127);
    }
    if (pid > 0) {
        waitpid(pid, NULL, 0);
        usleep(300000);
        pid = fork();
        if (pid == 0) {
            execl("/usr/bin/pkill", "pkill", "-KILL", "-x", "rmf", (char *)NULL);
            _exit(127);
        }
        if (pid > 0) waitpid(pid, NULL, 0);
    }
}

static void stop_all_plugins(void) {
    for (int i = 0; i < plugin_count; i++)
        stop_plugin(plugins[i].name);
}

static int do_backup(void) {
    mkdir(BACKUP_DIR, 0755);
    char dst[256];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    snprintf(dst, sizeof(dst), BACKUP_DIR "/rmf_%04d%02d%02d_%02d%02d%02d.tar.gz",
        t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
    char cmd[1200];
    snprintf(cmd, sizeof(cmd), "tar czf %s --exclude='%s' --exclude='build' -C . . 2>/dev/null", dst, BACKUP_DIR);
    int r = spawn_shell(cmd);
    char timebuf[64];
    strftime(timebuf, sizeof(timebuf), "%H:%M:%S", t);
    char msg[512];
    snprintf(msg, sizeof(msg), "[%s] Backup: %s (%s)", timebuf, dst, r == 0 ? "started" : "failed");
    log_add(msg);
    return r;
}

static void get_plugins_list(char *out, size_t out_size) {
    DIR *d = opendir(PLUGS_DIR);
    out[0] = '\0';
    strncat(out, "[", out_size - 1);
    int first = 1;
    if (d) {
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (strstr(e->d_name, ".xo")) {
                char name[256];
                snprintf(name, sizeof(name), "%s", e->d_name);
                char *dot = strstr(name, ".xo");
                if (dot) *dot = '\0';
                if (strcmp(plugin_canonical_name(name), name) != 0) continue;
                if (!first) strncat(out, ",", out_size - strlen(out) - 1);
                char item[280];
                snprintf(item, sizeof(item), "\"%s\"", name);
                strncat(out, item, out_size - strlen(out) - 1);
                first = 0;
            }
        }
        closedir(d);
    }
    strncat(out, "]", out_size - strlen(out) - 1);
}

static void get_status_json(char *out, size_t out_size) {
    snprintf(out, out_size, "{\"proxy\":%s,\"plugins\":[", is_proxy_running() ? "true" : "false");
    for (int i = 0; i < plugin_count; i++) {
        if (i > 0) strncat(out, ",", out_size - strlen(out) - 1);
        char item[256];
        snprintf(item, sizeof(item), "{\"name\":\"%.127s\",\"pid\":%d,\"active\":%s}",
            plugins[i].name, plugins[i].pid,
            is_plugin_running(&plugins[i]) ? "true" : "false");
        strncat(out, item, out_size - strlen(out) - 1);
    }
    strncat(out, "]}", out_size - strlen(out) - 1);
}

// Сравнение префикса пути ровно по длине литерала: sizeof даёт длину
// вместе с NUL, поэтому вычитаем единицу. Иначе строка с query-параметрами
// не совпадёт, как это было с /api/constructor/load.
#define path_is(p, lit) (strncmp((p), (lit), sizeof(lit) - 1) == 0)

static void handle_request(int fd) {
    char buf[BUF_SIZE];
    ssize_t n = read_request(fd, buf, sizeof(buf));
    if (n <= 0) { close(fd); return; }

    char method[8] = {0}, path[512] = {0};
    if (sscanf(buf, "%7s %511s", method, path) < 2) {
        send_json(fd, "400 Bad Request", "{\"error\":\"bad request\"}");
        close(fd);
        return;
    }

    if (strcmp(method, "OPTIONS") == 0) {
        send_response(fd, "204 No Content", "text/plain", "");
        close(fd); return;
    }

    if (strcmp(path, "/api/status") == 0) {
        char json[16384];
        get_status_json(json, sizeof(json));
        send_json(fd, "200 OK", json);
    } else if (strncmp(path, "/api/logs", 9) == 0) {
        char json[LOG_MAX * 520 + 16];
        char tag[128] = {0}, q[256] = {0};
        int limit = 0;
        const char *tp = strstr(path, "?tag=");
        if (tp) {
            const char *end = strchr(tp + 5, '&');
            size_t len = end ? (size_t)(end - (tp + 5)) : strlen(tp + 5);
            if (len >= sizeof(tag)) len = sizeof(tag) - 1;
            memcpy(tag, tp + 5, len);
            tag[len] = '\0';
        }
        const char *qp = strstr(path, "?q=");
        if (!qp) qp = strstr(path, "&q=");
        if (qp) {
            const char *end = strchr(qp + 3, '&');
            size_t len = end ? (size_t)(end - (qp + 3)) : strlen(qp + 3);
            if (len >= sizeof(q)) len = sizeof(q) - 1;
            memcpy(q, qp + 3, len);
            q[len] = '\0';
        }
        const char *lp = strstr(path, "limit=");
        if (lp) limit = atoi(lp + 6);
        log_read_filtered(tag, q, limit, json, sizeof(json));
        send_json(fd, "200 OK", json);
    } else if (strncmp(path, "/api/logs/tags", 13) == 0) {
        // список сервисов, встречающихся в логах, для выпадающего фильтра
        char json[4096] = "{\"tags\":[";
        char seen[64][64];
        int nseen = 0, first = 1;
        int n = log_ring.count < LOG_MAX ? log_ring.count : LOG_MAX;
        int start = (log_ring.count < LOG_MAX) ? 0 : log_ring.head;
        for (int i = 0; i < n; i++) {
            const char *line = log_ring.lines[(start + i) % LOG_MAX];
            const char *lb = strchr(line, '[');
            if (!lb) continue;
            const char *rb = strchr(lb + 1, ']');
            if (!rb || rb - lb - 1 <= 0 || rb - lb - 1 > 63) continue;
            char tag[64] = {0};
            size_t tl = (size_t)(rb - lb - 1);
            if (tl > 63) tl = 63;
            memcpy(tag, lb + 1, tl);
            // [16:39:14] — это метка времени, а не сервис
            int is_time = 1;
            for (size_t k = 0; k < tl; k++) {
                if (!isdigit((unsigned char)tag[k]) && tag[k] != ':') { is_time = 0; break; }
            }
            if (is_time) continue;
            int dup = 0;
            for (int k = 0; k < nseen; k++) if (!strcmp(seen[k], tag)) { dup = 1; break; }
            if (dup || nseen >= 64) continue;
            memcpy(seen[nseen++], tag, strlen(tag));
            if (!first) strncat(json, ",", sizeof(json) - strlen(json) - 1);
            first = 0;
            snprintf(json + strlen(json), sizeof(json) - strlen(json) - 1, "\"%s\"", tag);
        }
        strncat(json, "]}", sizeof(json) - strlen(json) - 1);
        send_json(fd, "200 OK", json);
    } else if (path_is(path, "/api/constructor/validate")) {
        char body[32768] = {0};
        read_body(fd, buf, (size_t)n, body, sizeof(body));
        char out[65536];
        if (ctor_validate_json(body, out, sizeof(out)) != 0) {
            send_json(fd, "200 OK", "{\"ok\":false,\"diags\":[{\"level\":\"error\",\"step\":\"engine\",\"msg\":\"валидатор не ответил\",\"hint\":\"соберите его командой: make build/bin/mz-validate\"}],\"summary\":\"валидатор недоступен\"}");
        } else {
            send_json(fd, "200 OK", out);
        }
    } else if (path_is(path, "/api/constructor/save")) {
        char body[32768] = {0};
        read_body(fd, buf, (size_t)n, body, sizeof(body));
        char out[65536];
        if (ctor_validate_json(body, out, sizeof(out)) != 0) {
            send_json(fd, "200 OK", "{\"ok\":false,\"diags\":[{\"level\":\"error\",\"step\":\"engine\",\"msg\":\"валидатор не ответил\",\"hint\":\"соберите его командой: make build/bin/mz-validate\"}]}");
        } else if (!strstr(out, "\"ok\":true")) {
            send_json(fd, "200 OK", out);
        } else {
            char msg[512];
            if (ctor_save(body, msg, sizeof(msg)) != 0) {
                send_json(fd, "500 Internal Server Error",
                          "{\"ok\":false,\"diags\":[{\"level\":\"error\",\"step\":\"save\",\"msg\":\"не удалось сохранить\",\"hint\":\"проверьте права на каталог webui/custom\"}]}");
            } else {
                char both[66560];
                snprintf(both, sizeof(both), "{\"saved\":%s,\"check\":%s}", msg, out);
                send_json(fd, "200 OK", both);
            }
        }
    } else if (path_is(path, "/api/constructor/load")) {
        const char *nm = strstr(path, "name=");
        if (!nm) { send_json(fd, "400 Bad Request", "{\"error\":\"не указано имя\"}"); }
        else {
            char name[64], path2[256];
            size_t len = strcspn(nm + 5, "&");
            if (len >= sizeof(name)) len = sizeof(name) - 1;
            memcpy(name, nm + 5, len);
            name[len] = '\0';
            snprintf(path2, sizeof(path2), "%s/%s.json", CTOR_DIR, name);
            FILE *f = fopen(path2, "r");
            if (!f) send_json(fd, "404 Not Found", "{\"error\":\"модуль не найден\"}");
            else {
                static char spec[32768];
                size_t got = fread(spec, 1, sizeof(spec) - 1, f);
                fclose(f);
                spec[got] = '\0';
                send_json(fd, "200 OK", spec);
            }
        }
    } else if (path_is(path, "/api/constructor/list")) {
        ctor_list(fd);
    } else if (strcmp(path, "/api/telegram") == 0) {
        telegram_settings_json(fd);
    } else if (strncmp(path, "/api/telegram", 12) == 0) {
        // POST /api/telegram?secret=...&port=...&prefer_ipv6=0|1&fake_tls=0|1&ws=0|1
        char secret[128] = {0};
        int port = 0, v6 = -1, tls = -1, ws = -1, started = 0;
        const char *sp = strstr(path, "secret=");
        if (sp) {
            const char *end = strchr(sp + 7, '&');
            size_t len = end ? (size_t)(end - (sp + 7)) : strlen(sp + 7);
            if (len >= sizeof(secret)) len = sizeof(secret) - 1;
            memcpy(secret, sp + 7, len);
            secret[len] = '\0';
        }
        const char *pp = strstr(path, "port=");
        if (pp) port = atoi(pp + 5);
        const char *vp = strstr(path, "prefer_ipv6=");
        if (vp) v6 = atoi(vp + 12);
        const char *tp = strstr(path, "fake_tls=");
        if (tp) tls = atoi(tp + 9);
        const char *wsp = strstr(path, "&ws=");
        if (!wsp) wsp = strstr(path, "ws=");
        if (wsp) ws = atoi(wsp + 3);
        const char *stp = strstr(path, "start=");
        if (stp) started = atoi(stp + 6);

        char msg[256] = {0};
        int r = telegram_apply(secret, port, v6, tls, ws, started, msg, sizeof(msg));
        send_json(fd, r == 0 ? "200 OK" : "400 Bad Request", msg);
    } else if (strcmp(path, "/api/plugins") == 0) {
        char json[4096];
        get_plugins_list(json, sizeof(json));
        send_json(fd, "200 OK", json);
    } else if (strncmp(path, "/api/start", 10) == 0) {
        char plugin[256] = {0};
        const char *qp = strstr(path, "?plugin=");
        if (qp) strncpy(plugin, qp + 8, sizeof(plugin) - 1);
        if (!plugin[0]) { send_json(fd, "400 Bad Request", "{\"error\":\"no plugin\"}"); close(fd); return; }
        int r = start_plugin(plugin);
        if (r == -2) send_json(fd, "200 OK", "{\"ok\":false,\"error\":\"already running\"}");
        else send_json(fd, "200 OK", r == 0 ? "{\"ok\":true}" : "{\"ok\":false,\"error\":\"fork failed\"}");
    } else if (strcmp(path, "/api/stopall") == 0) {
        stop_all_plugins();
        stop_proxy();
        kill_all_rmf();
        send_json(fd, "200 OK", "{\"ok\":true}");
    } else if (strncmp(path, "/api/stop", 9) == 0) {
        char plugin[256] = {0};
        const char *qp = strstr(path, "?plugin=");
        if (qp) strncpy(plugin, qp + 8, sizeof(plugin) - 1);
        if (plugin[0]) stop_plugin(plugin);
        else stop_all_plugins();
        send_json(fd, "200 OK", "{\"ok\":true}");
    } else if (strcmp(path, "/api/backup") == 0) {
        int r = do_backup();
        send_json(fd, "200 OK", r == 0 ? "{\"ok\":true}" : "{\"ok\":false}");
    } else if (strncmp(path, "/api/rebuild", 12) == 0) {
        char plugin[256] = {0};
        const char *qp = strstr(path, "?plugin=");
        if (qp) strncpy(plugin, qp + 8, sizeof(plugin) - 1);
        const char *canonical_name = plugin_canonical_name(plugin);
        if (plugin[0] && !plugin_name_valid(canonical_name)) {
            send_json(fd, "400 Bad Request", "{\"error\":\"invalid plugin\"}");
            close(fd);
            return;
        }
        char cmd[1200];
        if (plugin[0]) snprintf(cmd, sizeof(cmd), "cd %s && make build/bin/plugs/%s.xo 2>&1", g_project_root, canonical_name);
        else snprintf(cmd, sizeof(cmd), "cd %s && make core plugs webui 2>&1", g_project_root);
        int r = spawn_shell(cmd);
        send_json(fd, "200 OK", r == 0 ? "{\"ok\":true,\"queued\":true}" : "{\"ok\":false}");
    } else if (strcmp(path, "/api/flush") == 0) {
        const char *cmd =
            "for ch in GITHUB_BYPASS DISCORD_BYPASS VRCHAT_BYPASS GOOGLE_YT_BYPASS XCOM_BYPASS SPEEDTEST_BYPASS "
            "ACTIVISION_BYPASS BATTLENET_BYPASS ELECTRONICARTS_BYPASS EPICGAMES_BYPASS ROBLOX_BYPASS "
            "SOUNDCLOUD_BYPASS STEAM_BYPASS TWITCH_BYPASS RMF_DNS; do "
            "iptables -t nat -D OUTPUT -j \"$ch\" 2>/dev/null; "
            "iptables -t nat -F \"$ch\" 2>/dev/null; "
            "iptables -t nat -X \"$ch\" 2>/dev/null; "
            "done";
        int r = spawn_shell(cmd);
        log_add("rmf nat chains flush queued");
        send_json(fd, "200 OK", r == 0 ? "{\"ok\":true,\"queued\":true}" : "{\"ok\":false}");
    } else if (strcmp(path, "/api/info") == 0) {
        send_json(fd, "200 OK",
            "{\"name\":\"rmf\",\"version\":\"3.1\",\"api\":["
            "\"GET /api/status\",\"GET /api/plugins\",\"GET /api/logs\","
            "\"POST /api/start?plugin=<name>\",\"POST /api/stop?plugin=<name>\","
            "\"POST /api/stopall\",\"POST /api/backup\","
            "\"POST /api/rebuild?plugin=<name>\",\"POST /api/rebuild\",\"POST /api/flush\","
            "\"POST /api/restart?target=web|proxy\",\"GET /api/info\"]}");
    } else if (strncmp(path, "/api/restart", 12) == 0) {
        char target[64] = {0};
        const char *qp = strstr(path, "?target=");
        if (qp) strncpy(target, qp + 8, sizeof(target) - 1);
        if (strcmp(target, "proxy") == 0) {
            stop_proxy();
            start_proxy();
            log_add("proxy restarted");
            send_json(fd, "200 OK", "{\"ok\":true}");
        } else {
            send_json(fd, "200 OK", "{\"ok\":true,\"note\":\"restarting web\"}");
            running = 0;
        }
    } else if (strcmp(path, "/static/index.html") == 0) {
        const char *fpath = "webui/static/index.html";
        int ff = open(fpath, O_RDONLY | O_CLOEXEC);
        if (ff < 0) {
            send_response(fd, "404 Not Found", "text/plain", "Not Found");
        } else {
            struct stat st;
            if (fstat(ff, &st) < 0 || !S_ISREG(st.st_mode) ||
                st.st_size < 0 || st.st_size > 4 * 1024 * 1024) {
                close(ff);
                send_response(fd, "404 Not Found", "text/plain", "Not Found");
            } else {
                size_t size = (size_t)st.st_size;
                char *body = calloc(size + 1, 1);
                if (!body) {
                    close(ff);
                    send_response(fd, "500 Internal Server Error", "text/plain", "Memory error");
                } else {
                    size_t total = 0;
                    while (total < size) {
                        ssize_t n = read(ff, body + total, size - total);
                        if (n > 0) {
                            total += (size_t)n;
                            continue;
                        }
                        if (n < 0 && errno == EINTR) continue;
                        break;
                    }
                    close(ff);
                    if (total == size) {
                        body[total] = '\0';
                        send_response(fd, "200 OK", "text/html", body);
                    } else {
                        send_response(fd, "500 Internal Server Error", "text/plain", "Read error");
                    }
                    free(body);
                }
            }
        }
    } else {
        char resp[] =
            "HTTP/1.1 302 Found\r\n"
            "Location: /static/index.html\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n\r\n";
        (void)send_all(fd, resp, strlen(resp));
    }
    close(fd);
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGPIPE, SIG_IGN);

    char *project_root = getenv("RMF_ROOT");
    if (!project_root) project_root = getenv("MINIZAPRET_ROOT");
    if (!project_root) {
        char exe_path[512];
        ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
        if (len > 0) {
            exe_path[len] = '\0';
            static char project_dir[512];
            strncpy(project_dir, exe_path, sizeof(project_dir) - 1);
            project_dir[sizeof(project_dir) - 1] = '\0';
            char *p;
            for (int i = 0; i < 3; i++) {
                p = strrchr(project_dir, '/');
                if (p) *p = '\0';
            }
            project_root = project_dir;
        }
    }
    if (!project_root) project_root = ".";
    snprintf(g_project_root, sizeof(g_project_root), "%s", project_root);
    const char *port_value = getenv("RMF_PORT");
    if (!port_value) port_value = getenv("MINIZAPRET_PORT");
    if (port_value && *port_value) {
        char *end = NULL;
        long parsed = strtol(port_value, &end, 10);
        if (end != port_value && *end == '\0' && parsed > 0 && parsed <= 65535)
            listen_port = (int)parsed;
    }
    if (chdir(project_root) < 0) { perror("chdir"); return 1; }

    mkdir("build/bin/plugs", 0755);
    mkdir(BACKUP_DIR, 0755);

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); return 1; }
    server_fd = srv;
    if (fcntl(srv, F_SETFD, FD_CLOEXEC) < 0) { perror("fcntl"); close(srv); return 1; }
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = htons((uint16_t)listen_port)
    };
    if (bind(srv, (struct sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); close(srv); return 1; }

    if (listen(srv, 64) < 0) { perror("listen"); close(srv); return 1; }
    printf("[WEB] http://127.0.0.1:%d\n", listen_port);
    fflush(stdout);

    while (running) {
        struct pollfd fds[2];
        fds[0].fd = srv;
        fds[0].events = POLLIN;
        fds[1].fd = proxy_pipe[0];
        fds[1].events = proxy_pipe[0] >= 0 ? POLLIN : 0;
        int nfds = proxy_pipe[0] >= 0 ? 2 : 1;

        int ret = poll(fds, nfds, 2000);
        if (ret < 0) { if (errno == EINTR) continue; break; }

        if (fds[1].fd >= 0 &&
            (fds[1].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)))
            drain_pipe();

        if (fds[0].revents & POLLIN) {
            struct sockaddr_in cli;
            socklen_t cl = sizeof(cli);
            int cfd = accept(srv, (struct sockaddr*)&cli, &cl);
            if (cfd >= 0) {
                if (fcntl(cfd, F_SETFD, FD_CLOEXEC) < 0) close(cfd);
                else {
                    set_socket_timeouts(cfd);
                    handle_request(cfd);
                }
            }
        }

        reap_children();
        for (int i = 0; i < plugin_count; i++)
            if (plugins[i].active) is_plugin_running(&plugins[i]);
    }

    stop_all_plugins();
    stop_proxy();
    close(srv);
    server_fd = -1;
    return 0;
}
