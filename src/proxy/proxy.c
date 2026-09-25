#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include "src/dns/doh_resolve.h"

#define MAX_CHILDREN 64
#define DNS_PROXY_MARK 0x4d5f

static volatile int running = 1;
static volatile sig_atomic_t child_count = 0;
static unsigned int child_limit_logs;
static void on_sig(int s) { (void)s; running = 0; }
static void on_chld(int s) {
    (void)s;
    pid_t pid;
    while ((pid = waitpid(-1, NULL, WNOHANG)) > 0) {
        if (child_count > 0) child_count--;
    }
}

// Неблокирующий stderr: при полном pipe (webui) fprintf не должен вешать
// recvfrom-цикл — иначе Recv-Q на :53 растёт и DNS мерт.
static void make_stderr_nonblock(void) {
    int fl = fcntl(STDERR_FILENO, F_GETFL, 0);
    if (fl >= 0) fcntl(STDERR_FILENO, F_SETFL, fl | O_NONBLOCK);
}

static void plog(const char *fmt, ...) {
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0) {
        ssize_t w = write(STDERR_FILENO, buf, (size_t)n);
        (void)w;
    }
}

struct hosts { char domain[128]; char ip[64]; };
static struct hosts *hlist = NULL;
static int hcount = 0;

static void load_hosts(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        // try next to binary (webui/proxy may start with different cwd)
        char exe[1024];
        ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
        if (n > 0) {
            exe[n] = '\0';
            char *slash = strrchr(exe, '/');
            if (slash) {
                *slash = '\0';
                // build/bin -> project root (../..) or same dir
                char alt[1200];
                snprintf(alt, sizeof(alt), "%s/../../hosts.txt", exe);
                f = fopen(alt, "r");
                if (!f) {
                    snprintf(alt, sizeof(alt), "%s/../hosts.txt", exe);
                    f = fopen(alt, "r");
                }
                if (!f) {
                    snprintf(alt, sizeof(alt), "%s/hosts.txt", exe);
                    f = fopen(alt, "r");
                }
            }
        }
    }
    if (!f) { plog("[PROXY] no hosts file: %s\n", path); return; }
    hlist = calloc(512, sizeof(struct hosts));
    if (!hlist) { fclose(f); return; }
    char line[256];
    while (fgets(line, sizeof(line), f) && hcount < 512) {
        line[strcspn(line, "\r\n")] = 0;
        if (line[0] == '#' || line[0] == '\0') continue;
        char *sp = strchr(line, ' ');
        if (!sp) continue;
        *sp = 0;
        char *ip = sp + 1;
        while (*ip == ' ' || *ip == '\t') ip++;
        struct in_addr tmp;
        if (inet_pton(AF_INET, ip, &tmp) != 1) continue;
        snprintf(hlist[hcount].domain, sizeof(hlist[hcount].domain), "%.127s", line);
        snprintf(hlist[hcount].ip, sizeof(hlist[hcount].ip), "%.63s", ip);
        hcount++;
    }
    fclose(f);
    plog("[PROXY] hosts: %d\n", hcount);
}

static int find_host(const char *dom, char *ip, int iplen) {
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s", dom);
    int l = strlen(tmp);
    if (l > 0 && tmp[l-1] == '.') tmp[l-1] = 0;
    for (int i = 0; i < hcount; i++) {
        if (strcasecmp(tmp, hlist[i].domain) == 0) {
            snprintf(ip, iplen, "%s", hlist[i].ip);
            return 1;
        }
    }
    for (int i = 0; i < hcount; i++) {
        int bl = strlen(hlist[i].domain);
        int tl = strlen(tmp);
        if (tl > bl && tmp[tl - bl] == '.' && strcasecmp(tmp + tl - bl, hlist[i].domain) == 0) {
            snprintf(ip, iplen, "%s", hlist[i].ip);
            return 1;
        }
    }
    return 0;
}

static void get_qname(const unsigned char *pkt, int len, char *out, int outlen) {
    int pos = 12, o = 0;
    while (pos < len && pkt[pos] != 0 && o < outlen - 1) {
        int ll = pkt[pos++];
        if ((ll & 0xC0) == 0xC0) break;
        if (o > 0) out[o++] = '.';
        for (int i = 0; i < ll && pos < len && o < outlen - 1; i++)
            out[o++] = (char)pkt[pos++];
    }
    out[o] = 0;
}

static int skip_qname(const unsigned char *pkt, int len) {
    int pos = 12;
    while (pos < len && pkt[pos] != 0) {
        int ll = pkt[pos++];
        if ((ll & 0xC0) == 0xC0) { pos++; break; }
        pos += ll;
    }
    if (pos < len) pos++;
    return pos;
}
static int build_a_resp(const unsigned char *q, int ql, unsigned char *buf, int buflen, const char *ip) {
    int qpos = skip_qname(q, ql);
    int qsection_len = qpos + 4;
    if (qsection_len > ql || buflen < qsection_len + 24) return -1;
    memset(buf, 0, buflen);
    memcpy(buf, q, qsection_len);
    unsigned char *r = buf;
    r[2] = 0x81; r[3] = 0x80;
    r[6] = 0; r[7] = 1;
    r[8] = 0; r[9] = 0;
    int o = qsection_len;
    r[o++] = 0xC0; r[o++] = 0x0C;
    r[o++] = 0x00; r[o++] = 0x01;
    r[o++] = 0x00; r[o++] = 0x01;
    r[o++] = 0x00; r[o++] = 0x00; r[o++] = 0x00; r[o++] = 0x78;
    r[o++] = 0x00; r[o++] = 0x04;
    struct in_addr a;
    if (inet_pton(AF_INET, ip, &a) != 1) return -1;
    memcpy(r + o, &a, 4);
    o += 4;
    r[10] = 0; r[11] = 0;
    return o;
}

static int forward_q(const unsigned char *q, int ql, unsigned char *ans, int anslen, const char *up) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    unsigned int mark = DNS_PROXY_MARK;
    setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(53);
    if (inet_pton(AF_INET, up, &sa.sin_addr) != 1) {
        close(fd);
        return -1;
    }
    if (sendto(fd, q, ql, 0, (struct sockaddr*)&sa, sizeof(sa)) != ql) {
        close(fd);
        return -1;
    }
    struct pollfd pfd = {fd, POLLIN, 0};
    int rc = poll(&pfd, 1, 2000);
    ssize_t n = -1;
    if (rc > 0 && (pfd.revents & POLLIN)) {
        n = recvfrom(fd, ans, anslen, 0, NULL, NULL);
        if (n >= 12 && (ans[0] != q[0] || ans[1] != q[1])) n = -1;
    }
    close(fd);
    return (int)n;
}

int run_proxy(int argc, char **argv) {
    int port = 53;
    const char *up = "1.1.1.1";
    const char *fb = "8.8.8.8";
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i+1 < argc) port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--upstream") == 0 && i+1 < argc) up = argv[++i];
        else if (strcmp(argv[i], "--fallback") == 0 && i+1 < argc) fb = argv[++i];
    }

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);
    signal(SIGCHLD, on_chld);
    make_stderr_nonblock();

    load_hosts("hosts.txt");

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 1; }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        plog("[PROXY] bind %d: %s\n", port, strerror(errno));
        return 1;
    }
    plog("[PROXY] listening :%d upstream %s/%s\n", port, up, fb);

    unsigned char qbuf[512], rbuf[1024];
    char dom[256];

    while (running) {
        struct pollfd pfd = {fd, POLLIN, 0};
        if (poll(&pfd, 1, 1000) <= 0) continue;

        while (running) {
            struct sockaddr_in cli;
            socklen_t cl = sizeof(cli);
            ssize_t n = recvfrom(fd, qbuf, sizeof(qbuf), MSG_DONTWAIT, (struct sockaddr*)&cli, &cl);
            if (n < 12) break;

            get_qname(qbuf, (int)n, dom, sizeof(dom));
            int qpos = skip_qname(qbuf, (int)n);
            int qtype = (qpos + 1 < n) ? (qbuf[qpos] << 8) | qbuf[qpos + 1] : 0;

            char pinned[64] = {0};
            if (qtype == 1 && find_host(dom, pinned, sizeof(pinned))) {
                int rl = build_a_resp(qbuf, (int)n, rbuf, sizeof(rbuf), pinned);
                if (rl > 0) {
                    plog("[PROXY] %s -> %s\n", dom, pinned);
                    sendto(fd, rbuf, rl, 0, (struct sockaddr*)&cli, cl);
                    continue;
                }
            }

            if (child_count >= MAX_CHILDREN) {
                if ((child_limit_logs++ & 63U) == 0)
                    plog("[PROXY] child limit reached\n");
                continue;
            }

            sigset_t block_chld, old_mask;
            sigemptyset(&block_chld);
            sigaddset(&block_chld, SIGCHLD);
            sigprocmask(SIG_BLOCK, &block_chld, &old_mask);
            pid_t child = fork();
            if (child == 0) {
                sigprocmask(SIG_SETMASK, &old_mask, NULL);
                prctl(PR_SET_PDEATHSIG, SIGTERM);
                if (getppid() == 1) _exit(0);
                int rl = -1;
                if (qtype == 1) {
                    char doh_ip[64] = {0};
                    if (doh_resolve_a(dom, doh_ip, sizeof(doh_ip)) == 0)
                        rl = build_a_resp(qbuf, (int)n, rbuf, sizeof(rbuf), doh_ip);
                }
                if (rl <= 0) rl = forward_q(qbuf, (int)n, rbuf, sizeof(rbuf), up);
                if (rl <= 0) rl = forward_q(qbuf, (int)n, rbuf, sizeof(rbuf), fb);
                if (rl > 0)
                    sendto(fd, rbuf, rl, 0, (struct sockaddr*)&cli, cl);
                _exit(0);
            }
            if (child < 0) {
                plog("[PROXY] fork: %s\n", strerror(errno));
            } else {
                child_count++;
            }
            sigprocmask(SIG_SETMASK, &old_mask, NULL);
        }
    }
    close(fd);
    free(hlist);
    return 0;
}
