// Простой TCP-релей без модификации TLS. Общий для модулей, которым нужно
// перенаправить 443 на локальный порт: у каждого модуля свой порт, свой
// SO_MARK и свои настройки, поэтому общий код не создаёт конфликтов.
//
// Отличие от общего src/common/sni_relay.c:
//   - не трогает TLS вообще, ClientHello проходит без изменений;
//   - корректно переживает закрытие одной из сторон (shutdown(SHUT_WR) и
//     продолжение перекачки в другую сторону), а не рвёт соединение целиком;
//   - отправка неблокирующая с ожиданием POLLOUT, поэтому медленный клиент
//     не встаёт вровень с другими соединениями;
//   - не имеет общих настроек с остальными модулями.

#include "src/common/plain_relay.h"
#include "src/common/sni_relay.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <linux/netfilter_ipv4.h>

#define BUF_SIZE        65536
#define CH_TIMEOUT_MS   8000
#define CONN_MAX_SEC     300     // потолок жизни одного соединения
#define CHILD_MAX        512     // больше живых соединений рель не берёт

// Диагностика только по переменной окружения SNI_RELAY_DEBUG=1
static int g_dbg = -1;
static volatile sig_atomic_t g_children = 0;
static long g_rejected = 0;
static int dbg_on(void) {
    if (g_dbg < 0) {
        const char *v = getenv("SNI_RELAY_DEBUG");
        g_dbg = (v && *v && strcmp(v, "0") != 0) ? 1 : 0;
    }
    return g_dbg;
}
static void dbg(const char *fmt, ...) {
    if (!dbg_on()) return;
    // Одним write(): иначе строки от разных соединений перемешиваются в общем
    // канале и читать трассу невозможно.
    char msg[512];
    int n = snprintf(msg, sizeof(msg), "[plain-relay %d] ", (int)getpid());
    va_list ap;
    va_start(ap, fmt);
    n += vsnprintf(msg + n, sizeof(msg) - (size_t)n, fmt, ap);
    va_end(ap);
    if (n > 0) {
        if ((size_t)n >= sizeof(msg)) n = (int)sizeof(msg) - 1;
        msg[n++] = '\n';
        ssize_t w = write(STDERR_FILENO, msg, (size_t)n);
        (void)w;
    }
}
#define CONNECT_TIMEOUT 3000
#define POLL_WAIT_MS    30000

static pid_t g_pid = -1;
static unsigned int g_mark = 0x4d5b;
static int g_chunk = 0;
static int g_pause_ms = 0;
static int g_idle_sec = 0;
static int g_split_ch = 0;
static int g_frag_delay_ms = 0;
static int g_first_seg = 20;
static int g_split_data = 0;
static int g_split_size = 512;
static int g_split_delay_ms = 0;

#define CH_BUF 65536

static void msleep(int ms) {
    if (ms <= 0) return;
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static int set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

// Отправка всей порции. На неблокирующем сокете ждёт готовности записи,
// вместо того чтобы блокировать или рвать соединение на короткой записи.
static int send_all(int fd, const void *data, size_t n) {
    const unsigned char *p = data;
    while (n > 0) {
        ssize_t s = send(fd, p, n, MSG_NOSIGNAL);
        if (s > 0) { p += s; n -= (size_t)s; continue; }
        if (s < 0 && errno == EINTR) continue;
        if (s < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd pfd = { .fd = fd, .events = POLLOUT };
            int r = poll(&pfd, 1, POLL_WAIT_MS);
            if (r > 0) continue;
            return -1;
        }
        return -1;
    }
    return 0;
}

static int connect_upstream(const struct sockaddr_in *sa) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    setsockopt(fd, SOL_SOCKET, SO_MARK, &g_mark, sizeof(g_mark));

    if (set_nonblock(fd) != 0) { close(fd); return -1; }
    int rc = connect(fd, (const struct sockaddr *)sa, sizeof(*sa));
    if (rc != 0 && errno != EINPROGRESS) { close(fd); return -1; }
    if (rc != 0) {
        struct pollfd pfd = { .fd = fd, .events = POLLOUT };
        if (poll(&pfd, 1, CONNECT_TIMEOUT) <= 0) { close(fd); return -1; }
        int err = 0;
        socklen_t elen = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) != 0 || err != 0) {
            close(fd);
            return -1;
        }
    }
    return fd;
}

// Двунаправленная перекачка. Закрытие одной стороны не убивает вторую:
// делается shutdown по направлению записи и ждём вторую до конца.
static void pump(int cfd, int ufd) {
    int c_done = 0, u_done = 0;
    long to_up = 0, to_client = 0;
    unsigned char buf[BUF_SIZE];
    time_t born = time(NULL);

    while (!(c_done && u_done)) {
        // Потолок жизни: соединение, которое только ждёт и почти не нагружено
        // данными, poll() не отпускает — оно живёт вечно и держит процесс.
        if (time(NULL) - born > CONN_MAX_SEC) { dbg("достигнут потолок %d с", CONN_MAX_SEC); break; }
        struct pollfd p[2] = { { .fd = cfd, .events = 0 }, { .fd = ufd, .events = 0 } };
        if (!c_done) p[0].events = POLLIN;
        if (!u_done) p[1].events = POLLIN;
        int r = poll(p, 2, g_idle_sec > 0 ? g_idle_sec * 1000 : -1);
        if (r < 0) { if (errno == EINTR) continue; break; }
        if (r == 0) break;                       // простой

        for (int i = 0; i < 2; i++) {
            if (p[i].revents == 0) continue;
            // Сторона, по которой уже получено EOF, больше не читается. Без этой
            // проверки poll продолжает возвращать POLLHUP по закрытому сокету,
            // recv даёт 0, и цикл крутится без остановки, пока не закроется
            // вторая сторона — процессы в полную нагрузку и в пустую лог.
            if ((i == 0) ? c_done : u_done) continue;
            int src = (i == 0) ? cfd : ufd;
            int dst = (i == 0) ? ufd : cfd;
            ssize_t n = recv(src, buf, sizeof(buf), 0);
            if (n > 0) {
                // Записи с данными режем на мелкие: иначе провайдер собирает
                // их и обрывает поток по достигнут��му объёму.
                if (g_split_data) {
                    size_t off = 0;
                    while (off < (size_t)n) {
                        if ((size_t)n - off < 5) {
                            if (send_all(dst, buf + off, (size_t)n - off) != 0) return;
                            off = (size_t)n;
                            break;
                        }
                        unsigned char *rec = buf + off;
                        int rlen = (rec[3] << 8) | rec[4];
                        int rec_end = 5 + rlen;
                        if (rec[0] != 0x17 || rlen <= g_split_size || rec_end > (int)n) {
                            size_t part = (size_t)n - off;
                            if (part > (size_t)g_split_size) part = (size_t)g_split_size;
                            if (send_all(dst, rec, part) != 0) return;
                            off += part;
                            continue;
                        }
                        int body = 5;
                        while (body < rec_end) {
                            int part = rec_end - body;
                            if (part > g_split_size) part = g_split_size;
                            unsigned char hdr[5] = {0x17, rec[1], rec[2],
                                                    (unsigned char)((part >> 8) & 0xFF),
                                                    (unsigned char)(part & 0xFF)};
                            if (send_all(dst, hdr, 5) != 0 ||
                                send_all(dst, rec + body, (size_t)part) != 0) return;
                            body += part;
                            if (body < rec_end) msleep(g_split_delay_ms);
                        }
                        off += (size_t)rec_end;
                    }
                    continue;
                }
                if (g_chunk > 0 && (size_t)n > (size_t)g_chunk) {
                    size_t off = 0;
                    while (off < (size_t)n) {
                        size_t part = (size_t)n - off;
                        if (part > (size_t)g_chunk) part = (size_t)g_chunk;
                        if (send_all(dst, buf + off, part) != 0) return;
                        off += part;
                        if (off < (size_t)n) msleep(g_pause_ms);
                    }
                } else if (send_all(dst, buf, (size_t)n) != 0) {
                    dbg("не удалось переслать %zd байт: %s", n, strerror(errno));
                    goto out;
                }
                if (i == 0) to_up += n; else to_client += n;
            } else if (n == 0) {
                dbg("%s закрыл соединение", (i == 0) ? "клиент" : "сервер");
                shutdown(dst, SHUT_WR);
                if (i == 0) c_done = 1; else u_done = 1;
            } else {
                if (errno == EINTR || errno == EAGAIN) continue;
                dbg("ошибка чтения (%s): %s", (i == 0) ? "клиент" : "сервер",
                    strerror(errno));
                goto out;
            }
        }
    }
out:
    dbg("итог: клиент->сервер %ld, сервер->клиент %ld", to_up, to_client);
}

// Читает ClientHello, разрывает SNI между двумя TLS-записями и отправляет
// вверх. Остаток после ClientHello возвращает в rest/leftover — его нужно
// переслать до начала обычной перекачки. Возвращает 0 в любом случае:
// если разобрать не удалось, байты уходят как есть, без разрыва.
static int forward_split_hello(int cfd, int ufd, unsigned char **rest, int *leftover) {
    *rest = NULL;
    *leftover = 0;

    unsigned char *buf = malloc(CH_BUF);
    if (!buf) return 0;
    int blen = 0, consumed = 0;

    for (;;) {
        if (blen >= 5 && buf[0] == 0x16) {
            int rec_len = (buf[3] << 8) | buf[4];
            if (rec_len < 4 || rec_len + 5 > blen) {
                if (blen >= CH_BUF) break;                 // не помещается — как есть
            } else if (buf[5] == 0x01) {
                int hs_len = (buf[6] << 16) | (buf[7] << 8) | buf[8];
                if (hs_len > 0 && hs_len + 4 == rec_len) {
                    consumed = rec_len + 5;
                    break;
                }
            }
        }
        ssize_t n = recv(cfd, buf + blen, (size_t)(CH_BUF - blen), 0);
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
            // Сокет неблокирующий, а рель принимает соединение по SYN — к моменту
            // чтения ClientHello данных ещё может не быть. Это НЕ конец потока:
            // ждём и продолжаем собирать приветствие, иначе уйдёт целый CH и его
            // зарежут по имени.
            struct pollfd pfd = { .fd = cfd, .events = POLLIN };
            int pr = poll(&pfd, 1, CH_TIMEOUT_MS);
            if (pr > 0) continue;
            if (pr == 0) { dbg("ClientHello не пришёл за %d мс", CH_TIMEOUT_MS); break; }
            continue;                                   // EINTR
        }
        if (n <= 0) {
            // клиент закрылся или данных мало — пересылаем как есть
            if (blen > 0) send_all(ufd, buf, (size_t)blen);
            free(buf);
            return 0;
        }
        blen += (int)n;
        if (blen == CH_BUF) break;
    }
    if (consumed == 0) {                                 // ClientHello не распознали
        if (blen > 0) send_all(ufd, buf, (size_t)blen);
        free(buf);
        return 0;
    }


    unsigned char *frag = malloc((size_t)consumed * 2 + 16);
    int first_seg = 0;
    int flen = frag ? sni_build_fragmented_ch(buf + 5, consumed - 5,
                                              frag, consumed * 2 + 16, &first_seg) : -1;
    int ok = 0;
    if (flen > 0) {
        int fs;                          // выставляется ниже: режем по границе SNI
        // Первая запись должна уйти ЦЕЛИКОМ: только так сервер может её
        // разобрать и дойти до имени. Обрезанная на fs байт запись означает,
        // что сервер ждёт остаток первой записи, а вторую он не в счёт — и
        // ответа не будет вовсе. fs из g_first_seg тут неприменим.
        int r1 = 5 + sni_find_split(buf + 5, consumed - 5);
        if (r1 < 6) r1 = flen / 2;
        if (r1 > flen) r1 = flen;
        fs = r1;
        if (send_all(ufd, frag, (size_t)fs) == 0) {
            msleep(g_frag_delay_ms > 0 ? g_frag_delay_ms : 30);
            ok = (send_all(ufd, frag + fs, (size_t)(flen - fs)) == 0);
        }
    }
    free(frag);
    if (!ok) {                                           // не смогли — шлём как есть
        send_all(ufd, buf, (size_t)consumed);
        free(buf);
        return 0;
    }

    if (consumed < blen) {
        *leftover = blen - consumed;
        *rest = malloc((size_t)*leftover);
        if (*rest) memcpy(*rest, buf + consumed, (size_t)*leftover);
        else *leftover = 0;
    }
    free(buf);
    return 0;
}

static void handle_conn(int cfd) {
    set_nonblock(cfd);
    int one = 1;
    setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    struct sockaddr_in orig = {0};
#ifdef PLAIN_RELAY_TEST_TARGET
    // Только для проверки без iptables: адрес назначения задаётся при сборке.
    orig.sin_family = AF_INET;
    orig.sin_port = htons(443);
    inet_pton(AF_INET, PLAIN_RELAY_TEST_TARGET, &orig.sin_addr);
#else
    socklen_t olen = sizeof(orig);
    if (getsockopt(cfd, SOL_IP, SO_ORIGINAL_DST, &orig, &olen) != 0 ||
        orig.sin_family != AF_INET ||
        orig.sin_addr.s_addr == htonl(INADDR_LOOPBACK)) {
        return;                       // неизвестно, куда подменять — не рискуем
    }
    if (ntohs(orig.sin_port) == 0) return;
#endif

    struct sockaddr_in peer = {0};
    socklen_t plen = sizeof(peer);
    getpeername(cfd, (struct sockaddr *)&peer, &plen);
    dbg("принято: клиент %d.%d.%d.%d:%d -> оригинал %d.%d.%d.%d:%d, разрыв CH=%s",
        (unsigned char)peer.sin_addr.s_addr, (unsigned char)(peer.sin_addr.s_addr >> 8),
        (unsigned char)(peer.sin_addr.s_addr >> 16), (unsigned char)(peer.sin_addr.s_addr >> 24),
        ntohs(peer.sin_port),
        (unsigned char)orig.sin_addr.s_addr, (unsigned char)(orig.sin_addr.s_addr >> 8),
        (unsigned char)(orig.sin_addr.s_addr >> 16), (unsigned char)(orig.sin_addr.s_addr >> 24),
        ntohs(orig.sin_port), g_split_ch ? "да" : "нет");
    int ufd = connect_upstream(&orig);
    if (ufd < 0) { dbg("не удалось соединиться с оригиналом"); return; }

    int leftover = 0;
    unsigned char *rest = NULL;
    if (g_split_ch && forward_split_hello(cfd, ufd, &rest, &leftover) < 0) {
        // разрыв не удался — соединение закрываем, а не ведём в никуда
        free(rest);
        close(ufd);
        return;
    }

    if (leftover > 0 && rest)
        send_all(ufd, rest, (size_t)leftover);

    dbg("перекачка начата, остаток после CH=%d", leftover);
    pump(cfd, ufd);
    free(rest);
    close(ufd);
    dbg("перекачка закончена");
}

static void relay_loop(int port) {
    prctl(PR_SET_PDEATHSIG, SIGKILL);
    if (getppid() == 1) _exit(0);
    setsid();
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGTERM, SIG_DFL);

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) _exit(1);
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(lfd, (struct sockaddr *)&a, sizeof(a)) != 0) _exit(2);
    if (listen(lfd, 128) != 0) _exit(3);

    for (;;) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            if (errno == EMFILE || errno == ENFILE || errno == ENOMEM ||
                errno == ENOBUFS || errno == ECONNABORTED) {
                msleep(50);
                continue;
            }
            break;
        }
        if (g_children >= CHILD_MAX) {
            // Кто-то открывает соединения к релю лавиной. Обслуживать их все
            // бессмысленно: процессы копятся и едят память. Отказываем сразу.
            g_rejected++;
            if (g_rejected % 100 == 1)
                fprintf(stderr, "рель: предел соединений (%d), отказано %ld — "
                                "источник лавины не обслуживается\n",
                        CHILD_MAX, g_rejected);
            close(cfd);
            continue;
        }
        pid_t p = fork();
        if (p == 0) {
            g_children = 0;                       // в ребёнке счётчик не нужен
            prctl(PR_SET_PDEATHSIG, SIGKILL);
            if (getppid() == 1) _exit(0);
            close(lfd);
            handle_conn(cfd);
            close(cfd);
            _exit(0);
        }
        close(cfd);
        if (p == 0) continue;
        if (p > 0) g_children++;
        else msleep(20);
    }
    _exit(0);
}

// Занят ли порт кем-то ещё (чужим процессом).
static int port_busy(int port) {
    int t = socket(AF_INET, SOCK_STREAM, 0);
    if (t < 0) return 0;
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int busy = (connect(t, (struct sockaddr *)&a, sizeof(a)) == 0);
    close(t);
    return busy;
}

int plain_relay_start(const plain_relay_config_t *cfg) {
    if (g_pid > 0 && kill(g_pid, 0) == 0) return 0;

    int port = (cfg && cfg->port > 0) ? cfg->port : 18444;
    if (port_busy(port)) {
        // Порт держит чужой слушатель — обычно осиротевший рель прошлого
        // запуска. Молча подхватывать его нельзя: мы сообщили бы «готов»,
        // а трафик обслуживал бы старый бинарник.
        fprintf(stderr, "рель: порт %d уже занят другим процессом — "
                        "убей старый rmf (./run.sh stop) и запусти снова\n", port);
        return -1;
    }
    g_mark = (cfg && cfg->so_mark) ? cfg->so_mark : 0x4d5b;
    g_chunk = (cfg && cfg->chunk > 0) ? cfg->chunk : 0;
    g_pause_ms = (cfg && cfg->pause_ms > 0) ? cfg->pause_ms : 0;
    // Без конечного таймаута pump() ждал бы poll(-1) вечно, и обработчики
    // оседали бы в памяти навсегда: соединения, по которым не приходит данных,
    // никто не закрывает. 30 с простоя — соединение уходит.
    g_idle_sec = (cfg && cfg->idle_sec > 0) ? cfg->idle_sec : 30;
    g_split_ch = (cfg && cfg->split_client_hello && cfg->frag_delay_ms > 0) ? 1 : 0;
    g_frag_delay_ms = (cfg && cfg->frag_delay_ms > 0) ? cfg->frag_delay_ms : 0;
    g_first_seg = (cfg && cfg->frag_first_seg > 0) ? cfg->frag_first_seg : 20;
    g_split_data = (cfg && cfg->split_data_records) ? 1 : 0;
    g_split_size = (cfg && cfg->split_record_size > 0) ? cfg->split_record_size : 512;
    g_split_delay_ms = (cfg && cfg->split_record_delay_ms > 0) ? cfg->split_record_delay_ms : 0;

    int pfd[2];
    (void)pfd;
    pid_t p = fork();
    if (p < 0) return -1;
    if (p == 0) {
        relay_loop(port);
        _exit(0);
    }
    g_pid = p;

    // Готовность проверяемconnect'ом к порту: слушатель уже поднят — значит
    // можно принимать соединения.
    int ok = 0;
    for (int i = 0; i < 20 && !ok; i++) {
        int st = 0;
        if (waitpid(g_pid, &st, WNOHANG) == g_pid) {
            fprintf(stderr, "рель: процесс на порту %d сразу завершился "
                            "(код %d) — порт занят?\n", port, WIFEXITED(st) ? WEXITSTATUS(st) : -1);
            g_pid = -1;
            return -1;
        }
        int t = socket(AF_INET, SOCK_STREAM, 0);
        if (t >= 0) {
            struct sockaddr_in a = {0};
            a.sin_family = AF_INET;
            a.sin_port = htons((uint16_t)port);
            a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            ok = (connect(t, (struct sockaddr *)&a, sizeof(a)) == 0);
            close(t);
        }
        if (!ok) msleep(100);
    }
    if (!ok) {
        kill(g_pid, SIGTERM);
        waitpid(g_pid, NULL, 0);
        g_pid = -1;
        return -1;
    }
    return 0;
}

void plain_relay_stop(void) {
    if (g_pid <= 0) return;
    kill(g_pid, SIGTERM);
    for (int i = 0; i < 20; i++) {
        if (waitpid(g_pid, NULL, WNOHANG) == g_pid) { g_pid = -1; return; }
        msleep(50);
    }
    kill(g_pid, SIGKILL);
    waitpid(g_pid, NULL, 0);
    g_pid = -1;
}

int plain_relay_running(void) {
    if (g_pid <= 0) return 0;
    if (kill(g_pid, 0) == 0) return 1;
    g_pid = -1;
    return 0;
}

int plain_relay_pid(void) { return (int)g_pid; }
