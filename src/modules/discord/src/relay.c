#include "src/modules/discord/include/header.h"
#include "src/dns/dns_resolve.h"
#include "src/dns/doh_resolve.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <poll.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <linux/netfilter_ipv4.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <time.h>

// Прозрачный TCP-relay с TLS record-фрагментацией ClientHello.
//
// Клиент -> relay (loopback, DPI не видит) -> relay пере-фреймит ClientHello:
//   2 TLS-records, cut посередине SNI-hostname;
//   первый TCP-сегмент обрывается ВНУТРИ record1 (см. коммент в discord_module.c).
// Затем обычный splice до закрытия сторон.
//
// Модель: fork. accept-loop в дочернем процессе, на соединение ещё fork.
// Апстрим-сокеты получают SO_MARK=0x4d5a, чтобы iptables REDIRECT (OUTPUT)
// не зацикливал собственные соединения relay'я.

#define DISCORD_SO_MARK 0x4d5a
#define CH_TIMEOUT_SEC  8
#define SPLICE_IDLE_SEC 15
#define MAX_CH_BUF      (1 << 20)

static pid_t relay_pid = -1;
static int ready_pipe[2] = {-1, -1};

static void msleep(int ms) {
    if (ms <= 0) return;
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

int discord_relay_running(void) {
    if (relay_pid <= 0) return 0;
    int status;
    pid_t rc = waitpid(relay_pid, &status, WNOHANG);
    if (rc == 0 && kill(relay_pid, 0) == 0) return 1;
    relay_pid = -1;
    discord_get_ctx()->relay_pid = -1;
    return 0;
}

void discord_relay_stop(void) {
    if (relay_pid <= 0) { discord_get_ctx()->relay_pid = -1; return; }
    kill(relay_pid, SIGTERM);
    int st;
    for (int i = 0; i < 20; i++) {
        if (waitpid(relay_pid, &st, WNOHANG) == relay_pid) {
            relay_pid = -1;
            discord_get_ctx()->relay_pid = -1;
            return;
        }
        msleep(50);
    }
    kill(relay_pid, SIGKILL);
    waitpid(relay_pid, &st, 0);
    relay_pid = -1;
    discord_get_ctx()->relay_pid = -1;
}

// --- Извлечь полный ClientHello (handshake message, может идти в нескольких records) ---

static int extract_client_hello(const unsigned char *buf, int len,
                                unsigned char *hs_out, int hs_cap,
                                int *consumed) {
    int off = 0;
    int need = -1;          // размер hs с заголовком, -1 = ещё не знаем
    int got = 0;
    while (off + 5 <= len) {
        if (buf[off] != 0x16) return -1;    // первый record обязан быть handshake
        int rlen = (buf[off + 3] << 8) | buf[off + 4];
        if (rlen <= 0 || rlen > 1 << 16) return -1;
        if (off + 5 + rlen > len) break;    // record не полон — ждём

        const unsigned char *payload = buf + off + 5;
        int plen = rlen;
        if (need < 0) {
            if (plen < 4 || payload[0] != 0x01) return -1;
            need = 4 + ((payload[1] << 16) | (payload[2] << 8) | payload[3]);
            if (need > hs_cap) return -1;
        }
        int take = need - got;
        if (take > plen) take = plen;
        memcpy(hs_out + got, payload, (size_t)take);
        got += take;
        off += 5 + rlen;
        if (got >= need) {
            *consumed = off;
            return got;
        }
    }
    return 0; // нужно ещё данных
}

// --- Splice: оба направления в одном select-цикле ---
//
// Сплит большой 0x16-записи допустим ТОЛЬКО когда off стоит точно на границе
// записи. Раньше граница терялась после чанка 4096, заголовок парсился внутри
// payload'а — из потока вырезалось 5 байт, клиент зависал в ожидании записи,
// которая уже не придёт (максимум SPLICE_IDLE_SEC, дальше соединение рвали).
//
// rem  >0 — байт осталось до конца текущей записи; rem==0 — стоим на границе.
// phn >0  — заголовок записи разорван между recv, phn байт уже отправлены
//           и запомнены только для разбора длины.

static int splice_forward(int dst, const unsigned char *buf, int n,
                          int *rem, unsigned char *ph, int *phn) {
    int off = 0;
    while (off < n) {
        int remain = n - off;

        if (*rem == 0) {
            if (*phn > 0) {
                int need = 5 - *phn;
                int take = need < remain ? need : remain;
                memcpy(ph + *phn, buf + off, (size_t)take);
                if (send(dst, buf + off, (size_t)take, MSG_NOSIGNAL) != take) return -1;
                off += take; *phn += take;
                if (*phn < 5) continue;
                int rlen = (ph[3] << 8) | ph[4];
                *rem = 5 + rlen - *phn;
                *phn = 0;
                if (*rem < 0) *rem = 0;
                continue;
            }
            if (remain < 5) {
                memcpy(ph, buf + off, (size_t)remain);
                *phn = remain;
                if (send(dst, buf + off, (size_t)remain, MSG_NOSIGNAL) != remain) return -1;
                off += remain;
                continue;
            }
            int rlen = (buf[off + 3] << 8) | buf[off + 4];
            int total = 5 + rlen;
            if (buf[off] == 0x16 && rlen > 200 && total <= remain) {
                int split = rlen / 2;
                if (split < 1) split = 1;
                unsigned char h1[5] = {0x16, 0x03, 0x01,
                               (unsigned char)(split >> 8), (unsigned char)split};
                unsigned char h2[5] = {0x16, 0x03, 0x01,
                               (unsigned char)((rlen - split) >> 8),
                               (unsigned char)(rlen - split)};
                if (send(dst, h1, 5, MSG_NOSIGNAL) != 5) return -1;
                if (send(dst, buf + off + 5, (size_t)split, MSG_NOSIGNAL) != split) return -1;
                msleep(1);
                if (send(dst, h2, 5, MSG_NOSIGNAL) != 5) return -1;
                if (send(dst, buf + off + 5 + split, (size_t)(rlen - split), MSG_NOSIGNAL) != rlen - split) return -1;
                off += total;
                continue;
            }
            *rem = total;
        }

        int take = remain;
        if (*rem > 0 && take > *rem) take = *rem;
        if (take > 4096) take = 4096;
        if (send(dst, buf + off, (size_t)take, MSG_NOSIGNAL) != take) return -1;
        off += take;
        if (*rem > 0) *rem -= take;
        if (take >= 4096) msleep(1);
    }
    return 0;
}

static void splice_loop(int a, int b) {
    int rem[2] = {0, 0};
    unsigned char ph[2][5] = {{0}};
    int phn[2] = {0, 0};
    for (;;) {
        struct pollfd p[2] = {
            { .fd = a, .events = POLLIN },
            { .fd = b, .events = POLLIN },
        };
        int r = poll(p, 2, SPLICE_IDLE_SEC * 1000);
        if (r <= 0) return;
        for (int i = 0; i < 2; i++) {
            if (!(p[i].revents & (POLLIN | POLLHUP | POLLERR))) continue;
            unsigned char buf[65536];
            ssize_t n = recv(p[i].fd, buf, sizeof(buf), 0);
            if (n <= 0) return;
            int dst = (i == 0) ? b : a;
            if (splice_forward(dst, buf, (int)n, &rem[i], ph[i], &phn[i]) != 0) return;
        }
    }
}

// --- SNI hostname из handshake message (или пусто) ---

static void extract_sni(const unsigned char *hs, int hs_len, char *out, size_t out_sz) {
    out[0] = '\0';
    if (!hs || hs_len < 46 || hs[0] != 0x01) return;
    int body_len = hs_len - 4;
    const unsigned char *body = hs + 4;
    int p = 2 + 32;
    if (p >= body_len) return;
    int sid_len = body[p]; p += 1 + sid_len;
    if (p + 2 > body_len) return;
    int cs_len = (body[p] << 8) | body[p + 1]; p += 2 + cs_len;
    if (p >= body_len) return;
    int comp_len = body[p]; p += 1 + comp_len;
    if (p + 2 > body_len) return;
    int ext_total = (body[p] << 8) | body[p + 1]; p += 2;
    int end = p + ext_total;
    if (end > body_len) return;
    while (p + 4 <= end) {
        int et = (body[p] << 8) | body[p + 1];
        int el = (body[p + 2] << 8) | body[p + 3];
        if (p + 4 + el > end) return;
        if (et == 0x0000 && el >= 5) {
            const unsigned char *ed = body + p + 4;
            int nlen = (ed[3] << 8) | ed[4];
            int name_off = p + 4 + 5;
            if (nlen > 0 && nlen <= 253 && nlen < (int)out_sz &&
                name_off + nlen <= body_len) {
                memcpy(out, body + name_off, (size_t)nlen);
                out[nlen] = '\0';
            }
            return;
        }
        p += 4 + el;
    }
}

// Подключение к апстриму: original dst + все кандидаты из честного DNS + system.
// Anycast Discord ненадёжен (162.159.136.232 периодически мёртв) — пробуем по списку.
static int connect_upstream(const struct sockaddr_in *orig, int have_orig,
                            const char *sni, struct timeval *tv) {
    struct sockaddr_in cands[8];
    int n = 0;
    if (have_orig) cands[n++] = *orig;

    discord_ctx_t *cx = discord_get_ctx();
    int have_doh = 0;
    if (sni && sni[0]) {
        char doh_ip[64] = {0};
        if (doh_resolve_a(sni, doh_ip, sizeof(doh_ip)) == 0) {
            struct sockaddr_in a = {0};
            a.sin_family = AF_INET;
            a.sin_port = htons(443);
            if (inet_pton(AF_INET, doh_ip, &a.sin_addr) == 1) {
                int dup = 0;
                for (int i = 0; i < n; i++)
                    dup |= (cands[i].sin_addr.s_addr == a.sin_addr.s_addr);
                if (!dup && n < 8) {
                    cands[n++] = a;
                    have_doh = 1;
                }
            }
        }
    }
    if (sni && sni[0]) {
        for (int attempt = 0; attempt < 2 && n < 8; attempt++) {
            char ip[64] = {0};
            const char *dns = attempt ? cx->fallback : cx->primary;
            if (dns_resolve_udp(dns, sni, ip, sizeof(ip)) == 0 && ip[0]) {
                struct sockaddr_in a = {0};
                a.sin_family = AF_INET;
                a.sin_port = htons(443);
                if (inet_pton(AF_INET, ip, &a.sin_addr) == 1) {
                    int dup = 0;
                    for (int i = 0; i < n; i++)
                        dup |= (cands[i].sin_addr.s_addr == a.sin_addr.s_addr);
                    if (!dup) cands[n++] = a;
                }
            }
        }
        if (!have_doh) {
            struct addrinfo hints = {0}, *res = NULL;
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            if (getaddrinfo(sni, "443", &hints, &res) == 0) {
                for (struct addrinfo *ai = res; ai && n < 8; ai = ai->ai_next) {
                    struct sockaddr_in *sa = (struct sockaddr_in *)ai->ai_addr;
                    int dup = 0;
                    for (int i = 0; i < n; i++)
                        dup |= (cands[i].sin_addr.s_addr == sa->sin_addr.s_addr);
                    if (!dup) cands[n++] = *sa;
                }
            }
            freeaddrinfo(res);
        }
    }

    for (int i = 0; i < n; i++) {

        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return -1;
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        unsigned int mark = DISCORD_SO_MARK;
        setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, tv, sizeof(*tv));
        if (connect(fd, (struct sockaddr *)&cands[i], sizeof(cands[i])) == 0)
            return fd;
        close(fd);
    }
    return -1;
}

static void handle_conn(int cfd) {
    struct timeval tv = { CH_TIMEOUT_SEC, 0 };
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    int one = 1;
    setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    // 1. Original destination (для подключения через iptables REDIRECT)
    struct sockaddr_in orig = {0};
    socklen_t olen = sizeof(orig);
    int have_orig = (getsockopt(cfd, SOL_IP, SO_ORIGINAL_DST, &orig, &olen) == 0
                     && orig.sin_family == AF_INET
                     && orig.sin_addr.s_addr != htonl(INADDR_LOOPBACK));
    if (!have_orig) memset(&orig, 0, sizeof(orig));

    // 2. Буферизуем первый полный ClientHello
    unsigned char *buf = malloc(MAX_CH_BUF);
    if (!buf) return;
    int blen = 0, consumed = 0;
    unsigned char hs[65536];
    int hs_len = 0;
    for (;;) {
        if (blen >= MAX_CH_BUF) { free(buf); return; }
        hs_len = extract_client_hello(buf, blen, hs, (int)sizeof(hs), &consumed);
        if (hs_len != 0) break;
        ssize_t n = recv(cfd, buf + blen, (size_t)(MAX_CH_BUF - blen), 0);
        if (n <= 0) { free(buf); return; }
        blen += (int)n;
    }

    // Не ClientHello: если известен original dst — пускаем как есть, иначе дроп
    if (hs_len < 0) {
        if (!have_orig) { free(buf); return; }
        int u0 = socket(AF_INET, SOCK_STREAM, 0);
        if (u0 < 0) { free(buf); return; }
        setsockopt(u0, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        unsigned int mark0 = DISCORD_SO_MARK;
        setsockopt(u0, SOL_SOCKET, SO_MARK, &mark0, sizeof(mark0));
        setsockopt(u0, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (connect(u0, (struct sockaddr *)&orig, sizeof(orig)) != 0) {
            close(u0); free(buf); return;
        }
        send(u0, buf, (size_t)blen, MSG_NOSIGNAL);
        free(buf);
        splice_loop(cfd, u0);
        close(u0);
        return;
    }

    // 3+4. Апстрим: original dst (REDIRECT) + кандидаты по SNI (честный DNS)
    char sni[256] = {0};
    extract_sni(hs, hs_len, sni, sizeof(sni));
    struct timeval cto = { 2, 0 };  // таймаут на каждого кандидата
    int ufd = connect_upstream(have_orig ? &orig : NULL, have_orig, sni, &cto);
    if (ufd < 0) { free(buf); return; }

    // 5. Фрагментируем ClientHello и отправляем
    discord_ctx_t *cx = discord_get_ctx();
    static unsigned char frag[65536 * 2];
    int fs = 0;
    int flen = discord_build_fragmented_ch(hs, hs_len, frag, (int)sizeof(frag), &fs);
    int ok = 0;
    if (flen > 0 && fs > 0) {
        if (send(ufd, frag, (size_t)fs, MSG_NOSIGNAL) == fs) {
            msleep(cx->frag_delay_ms > 0 ? cx->frag_delay_ms : 30);
            ok = (send(ufd, frag + fs, (size_t)(flen - fs), MSG_NOSIGNAL) == flen - fs);
        }
    }
    if (!ok) { close(ufd); free(buf); return; }

    // 6. Остаток первого полёта клиента (после ClientHello)
    if (consumed < blen)
        send(ufd, buf + consumed, (size_t)(blen - consumed), MSG_NOSIGNAL);
    free(buf);

    // 7. Обычный bidirectional splice
    struct timeval tv0 = {0, 0};
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv0, sizeof(tv0));
    setsockopt(ufd, SOL_SOCKET, SO_RCVTIMEO, &tv0, sizeof(tv0));
    splice_loop(cfd, ufd);
    close(ufd);
}

static void relay_child(int port) {
    prctl(PR_SET_PDEATHSIG, SIGKILL);
    if (getppid() == 1) _exit(0);
    setsid();
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);   // авто-reap форкнутых обработчиков
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
    if (ready_pipe[1] >= 0) {
        char ok = 1;
        if (write(ready_pipe[1], &ok, 1) != 1) _exit(5);
        close(ready_pipe[1]);
        ready_pipe[1] = -1;
    }

    for (;;) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            _exit(4);
        }
        pid_t p = fork();
        if (p == 0) {
            prctl(PR_SET_PDEATHSIG, SIGKILL);
            if (getppid() == 1) _exit(0);
            close(lfd);
            handle_conn(cfd);
            close(cfd);
            _exit(0);
        }
        close(cfd);
    }
}

int discord_relay_start(int port) {
    if (discord_relay_running()) return 0;
    if (port <= 0) port = 18443;

    if (pipe(ready_pipe) != 0) return -1;
    pid_t p = fork();
    if (p < 0) { close(ready_pipe[0]); close(ready_pipe[1]); return -1; }
    if (p == 0) {
        close(ready_pipe[0]);
        relay_child(port);
        _exit(0);
    }
    close(ready_pipe[1]);
    relay_pid = p;
    // ждём готовности listen'а. setsockopt(SO_RCVTIMEO) на pipe всегда
    // возвращает ENOTSOCK, поэтому таймаут задаём poll'ом — он работает и с pipe.
    char ok = 0;
    struct pollfd rp = { .fd = ready_pipe[0], .events = POLLIN };
    int pr = poll(&rp, 1, 2000);
    int got = (pr > 0) ? (int)read(ready_pipe[0], &ok, 1) : -1;
    close(ready_pipe[0]);
    ready_pipe[0] = ready_pipe[1] = -1;
    if (got != 1 || !ok) {
        int st;
        if (pr == 0) { waitpid(relay_pid, &st, WNOHANG); errno = ETIMEDOUT; }
        else { waitpid(relay_pid, &st, 0); if (WIFEXITED(st) && WEXITSTATUS(st)) errno = ECONNREFUSED; }
        discord_relay_stop();
        return -1;
    }
    discord_get_ctx()->relay_pid = (int)relay_pid;
    return 0;
}
