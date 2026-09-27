#include "src/common/sni_relay.h"
#include "src/dns/dns_resolve.h"
#include "src/dns/doh_resolve.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <signal.h>
#include <poll.h>
#include <fcntl.h>
#include <time.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <linux/netfilter_ipv4.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/prctl.h>
// ready_pipe declared below for relay_child after listen()

#define CH_TIMEOUT_SEC  8
#define SPLICE_IDLE_SEC 30
#define MAX_CH_BUF      (1 << 20)

static int ready_pipe[2] = {-1, -1};
static pid_t g_pid = -1;
static int g_port = 0;
static unsigned int g_mark = 0x4d5b;
static int g_delay_ms = 30;
static int g_first_seg = 20;
static int g_split_data = 0;
static int g_split_size = 512;
static int g_split_delay_ms = 1;
static int g_split_ch = 1;
static int g_data_chunk = 4096;
static int g_data_pause_ms = 1;   // -1 = без паузы
static char g_dns1[32] = "1.1.1.1";
static char g_dns2[32] = "8.8.8.8";
static int (*g_validate_ip)(const char *ip);
static const char *g_fallback_ips[16];
static size_t g_fallback_count;

static int relay_ip_allowed(const char *ip) {
    struct in_addr parsed;
    if (!ip || inet_pton(AF_INET, ip, &parsed) != 1) return 0;
    return !g_validate_ip || g_validate_ip(ip);
}

static void msleep(int ms) {
    if (ms <= 0) return;
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

// ── диагностика (SNI_RELAY_DEBUG=1) ───────────────────────────────────────
static int g_dbg = -1;
// Список имён, для которых сдвигается регистр первой буквы SNI.
static int g_dbg_fd = -1;
static int g_no_split_recs;
static int g_shift_sni;
// Включается только переменной окружения. Раньше здесь ещё проверялось
// наличие файла /tmp/sni-debug, из-за чего подробный лог включался у всех, кто
// этот файл создал, без всякого запроса.
static int dbg_on(void) {
    if (g_dbg < 0) {
        const char *v = getenv("SNI_RELAY_DEBUG");
        g_dbg = (v && *v && strcmp(v, "0") != 0) ? 1 : 0;
    }
    return g_dbg;
}
static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}
static long g_t0 = 0;
static void dbg(const char *fmt, ...) {
    if (!dbg_on()) return;
    // Дублируем в файл: кольцо лога веба переполняется чужими соединениями,
    // и строка нужного соединения вытесняется раньше, чем её успевают прочитать.
    if (g_dbg_fd < 0)
        g_dbg_fd = open("/tmp/sni-debug.log", O_WRONLY | O_CREAT | O_APPEND, 0644);

    va_list ap, ap_err, ap_file;
    va_start(ap, fmt);
    // Обе копии берём ДО первого использования ap: после vfprintf список
    // аргументов уже непригоден, и повторное чтение даёт мусор вместо значений.
    va_copy(ap_err, ap);
    va_copy(ap_file, ap);

    fprintf(stderr, "[relay %d +%ldms] ", (int)getpid(), now_ms() - g_t0);
    vfprintf(stderr, fmt, ap_err);
    fputc('\n', stderr);
    fflush(stderr);

    if (g_dbg_fd >= 0) {
        dprintf(g_dbg_fd, "[relay %d +%ldms] ", (int)getpid(), now_ms() - g_t0);
        vdprintf(g_dbg_fd, fmt, ap_file);
        dprintf(g_dbg_fd, "\n");
    }

    va_end(ap_file);
    va_end(ap_err);
    va_end(ap);
}

int sni_relay_running(void) {
    if (g_pid <= 0) return 0;
    if (kill(g_pid, 0) == 0) return 1;
    g_pid = -1;
    return 0;
}

int sni_relay_pid(void) { return (int)g_pid; }

void sni_relay_stop(void) {
    if (g_pid <= 0) {
        g_validate_ip = NULL;
        g_fallback_count = 0;
        memset(g_fallback_ips, 0, sizeof(g_fallback_ips));
        return;
    }
    kill(g_pid, SIGTERM);
    int st;
    for (int i = 0; i < 20; i++) {
        if (waitpid(g_pid, &st, WNOHANG) == g_pid) { g_pid = -1; return; }
        msleep(50);
    }
    kill(g_pid, SIGKILL);
    waitpid(g_pid, &st, 0);
    g_pid = -1;
    g_validate_ip = NULL;
    g_fallback_count = 0;
    memset(g_fallback_ips, 0, sizeof(g_fallback_ips));
}

int sni_find_split(const unsigned char *hs, int hs_len) {
    if (!hs || hs_len < 46 || hs[0] != 0x01) return -1;
    int body_len = ((hs[1] << 16) | (hs[2] << 8) | hs[3]);
    if (body_len != hs_len - 4 || body_len < 38) return -1;
    const unsigned char *body = hs + 4;
    int p = 2 + 32;
    if (p >= body_len) return -1;
    int sid_len = body[p]; p += 1 + sid_len;
    if (p + 2 > body_len) return -1;
    int cs_len = (body[p] << 8) | body[p + 1]; p += 2 + cs_len;
    if (p >= body_len) return -1;
    int comp_len = body[p]; p += 1 + comp_len;
    if (p + 2 > body_len) return -1;
    int ext_total = (body[p] << 8) | body[p + 1]; p += 2;
    int end = p + ext_total;
    if (end > body_len) return -1;

    while (p + 4 <= end) {
        int et = (body[p] << 8) | body[p + 1];
        int el = (body[p + 2] << 8) | body[p + 3];
        if (p + 4 + el > end) return -1;
        if (et == 0x0000 && el >= 5) {
            const unsigned char *ed = body + p + 4;
            int nlen = (ed[3] << 8) | ed[4];
            int name_off = (p + 4) + 5;
            if (nlen > 0 && nlen <= 253 && name_off + nlen <= body_len) {
                int cut_in = nlen / 2;
                if (cut_in < 1) cut_in = 1;
                int cut = 4 + name_off + cut_in;
                if (cut > 8 && cut < hs_len - 1) return cut;
            }
        }
        p += 4 + el;
    }
    return -1;
}

// Меняет регистр первой буквы имени в SNI.
//
// DNS и SNI регистронезависимы: сервер имя не различает и отвечает как обычно.
// А фильтр у провайдера сравнивает имя побайтово, от точного регистра, и режет
// поток. Проверено на одном адресе (172.217.113.4) с SNI youtubei.googleapis.com:
//   youtubei.googleapis.com   — тишина
//   Youtubei.googleapis.com   — ответ
//   YOUTUBEI.GOOGLEAPIS.COM   — ответ
//   youtubei.Googleapis.com   — тишина (важна первая буква имени)
// Значит достаточно поменять регистр первой буквы, длину и контрольные суммы
// трогать не нужно — длина байтов та же.
void sni_shift_case(unsigned char *hs, int hs_len) {
    if (!hs || hs_len < 46 || hs[0] != 0x01) return;
    int body_len = ((hs[1] << 16) | (hs[2] << 8) | hs[3]);
    if (body_len != hs_len - 4 || body_len < 38) return;
    unsigned char *body = hs + 4;
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
            unsigned char *ed = body + p + 4;
            int nlen = (ed[3] << 8) | ed[4];
            unsigned char *name = ed + 5;
            if (nlen > 0 && name + nlen <= body + body_len) {
                unsigned char c = name[0];
                name[0] = (c >= 'a' && c <= 'z') ? (unsigned char)(c - 32)
                                                  : (unsigned char)(c + 32);
            }
            return;
        }
        p += 4 + el;
    }
}




// Сколько частей дробить ClientHello. 2 — прежнее поведение, 3 и больше —
// multisplit из zapret: DPI, умеющий склеивать поток, натыкается на большее
// число границ, а первая граница по-прежнему ставится по SNI.
static int g_multi_parts = 2;

int sni_build_fragmented_ch(const unsigned char *hs, int hs_len,
                            unsigned char *out, int out_cap, int *first_seg_out) {
    if (!hs || !out || hs_len < 46) return -1;
    int parts = g_multi_parts >= 2 ? g_multi_parts : 2;
    if (parts > 16) parts = 16;
    if (parts > hs_len / 8) parts = hs_len / 8;
    if (parts < 2) parts = 2;

    // Первая граница — по SNI, как раньше: именно на ней DPI обычно и спотыкается.
    int first = sni_find_split(hs, hs_len);
    if (first <= 0) first = hs_len / parts;
    if (first < 1) first = 1;
    if (first >= hs_len) first = hs_len - 1;

    int total = 0;
    int pos = 0;
    int cut = first;
    for (int i = 0; i < parts; i++) {
        int remain = hs_len - pos;
        int take = cut;
        if (i == parts - 1) take = remain;
        if (take < 1 || take > remain) return -1;
        if (total + 5 + take > out_cap) return -1;
        unsigned char *rec = out + total;
        rec[0] = 0x16; rec[1] = 0x03; rec[2] = 0x01;
        rec[3] = (unsigned char)((take >> 8) & 0xFF);
        rec[4] = (unsigned char)(take & 0xFF);
        memcpy(rec + 5, hs + pos, (size_t)take);
        total += 5 + take;
        pos += take;
        // Остаток делим поровну, последняя часть забирает всё.
        // Делить только пока есть куда делить: на последней итерации
        // parts - i - 1 == 0, и обычное деление на ноль убивало процесс
        // рель-ребёнка на каждом соединении (SIGFPE).
        int left = parts - i - 1;
        if (left <= 0) break;
        cut = (hs_len - pos) / left;
        if (cut < 1) cut = 1;
    }

    if (first_seg_out) {
        int fs = g_first_seg > 0 ? g_first_seg : 20;
        int first_rec = 5 + first;
        if (fs >= first_rec) fs = first_rec - 1;
        if (fs < 1) fs = 1;
        *first_seg_out = fs;
    }
      return total;
  }

int sni_extract_name(const unsigned char *hs, int hs_len, char *out, size_t out_sz) {
    if (!out || out_sz == 0) return 0;
    out[0] = '\0';
    if (!hs || hs_len < 46 || hs[0] != 0x01) return 0;
    const unsigned char *body = hs + 4;
    int q = 2 + 32;
    q += 1 + body[q];
    q += 2 + ((body[q] << 8) | body[q + 1]);
    q += 1 + body[q];
    if (q + 2 > hs_len - 4) return 0;
    int ext_total = (body[q] << 8) | body[q + 1];
    q += 2;
    int e = q + ext_total;
    while (q + 4 <= e) {
        int et = (body[q] << 8) | body[q + 1];
        int el = (body[q + 2] << 8) | body[q + 3];
        if (et == 0x0000 && el >= 5) {
            int nlen = (body[q + 4 + 3] << 8) | body[q + 4 + 4];
            if (nlen > 0 && nlen < (int)out_sz && q + 4 + 5 + nlen <= e) {
                memcpy(out, body + q + 4 + 5, (size_t)nlen);
                out[nlen] = '\0';
                return nlen;
            }
            return 0;
        }
        q += 4 + el;
    }
    return 0;
}

static int extract_client_hello(const unsigned char *buf, int len,
                                unsigned char *hs_out, int hs_cap,
                                int *consumed) {
    int off = 0;
    int need = -1;
    int got = 0;
    while (off + 5 <= len) {
        if (buf[off] != 0x16) return -1;
        int rlen = (buf[off + 3] << 8) | buf[off + 4];
        if (rlen <= 0 || rlen > 1 << 16) return -1;
        if (off + 5 + rlen > len) break;

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
    return 0;
}

// Полная отправка: короткий write на заполненном буфере не должен рвать поток,
// иначе клиент видит оборванный ответ вместо ошибки.
static int g_send_errno = 0;      // для диагностики: чем именно упал send
static long g_send_left = -1;      // и сколько байт не отправилось

static int send_all(int fd, const void *data, size_t n) {
    const unsigned char *p = data;
    g_send_errno = 0;
    g_send_left = -1;
    while (n > 0) {
        ssize_t s = send(fd, p, n, MSG_NOSIGNAL);
        if (s > 0) { p += s; n -= (size_t)s; continue; }
        if (s < 0 && errno == EINTR) continue;
        g_send_errno = errno;
        g_send_left = (long)n;
        return -1;
    }
    return 0;
}

static void splice_loop(int a, int b) {
    const char *why = "unknown";
    long got_c = 0, got_s = 0, sent_c = 0, sent_s = 0;
    for (;;) {
        struct pollfd p[2] = {
            { .fd = a, .events = POLLIN },
            { .fd = b, .events = POLLIN },
        };
        int r = poll(p, 2, SPLICE_IDLE_SEC * 1000);
        if (r == 0) { why = "poll-timeout"; break; }
        if (r < 0) { why = (errno == EINTR) ? "poll-eintr" : "poll-error"; break; }
        for (int i = 0; i < 2; i++) {
            if (!(p[i].revents & (POLLIN | POLLHUP | POLLERR))) continue;
            unsigned char buf[65536];
            ssize_t n = recv(p[i].fd, buf, sizeof(buf), 0);
            if (n <= 0) {
                dbg("recv dir=%c n=%zd errno=%d revents=0x%x",
                    (i == 0) ? 'C' : 'S', n, errno, p[i].revents);
                why = "recv-eof-or-err";
                goto out;
            }
            if (i == 0) got_c += n; else got_s += n;
            dbg("recv dir=%c n=%zd first=0x%02x",
                (i == 0) ? 'C' : 'S', n, buf[0]);
            int dst = (i == 0) ? b : a;

            int off = 0;
            int rec_left = 0;   // сколько байт ТЕКУЩЕЙ записи осталось
                                // отправить как есть; >0 означает, что off
                                // стоит внутри записи, а не на её границе
            while (off < n) {
                int remain = (int)n - off;

                // Внутри записи разбирать нечего: байты шифротекста, и
                // «0x17» в них — случайное совпадение, а не тип записи.
                if (rec_left > 0) {
                    int chunk = rec_left < remain ? rec_left : remain;
                    if (send_all(dst, buf + off, (size_t)chunk) != 0) {
                        why = "send-raw-mid";
                        goto out;
                    }
                    if (i == 0) sent_c += chunk; else sent_s += chunk;
                    off += chunk;
                    rec_left -= chunk;
                    continue;
                }

                if (!g_no_split_recs && remain >= 5 && buf[off] == 0x16) {
                    int rlen = (buf[off + 3] << 8) | buf[off + 4];
                    int rec_end = off + 5 + rlen;
                    if (rec_end <= n && rlen > 200) {
                        int split = rlen / 2;
                        if (split < 1) split = 1;
                        dbg("split off=%d rlen=%d split=%d dir=%c", off, rlen, split,
                            (i == 0) ? 'C' : 'S');
                        // Заголовок первой половины объявляет длину СВОЕЙ
                        // половины. С исходным заголовком (полная длина записи)
                        // получатель читал вторую половину и заголовок второй
                        // записи как продолжение первой — поток разъезжался на
                        // крупных ответах, и клиент отвечал алертом.
                        unsigned char hdr1[5] = {0x16, buf[off + 1], buf[off + 2],
                                                 (unsigned char)((split >> 8) & 0xFF),
                                                 (unsigned char)(split & 0xFF)};
                        if (send_all(dst, hdr1, 5) != 0) { why = "send-hdr1"; goto out; }
                        if (send_all(dst, buf + off + 5, (size_t)split) != 0) { why = "send-p1"; goto out; }
                        msleep(1);
                        // Именно unsigned char: массив int отдавал бы наружу
                        // 5 байт от начала, то есть 16 00 00 00 03 — сломанный
                        // заголовок второй половины.
                        unsigned char hdr2[5] = {0x16, 0x03, 0x01,
                                        (unsigned char)(((rlen - split) >> 8) & 0xFF),
                                        (unsigned char)((rlen - split) & 0xFF)};
                        if (send_all(dst, hdr2, 5) != 0) { why = "send-hdr2"; goto out; }
                        if (send_all(dst, buf + off + 5 + split, (size_t)(rlen - split)) != 0) { why = "send-p2"; goto out; }
                        off = rec_end;
                        continue;
                    }
                }
                // Дробление записей с данными: DPI не должен иметь возможности
                // собрать перезаписанные TLS-записи и оценить объём ответа.
                if (g_split_data && remain >= 5 && buf[off] == 0x17) {
                    int rlen = (buf[off + 3] << 8) | buf[off + 4];
                    int rec_end = off + 5 + rlen;
                    if (rec_end <= n && rlen > g_split_size) {
                        int body = 5, end = 5 + rlen;
                        while (body < end) {
                            int chunk = end - body;
                            if (chunk > g_split_size) chunk = g_split_size;
                            unsigned char hdr[5] = {0x17, buf[off + 1], buf[off + 2],
                                                    (unsigned char)((chunk >> 8) & 0xFF),
                                                    (unsigned char)(chunk & 0xFF)};
                            if (send_all(dst, hdr, 5) != 0 ||
                                send_all(dst, buf + off + body, (size_t)chunk) != 0) {
                                why = "send-split";
                                goto out;
                            }
                            body += chunk;
                            if (body < end) msleep(g_split_delay_ms);
                        }
                        dbg("data-split off=%d rlen=%d parts=%d dir=%c", off, rlen,
                            (rlen + g_split_size - 1) / g_split_size, (i == 0) ? 'C' : 'S');
                        if (i == 0) sent_c += rlen; else sent_s += rlen;
                        off = rec_end;
                        continue;
                    }
                }
                // Запись с данными не помещается в этот recv (или не режем) —
                // шлём как есть. Но если она обрезана границей буфера, её хвост
                // придёт в следующих recv, и до него разбирать записи нельзя:
                // off окажется внутри шифротекста, где «0x17» — случайный байт.
                //
                // Раньше здесь ничего не помечалось, и на записях длиннее
                // g_data_chunk (4096) цикл регулярно останавливался посреди
                // записи, после чего следующая итерация читала «длину записи»
                // из мусора и резала поток по выдуманным смещениям. Клиент
                // получал битый кадр и отвечал "decryption failed or bad record
                // mac" — воспроизводилось 10 из 10.
                if (g_split_data && remain >= 5 && buf[off] == 0x17) {
                    int rlen = (buf[off + 3] << 8) | buf[off + 4];
                    int rec_end = off + 5 + rlen;
                    if (rec_end > n) {
                        // запись продолжается за пределами буфера
                        rec_left = rec_end - off;
                        dbg("partial data record off=%d rlen=%d left=%d",
                            off, rlen, rec_left);
                    }
                }

                int chunk = remain;
                if (chunk > g_data_chunk) chunk = g_data_chunk;
                if (rec_left > 0 && chunk > rec_left) chunk = rec_left;
                if (chunk > 0) {
                    ssize_t s = send(dst, buf + off, (size_t)chunk, MSG_NOSIGNAL);
                    if (s != chunk) {
                        why = "send-short";
                        goto out;
                    }
                    if (i == 0) sent_c += chunk; else sent_s += chunk;
                    off += chunk;
                    if (rec_left > 0) rec_left -= chunk;
                } else {
                    // Защита от бесконечного цикла: еслиremain ненулевой, а
                    // взять нечего — уходим, а не крутимся.
                    why = "stall";
                    goto out;
                }
                if (g_data_pause_ms > 0) msleep(g_data_pause_ms);

            }
        }
    }
out:
    dbg("splice exit: %s (C->S=%ld S->C=%ld) send_errno=%d(%s) left=%ld",
        why, sent_c, sent_s, g_send_errno,
        g_send_errno ? strerror(g_send_errno) : "-", g_send_left);
}

static int connect_one(const struct sockaddr_in *sa, const struct timeval *tv) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    unsigned int mark = g_mark;
    setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(fd);
        return -1;
    }

    int rc = connect(fd, (const struct sockaddr *)sa, sizeof(*sa));
    if (rc == 0) {
        fcntl(fd, F_SETFL, flags);
        return fd;
    }
    if (errno != EINPROGRESS) {
        close(fd);
        return -1;
    }

    int timeout_ms = 2000;
    if (tv && tv->tv_sec >= 0)
        timeout_ms = (int)tv->tv_sec * 1000 + (int)(tv->tv_usec / 1000);
    if (timeout_ms <= 0) timeout_ms = 2000;

    struct pollfd pfd = { .fd = fd, .events = POLLOUT };
    int pr = poll(&pfd, 1, timeout_ms);
    if (pr <= 0) {
        close(fd);
        return -1;
    }
    int err = 0;
    socklen_t elen = sizeof(err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) != 0 || err != 0) {
        close(fd);
        return -1;
    }
    fcntl(fd, F_SETFL, flags);
    return fd;
}

static int add_unique(struct sockaddr_in *cands, int *n, int max,
                      const struct sockaddr_in *sa) {
    if (*n >= max) return 0;
    for (int i = 0; i < *n; i++)
        if (cands[i].sin_addr.s_addr == sa->sin_addr.s_addr) return 0;
    cands[(*n)++] = *sa;
    return 1;
}

static int sni_to_cand(const char *ip, struct sockaddr_in *out) {
    memset(out, 0, sizeof(*out));
    out->sin_family = AF_INET;
    out->sin_port = htons(443);
    return inet_pton(AF_INET, ip, &out->sin_addr) == 1;
}

static int add_ip_candidate(struct sockaddr_in *cands, int *n, int max,
                            const char *ip) {
    if (!relay_ip_allowed(ip)) return 0;
    struct sockaddr_in candidate;
    if (!sni_to_cand(ip, &candidate)) return 0;
    return add_unique(cands, n, max, &candidate);
}

// Последний сработавший апстрим. Без этого каждое соединение платит полный
// перебор: на заблокированном адресе connect_upstream ждёт CONNECT_TIMEOUT,
// потом пробует следующий, и так далее. На замере это выглядело как запросы
// ровно на 15 с (таймаут curl) вперемешку с мгновенными отказами, хотя часть
// адресов Discord в любой момент отвечает.
//
// Сработавший адрес ставится первым, поэтому после первого успеха стоимость
// подключения падает до одного connect. Кэш один на весь рель: адреса у Discord
// общие, и разные соединения идут к одному и тому же фронт-энду.
// Соединения обрабатываются через fork() — по процессу на соединение. Обычная
// статическая переменная тут не годится: ребёнок записывает адрес и умирает,
// а родитель его изменения не видит, поэтому кэш всегда оставался пустым и
// каждое соединение снова платило полный перебор кандидатов. Отдельный файл на
// диске тоже не нужен — mmap до fork наследуется, а MAP_SHARED делает запись
// видимой всем процессам реля, включая будущие дети.
//
// Размер фиксирован, запись — один snprintf. Формально запись и чтение могут
// разойтись на границе байта, поэтому читаем вдвое: если строка не читается
// как IP целиком, адрес просто не используется и делается обычный перебор.
static char *g_last_good;

// Задать адрес, который заведомо отдаёт данные целиком. Модуль вызывает это
// после собственной проверки: у Discord часть адресов отдаёт файл полностью,
// а часть режет поток примерно на 20 КБ. Перебор кандидатов тут не помогает —
// обрезающий адрес принимает соединение нормально, просто не отдаёт файл, и
// цикл connect_upstream его успешным не считает и дальше не идёт.
//
// Вызывать ДО sni_relay_start: страница общей памяти создаётся здесь, а рель
// наследует её через fork. Создание страницы в цикле accept осталось как
// запасной путь на случай, если предпочтение не задавали.
void sni_relay_prefer(const char *ip) {
    if (!ip || !ip[0]) return;
    if (!g_last_good) {
        g_last_good = mmap(NULL, INET_ADDRSTRLEN, PROT_READ | PROT_WRITE,
                           MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (g_last_good == MAP_FAILED) g_last_good = NULL;
    }
    if (!g_last_good) return;
    struct in_addr chk;
    if (inet_pton(AF_INET, ip, &chk) != 1) return;
    snprintf(g_last_good, INET_ADDRSTRLEN, "%s", ip);
}

static int connect_upstream(const struct sockaddr_in *orig, int have_orig,
                            const char *sni, const struct timeval *tv) {
    struct sockaddr_in cands[8];
    int n = 0;

    // Первым идёт адрес, который уже сработал. add_ip_candidate убирает
    // повторы, так что если он совпадает с оригиналом или DoH-ответом, он
    // просто окажется один раз.
    if (g_last_good) {
        char good[INET_ADDRSTRLEN] = {0};
        memcpy(good, g_last_good, sizeof good - 1);
        struct in_addr chk;
        if (good[0] && inet_pton(AF_INET, good, &chk) == 1)
            add_ip_candidate(cands, &n, 8, good);
    }

    if (have_orig && orig && orig->sin_family == AF_INET) {
        char ip[INET_ADDRSTRLEN] = {0};
        if (inet_ntop(AF_INET, &orig->sin_addr, ip, sizeof(ip)))
            have_orig = add_ip_candidate(cands, &n, 8, ip) > 0;
        else
            have_orig = 0;
    } else {
        have_orig = 0;
    }

    int have_doh = 0;
    if (sni && sni[0]) {
        char ip[64] = {0};
        if (doh_resolve_a(sni, ip, sizeof(ip)) == 0)
            have_doh = add_ip_candidate(cands, &n, 8, ip) > 0;
    }

    for (size_t i = 0; i < g_fallback_count && n < 8; i++)
        if (g_fallback_ips[i]) add_ip_candidate(cands, &n, 8, g_fallback_ips[i]);

    for (int i = 0; i < n; i++) {
        int fd = connect_one(&cands[i], tv);
        if (fd >= 0) {
            if (g_last_good) { char t[INET_ADDRSTRLEN];
                if (inet_ntop(AF_INET, &cands[i].sin_addr, t, sizeof t))
                    snprintf(g_last_good, INET_ADDRSTRLEN, "%s", t); }
            return fd;
        }
    }

    if (sni && sni[0]) {
        for (int attempt = 0; attempt < 2 && n < 8; attempt++) {
            char ip2[64] = {0};
            const char *dns = attempt ? g_dns2 : g_dns1;
            if (dns_resolve_udp(dns, sni, ip2, sizeof(ip2)) == 0)
                add_ip_candidate(cands, &n, 8, ip2);
        }
        if (!have_doh) {
            struct addrinfo hints = {0}, *res = NULL;
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            if (getaddrinfo(sni, "443", &hints, &res) == 0) {
                for (struct addrinfo *ai = res; ai && n < 8; ai = ai->ai_next) {
                    char ip[INET_ADDRSTRLEN] = {0};
                    struct sockaddr_in *sa = (struct sockaddr_in *)ai->ai_addr;
                    if (sa && inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip)))
                        add_ip_candidate(cands, &n, 8, ip);
                }
                freeaddrinfo(res);
            }
            for (int i = 0; i < n; i++) {
                int fd = connect_one(&cands[i], tv);
                if (fd >= 0) {
                    if (g_last_good) { char t[INET_ADDRSTRLEN];
                        if (inet_ntop(AF_INET, &cands[i].sin_addr, t, sizeof t))
                    snprintf(g_last_good, INET_ADDRSTRLEN, "%s", t); }
                    return fd;
                }
            }
        } else {
            for (int i = have_orig ? 1 : 0; i < n; i++) {
                int fd = connect_one(&cands[i], tv);
                if (fd >= 0) {
                    if (g_last_good) { char t[INET_ADDRSTRLEN];
                        if (inet_ntop(AF_INET, &cands[i].sin_addr, t, sizeof t))
                    snprintf(g_last_good, INET_ADDRSTRLEN, "%s", t); }
                    return fd;
                }
            }
        }
    }
    return -1;
}

static void handle_conn(int cfd) {
    struct timeval tv = { CH_TIMEOUT_SEC, 0 };
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    int one = 1;
    setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    struct sockaddr_in orig = {0};
    socklen_t olen = sizeof(orig);
    int have_orig = (getsockopt(cfd, SOL_IP, SO_ORIGINAL_DST, &orig, &olen) == 0
                     && orig.sin_family == AF_INET
                     && orig.sin_addr.s_addr != htonl(INADDR_LOOPBACK));
    if (!have_orig) memset(&orig, 0, sizeof(orig));

    g_t0 = now_ms();
    unsigned char *buf = malloc(MAX_CH_BUF);
    if (!buf) { dbg("conn: malloc fail"); return; }
    int blen = 0, consumed = 0;
    unsigned char hs[65536];
    int hs_len = 0;
    for (;;) {
        if (blen >= MAX_CH_BUF) { free(buf); return; }
        hs_len = extract_client_hello(buf, blen, hs, (int)sizeof(hs), &consumed);
        if (hs_len != 0) break;
        ssize_t n = recv(cfd, buf + blen, (size_t)(MAX_CH_BUF - blen), 0);
        if (n <= 0) { dbg("conn: CH read fail n=%zd errno=%d blen=%d", n, errno, blen); free(buf); return; }
        blen += (int)n;
        dbg("CH recv n=%zd blen=%d", n, blen);
    }
    dbg("conn: CH ok hs_len=%d blen=%d consumed=%d have_orig=%d", hs_len, blen, consumed, have_orig);

    // Сдвиг регистра первой буквы SNI. Длина байтов не меняется, поэтому ни
    // длина TLS-записи, ни контрольные суммы трогать не нужно: поток к
    // Cloudflare остаётся целым, а DPI перестаёт узнавать имя.
    //
    // Делаем ЗДЕСЬ, сразу после разбора, а не после отправки. Раньше вызов
    // стоял ниже по коду, уже после того, как и фрагменты, и исходный буфер
    // ушли в сокет, — то есть сдвигались байты, которые никто никогда не
    // видел, и shift_sni не делал ровно ничего. Меняем оба буфера: в buf
    // лежит подлинный ClientHello (его пересылает ветка без разрыва), из hs
    // собираются фрагменты (ветка с разрывом).
    if (g_shift_sni && hs_len > 0) {
        // hs — склеенная handshake-структура (тип 0x01 + длина + тело). В buf
        // она лежит подряд только когда ClientHello уместился в одну запись;
        // тогда consumed == 5 + hs_len и начало структуры стоит на buf+5.
        // Если записей было несколько, в buf байты разнесены, и сдвигать
        // склеенный hs в буфере нечего — там правится только hs.
        if (consumed == hs_len + 5)
            sni_shift_case(buf + 5, hs_len);
        sni_shift_case(hs, hs_len);
        dbg("conn: shift_sni applied hs_len=%d contiguous=%d",
            hs_len, consumed == hs_len + 5);
    }

    if (hs_len < 0) {
        dbg("conn: no split in CH, raw forward, have_orig=%d", have_orig);
        if (!have_orig) { free(buf); return; }
        struct timeval cto = { 2, 0 };
        int u0 = connect_one(&orig, &cto);
        if (u0 < 0) { dbg("conn: connect_one failed errno=%d", errno); free(buf); return; }
        send(u0, buf, (size_t)blen, MSG_NOSIGNAL);
        free(buf);
        splice_loop(cfd, u0);
        close(u0);
        return;
    }

    char sni[256] = {0};
    sni_extract_name(hs, hs_len, sni, sizeof(sni));
    struct timeval cto = { 2, 0 };
    int ufd = connect_upstream(have_orig ? &orig : NULL, have_orig, sni, &cto);
    if (ufd < 0) { dbg("conn: connect_upstream failed sni=%s errno=%d", sni, errno); free(buf); return; }
    dbg("conn: ufd=%d sni=%s", ufd, sni);

    static unsigned char frag[65536 * 2];
    int ok = 0;
    if (g_split_ch) {
        int flen = sni_build_fragmented_ch(hs, hs_len, frag, (int)sizeof(frag), NULL);
        if (flen > 0) {
            int fs = g_first_seg > 0 ? g_first_seg : 20;
            int r1_len = 5 + sni_find_split(hs, hs_len);
            if (r1_len < 6) r1_len = flen / 2;
            if (fs >= r1_len) fs = r1_len - 1;
            if (fs < 1) fs = 1;
            if (send_all(ufd, frag, (size_t)fs) == 0) {
                msleep(g_delay_ms > 0 ? g_delay_ms : 30);
                ok = (send_all(ufd, frag + fs, (size_t)(flen - fs)) == 0);
            }
        }
        if (!ok) { dbg("conn: frag send failed"); close(ufd); free(buf); return; }
        dbg("conn: frag ok flen=%d", flen);
    } else {
        // ClientHello уходит без разрыва SNI: диагностический режим, для
        // сравнения с режимом разрыва.
        ok = (send_all(ufd, buf, (size_t)consumed) == 0);
        if (!ok) { dbg("conn: plain CH send failed"); close(ufd); free(buf); return; }
        dbg("conn: plain CH ok len=%d", consumed);
        consumed = blen;
    }

    if (consumed < blen) {
        ssize_t s2 = send(ufd, buf + consumed, (size_t)(blen - consumed), MSG_NOSIGNAL);
        dbg("conn: leftover send %zd/%d", s2, blen - consumed);
    }
    free(buf);

    struct timeval tv0 = {0, 0};
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv0, sizeof(tv0));
    setsockopt(ufd, SOL_SOCKET, SO_RCVTIMEO, &tv0, sizeof(tv0));
    splice_loop(cfd, ufd);
    close(ufd);
}

static void relay_child(int port) {
    dprintf(2, "[relay] RAW child banner pid=%d port=%d dbg=%d env=%s flag=%d\n",
            (int)getpid(), port, dbg_on(),
            getenv("SNI_RELAY_DEBUG") ? getenv("SNI_RELAY_DEBUG") : "-",
            -1);
    setsid();
    g_t0 = now_ms();
    dbg("relay child started port=%d dbg=%d", port, dbg_on());
    // Умираем вместе с плагином: иначе дочерние relay-обработчики (и их форки)
    // остаются сиротами после stop/restart и копятся десятками.
    prctl(PR_SET_PDEATHSIG, SIGKILL);
    if (getppid() == 1) _exit(0);
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
            // transient resource errors — do not kill the listener
            if (errno == EMFILE || errno == ENFILE || errno == ENOMEM ||
                errno == ENOBUFS || errno == ECONNABORTED || errno == EPROTO) {
                msleep(50);
                continue;
            }
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
        if (p < 0) msleep(20); // fork failed; client already closed
    }
}

int sni_relay_start(const sni_relay_config_t *cfg) {
    if (sni_relay_running()) return 0;
    int port = (cfg && cfg->port > 0) ? cfg->port : 18444;
    g_port = port;
    g_mark = (cfg && cfg->so_mark) ? cfg->so_mark : 0x4d5b;
    g_delay_ms = (cfg && cfg->frag_delay_ms > 0) ? cfg->frag_delay_ms : 30;
    g_first_seg = (cfg && cfg->frag_first_seg > 0) ? cfg->frag_first_seg : 20;
    snprintf(g_dns1, sizeof(g_dns1), "%s", "1.1.1.1");
    snprintf(g_dns2, sizeof(g_dns2), "%s", "8.8.8.8");
    if (cfg && cfg->primary_dns) {
        snprintf(g_dns1, sizeof(g_dns1), "%s", cfg->primary_dns);
        char *c = strchr(g_dns1, ':'); if (c) *c = '\0';
    }
    if (cfg && cfg->fallback_dns) {
        snprintf(g_dns2, sizeof(g_dns2), "%s", cfg->fallback_dns);
        char *c = strchr(g_dns2, ':'); if (c) *c = '\0';
    }
    g_validate_ip = cfg ? cfg->validate_ip : NULL;
    g_no_split_recs = (cfg && cfg->no_split_handshake_records) ? 1 : 0;
    g_shift_sni = (cfg && cfg->shift_sni) ? 1 : 0;
    g_split_data = (cfg && cfg->split_data_records) ? 1 : 0;
    g_split_size = (cfg && cfg->split_record_size > 0) ? cfg->split_record_size : 512;
    g_split_delay_ms = (cfg && cfg->split_record_delay_ms > 0) ? cfg->split_record_delay_ms : 1;
    // Незаданное поле = 0 = прежнее поведение (разрыв ClientHello включён).
    g_split_ch = (cfg && cfg->no_split_client_hello) ? 0 : 1;
    g_multi_parts = (cfg && cfg->multi_parts >= 2) ? cfg->multi_parts : 2;
    g_data_chunk = (cfg && cfg->data_chunk > 0) ? cfg->data_chunk : 4096;
    g_data_pause_ms = (cfg && cfg->data_pause_ms < 0) ? -1
                      : (cfg && cfg->data_pause_ms > 0) ? cfg->data_pause_ms : 1;
    memset(g_fallback_ips, 0, sizeof(g_fallback_ips));
    g_fallback_count = cfg && cfg->fallback_count < 16 ? cfg->fallback_count : (cfg ? 16 : 0);
    for (size_t i = 0; i < g_fallback_count; i++)
        g_fallback_ips[i] = cfg->fallback_ips ? cfg->fallback_ips[i] : NULL;

    dprintf(2, "[relay] RAW start in pid=%d dbg=%d\n", (int)getpid(), dbg_on());
    if (pipe(ready_pipe) != 0) return -1;
    pid_t p = fork();
    if (p < 0) { close(ready_pipe[0]); close(ready_pipe[1]); return -1; }
    if (p == 0) {
        close(ready_pipe[0]);
        relay_child(port);
        _exit(0);
    }
    close(ready_pipe[1]);
    ready_pipe[1] = -1;
    g_pid = p;
    char ok = 0;
    struct pollfd pfd = { .fd = ready_pipe[0], .events = POLLIN };
    int pr = poll(&pfd, 1, 2000);
    int got = (pr > 0) ? (int)read(ready_pipe[0], &ok, 1) : 0;
    close(ready_pipe[0]);
    ready_pipe[0] = ready_pipe[1] = -1;
    if (got != 1 || !ok) { sni_relay_stop(); return -1; }
    return 0;
}
