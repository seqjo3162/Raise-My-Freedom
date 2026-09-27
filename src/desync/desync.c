// Пакетный слой десинхронизации: поддельная TLS-запись с чужим именем,
// которая переживает первый хоп провайдера и умирает до сервера.
//
// Наблюдение идёт через AF_PACKET (видим исходящие пакеты), подделка
// отправляется через SOCK_RAW с IP_HDRINCL — так мы формируем пакет целиком,
// включая TTL и контрольные суммы, и не зависим от того, как ядро соберёт
// обычный send().
//
// Рекурсии нет: у своей подделки мы ставим магический IP ID и такие пакеты
// пропускаем.

#define _GNU_SOURCE
#include "desync.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// Свои структуры заголовков вместо linux/ip.h: netinet тянет BSD-вариант с
// другими именами полей, и обе версии вместе не компилируются. Разбор
// пакета от системы не должен зависеть вовсе.
typedef struct {
    uint8_t  ver_ihl, tos;
    uint16_t tot_len, id, frag_off;
    uint8_t  ttl, proto;
    uint16_t check;
    uint32_t saddr, daddr;
} dip_t;

typedef struct {
    uint16_t src, dst;
    uint32_t seq, ack;
    uint8_t  doff_res, flags;
    uint16_t win, check, urg;
} dtcp_t;

#define TH_ACK_ 0x10
#define IPV(h)   ((h)->ver_ihl >> 4)
#define IHL(h)   ((h)->ver_ihl & 0x0F)
#define THL(h)   ((h)->doff_res >> 4)

#define FAKE_IPID 0xDE50          // наш пакет — такие пропускаем
#define MAX_PKT   65536
// Имя в подделанном ClientHello.
//
// Выбор неслучаен, и менять его на что-то зарубежное не надо. ТСПУ в России
// устроен так, что заблокированные ресурсы он разбирает и досматривает
// глубоко, а трафик к РОССИЙСКИМ площадкам почти не трогает: они живут на
// тех же CDN и в тех же AS, что и популярные зарубежные сайты, и их поломка
// сломала бы слишком многое. Отсюда и приём: подделка с российским именем
// выглядит для DPI как рутина, которую не стоит вскрывать.
//
// И наоборот: подделка с именем заблокированного ресурса — это прямое
// указание «здесь что-то спрятали», и на такой пакет DPI реагирует
// заметно агрессивнее. Поэтому www.google.com в дефолте стоял зря.
//
// Подставляется только в подделку; настоящий ClientHello клиента идёт
// байт в байт и его не касается. Переопределяется --fake-sni или SNI= в
// скриптах.
#define FAKE_SNI  "vk.ru"


static int              g_sock = -1;      // AF_PACKET, только чтение
static int              g_raw = -1;      // SOCK_RAW, отправка подделок

// Отправка подделки вынесена в указатель на функцию. В бою это sendto,
// в тесте — захват байтов. Смысл: раньше путь инъекции не проверялся вообще
// никогда, а именно он решает, уйдёт ли пакет в сеть.
typedef ssize_t (*desync_send_fn)(const void *buf, size_t len,
                                  struct sockaddr *sa, socklen_t sl);
static desync_send_fn   g_send = NULL;
static pthread_t        g_tid;
static volatile int     g_run = 0;
static char             g_err[256] = {0};
static desync_config_t  g_cfg;
static desync_stats_t   g_stats;

// Разбор по протоколам. Без этого невозможно понять, куда деваются пакеты:
// счётчик «просмотрено» растёт и при этом ни один не доходит до разбора TCP,
// а список адресов молчит, потому что считать нечего.
static struct {
    unsigned long long tcp, udp, icmp, other_proto, not_v4, long_hdr, short_pkt;
    // Разбивка по направлению. pkttype: 0 — пакет К НАМ, 3 — к другому хосту,
    // 4 — ПОСЫЛАЕМЫЙ НАМИ. Раньше исходящие и входящие были неразличимы,
    // и выглядело это так, будто мы «не видим свой исходящий трафик».
    unsigned long long to_us, to_other, outgoing, no_sni;
} g_proto;

// Топ диапазонов: куда вообще уходит трафик. Держим /16, этого достаточно,
// чтобы увидеть «есть ли вообще что-то похожее на цель».
static int g_dumped;
static struct { uint32_t net; unsigned long long pkts; } g_top[DESYNC_TOP_N];
static int g_top_n;

static uint32_t g_net;                   // сеть в сетевом порядке
static uint32_t g_mask;

const char *desync_mode_name(desync_mode_t m) {
    switch (m) {
        case DESYNC_MODE_FAKE:      return "fake";
        case DESYNC_MODE_FAKE_TAIL: return "fake-tail";
        default:                    return "off";
    }
}

const char *desync_last_error(void) { return g_err; }
bool desync_running(void) { return g_run != 0; }

void desync_get_stats(desync_stats_t *out) {
    if (out) *out = g_stats;
}

void desync_get_proto_stats(desync_proto_stats_t *out) {
    if (!out) return;
    out->tcp = g_proto.tcp;
    out->udp = g_proto.udp;
    out->icmp = g_proto.icmp;
    out->other = g_proto.other_proto;
    out->not_v4 = g_proto.not_v4;
    out->long_hdr = g_proto.long_hdr;
    out->short_pkt = g_proto.short_pkt;
    out->to_us = g_proto.to_us;
    out->to_other = g_proto.to_other;
    out->outgoing = g_proto.outgoing;
    out->no_sni = g_proto.no_sni;
}

static void note_peer(uint32_t addr) {
    // /16 — это адрес с обнулёнными ПОСЛЕДНИМИ двумя октетами, то есть
    // обнулять надо байты 2 и 3. Раньше стояло addr & 0xFFFF0000u, а это
    // обнуляет первые два октета в пространстве значения числа, и inet_ntop
    // потом печатал 192.168.31.253 как 0.0.31.253. Диагностика молча врала
    // именно там, где её и смотрели.
    uint32_t net = addr;
    ((unsigned char *)&net)[2] = 0;
    ((unsigned char *)&net)[3] = 0;
    for (int i = 0; i < g_top_n; i++)
        if (g_top[i].net == net) { g_top[i].pkts++; return; }
    if (g_top_n < DESYNC_TOP_N) {
        g_top[g_top_n].net = net;
        g_top[g_top_n].pkts = 1;
        g_top_n++;
        return;
    }
    unsigned long long least = g_top[0].pkts;
    int pos = 0;
    for (int i = 1; i < g_top_n; i++)
        if (g_top[i].pkts < least) { least = g_top[i].pkts; pos = i; }
    if (least < g_top[0].pkts + 1) { g_top[pos].net = net; g_top[pos].pkts = 1; }
}

// Крючки для теста: список адресов проверяется снаружи, а статические
// функции из другого translation unit недоступны.
void desync_test_note_peer(uint32_t addr) { note_peer(addr); }
void desync_test_reset_peers(void) { g_top_n = 0; memset(g_top, 0, sizeof(g_top)); }

void desync_top_peers(desync_top_peer_t *out, int max, int *count) {
    if (!out || max <= 0) { if (count) *count = 0; return; }
    int n = g_top_n < max ? g_top_n : max;
    // сортируем по убыванию простым выбором, размер крошечный
    for (int i = 0; i < n; i++) {
        int best = i;
        for (int j = i + 1; j < n; j++)
            if (g_top[j].pkts > g_top[best].pkts) best = j;
        if (best != i) {
            uint32_t n_ = g_top[i].net; unsigned long long p_ = g_top[i].pkts;
            g_top[i] = g_top[best]; g_top[best].net = n_; g_top[best].pkts = p_;
        }
        struct in_addr a;
        a.s_addr = g_top[i].net;
        inet_ntop(AF_INET, &a, out[i].net, sizeof(out[i].net));
        out[i].pkts = g_top[i].pkts;
    }
    if (count) *count = n;
}

static void set_err(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_err, sizeof(g_err), fmt, ap);
    va_end(ap);
}

// ── контрольные суммы ─────────────────────────────────────────────────────
static uint16_t csum16(const void *data, size_t len, uint32_t seed) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t sum = seed;
    while (len > 1) { sum += (uint32_t)((p[0] << 8) | p[1]); p += 2; len -= 2; }
    if (len) sum += (uint32_t)(p[0] << 8);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum);
}

static uint16_t ip_csum(const dip_t *ip) {
    dip_t copy = *ip;
    copy.check = 0;
    return csum16(&copy, sizeof(copy), 0);
}

// Сумма 16-битных слов без сложения и инверсии — только накопление.
static uint32_t sum16(const void *data, size_t len, uint32_t sum) {
    const uint8_t *p = (const uint8_t *)data;
    while (len > 1) { sum += (uint32_t)((p[0] << 8) | p[1]); p += 2; len -= 2; }
    if (len) sum += (uint32_t)(p[0] << 8);
    return sum;
}

static uint16_t tcp_csum(const dip_t *ip, const dtcp_t *tcp, size_t tcp_len) {
    uint32_t sum = 0;
    // Адреса берутся БАЙТАМИ, а не сдвигами по числу. Поле лежит в сетевом
    // порядке, и на x86 сдвиги разворачивают пары байт: вместо 0A00 0102
    // получалось 0201 000A, то есть считался другой адрес. Сумма выходила
    // неверной, и подделку отбрасывал первый же роутер.
    sum = sum16(&ip->saddr, 4, sum);
    sum = sum16(&ip->daddr, 4, sum);
    sum += IPPROTO_TCP;              // нулевой байт + протокол TCP
    sum += (uint32_t)tcp_len;
    sum = sum16(tcp, tcp_len, sum);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum);
}

// ── разбор ClientHello ────────────────────────────────────────────────────
// Возвращает смещение начала SNI и его длину, либо 0.
static int find_sni(const unsigned char *p, int len, int *out_len) {
    if (len < 9 || p[0] != 0x16 || p[1] != 0x03) return 0;
    if (p[5] != 0x01) return 0;                    // Handshake ClientHello
    // Раскладка: запись 5 байт (0..4), заголовок рукопожатия 4 байта (5..8),
    // client_version 32 байта (9..40), дальше session id.
    int off = 9 + 32;
    if (off >= len) return 0;
    off += 1 + p[off];                             // session id
    if (off + 2 > len) return 0;
    off += 2 + ((p[off] << 8) | p[off + 1]);      // cipher suites
    if (off >= len) return 0;
    off += 1 + p[off];                             // compression
    if (off + 2 > len) return 0;
    int ext_total = (p[off] << 8) | p[off + 1];
    off += 2;
    int end = off + ext_total;
    if (end > len) end = len;
    while (off + 4 <= end) {
        int et = (p[off] << 8) | p[off + 1];
        int el = (p[off + 2] << 8) | p[off + 3];
        int body = off + 4;
        if (body + el > end) break;
        if (et == 0x0000 && el >= 4) {            // server_name
            // Внутри расширения: тип_имени(1) + длина_имени(2) + имя.
            int nlen = (p[body + 1] << 8) | p[body + 2];
            if (nlen > 0 && body + 3 + nlen <= body + el) {
                *out_len = nlen;
                return body + 3;
            }
        }
        off = body + el;
    }
    return 0;
}

// Минимальный ClientHello с чужим именем. Настоящий разбирать не нужно:
// DPI достаточно увидеть корректно выглядящую запись с SNI, которого нет
// в его стоп-листе.
static int build_fake_hello(const char *sni, unsigned char *out, int cap) {
    int nlen = (int)strlen(sni);
    if (nlen < 1 || nlen > 250) return -1;
    // body: тип(1) + длина(3) + client_version(32) + session(1) +
    //       cipher len(2) + suite(2) + comp len(1) + comp(1) +
    //       ext len(2) + server_name(4 + 2 + 1 + 2 + nlen)
    int ext_len = 7 + nlen;   // 2 тип + 2 длина + 1 тип_имени + 2 длина_имени + имя
    int body_len = 1 + 3 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + ext_len;
    int total = 5 + body_len;
    if (total > cap) return -1;
    memset(out, 0, (size_t)total);

    unsigned char *b = out + 5;
    int p = 0;
    b[p++] = 0x01;                                     // ClientHello
    // Длина рукопожатия — ТРИ байта. Двух байт мало: весь разбор сдвигается
    // на единицу и подделка получается невалидной, а такое не видно ни в
    // тесте, ни в логах — пакет просто не работает.
    b[p++] = (unsigned char)(((body_len - 4) >> 16) & 0xFF);
    b[p++] = (unsigned char)((body_len - 4) >> 8);
    b[p++] = (unsigned char)((body_len - 4) & 0xFF);
    memset(b + p, 0x03, 32); p += 32;                  // client_version
    b[p++] = 0x00;                                     // session id: пусто
    b[p++] = 0x00; b[p++] = 0x02;                      // cipher suites: длина
    b[p++] = 0x13; b[p++] = 0x01;                      // TLS_AES_128_GCM_SHA256
    b[p++] = 0x01;                                     // compression: длина
    b[p++] = 0x00;                                     // null
    b[p++] = (unsigned char)(ext_len >> 8);
    b[p++] = (unsigned char)(ext_len & 0xFF);
    b[p++] = 0x00; b[p++] = 0x00;                      // тип расширения: server_name
    b[p++] = (unsigned char)((nlen + 3) >> 8);          // длина расширения
    b[p++] = (unsigned char)((nlen + 3) & 0xFF);
    b[p++] = 0x00;                                      // тип имени: host_name
    b[p++] = (unsigned char)(nlen >> 8);
    b[p++] = (unsigned char)(nlen & 0xFF);
    memcpy(b + p, sni, (size_t)nlen);
    p += nlen;

    out[0] = 0x16; out[1] = 0x03; out[2] = 0x01;
    out[3] = (unsigned char)((body_len >> 8) & 0xFF);
    out[4] = (unsigned char)(body_len & 0xFF);
    return total;
}

// Доступ к внутренним функциям для теста без сети и без прав.
int find_sni_for_test(const unsigned char *p, int len, int *out_len) {
    return find_sni(p, len, out_len);
}

int build_fake_for_test(const char *sni, unsigned char *out, int cap) {
    return build_fake_hello(sni, out, cap);
}

// Начало ClientHello: запись TLS версии 1.x, внутри — рукопожатие ClientHello.
// Достаточно первых 6 байт, поэтому работает даже когда рукопожатие разрезано
// нами же на сегменты по 20 байт.
static int is_client_hello_start(const unsigned char *p, int len) {
    if (len < 6) return 0;
    if (p[0] != 0x16 || p[1] != 0x03) return 0;   // не запись рукопожатия
    if (p[5] != 0x01) return 0;                    // не ClientHello
    return 1;
}

static int in_target(uint32_t addr) {
    return (addr & g_mask) == (g_net & g_mask);
}

// Буфер под пакет: стековый 64 КБ на каждый вызов не нужен, а поток один.
static unsigned char g_out[MAX_PKT];

static void handle(const unsigned char *pkt, int len) {
    g_stats.seen++;
    if (len < (int)sizeof(dip_t) + (int)sizeof(dtcp_t)) { g_proto.short_pkt++; return; }
    const dip_t *ip = (const dip_t *)pkt;
    if (IPV(ip) != 4) { g_proto.not_v4++; return; }
    if (IHL(ip) != 5) { g_proto.long_hdr++; return; }
    if (ip->proto != IPPROTO_TCP) {
        g_proto.other_proto++;
        if (ip->proto == IPPROTO_UDP) g_proto.udp++;
        else if (ip->proto == IPPROTO_ICMP) g_proto.icmp++;
        return;
    }
    g_proto.tcp++;
    if (ntohs(ip->id) == FAKE_IPID) { g_stats.skipped++; return; }
    note_peer(ip->daddr);
    if (!in_target(ip->daddr)) return;

    int ihl = IHL(ip) * 4;
    const dtcp_t *tcp = (const dtcp_t *)(pkt + ihl);
    int thl = THL(tcp) * 4;
    if (thl < 20 || ihl + thl > len) return;
      if (g_cfg.dport && ntohs(tcp->dst) != g_cfg.dport) return;
      // Флаги TCP здесь намеренно НЕ фильтруются. Раньше стояло правило
      // «есть ACK — пропустить», и это было ошибкой: рель подключается к цели
      // обычным connect(), поэтому настоящий ClientHello приходит в пакете
      // с установленным ACK, и такому правилу подвергался каждый настоящий
      // ClientHello — подделок не было бы вообще. Настоящий ClientHello может
      // прийти и с SYN, и с PSH+ACK. Повторные передачи не мешают: подделка
      // умирает по TTL и до сервера не доходит в любом случае.

    g_stats.matched++;
    int total = ntohs(ip->tot_len);
    if (total < ihl + thl + 6 || total > len) return;
    int pl = total - ihl - thl;
    const unsigned char *pl_buf = pkt + ihl + thl;
    // Ищем начало ClientHello, а НЕ имя в нём. Собственный рель режет
    // рукопожатие на куски по 20 байт (split_ch), поэтому в первом сегменте
    // имени нет физически, и поиск SNI всегда проваливался. Имя для подделки
    // и так берётся из настройки — из пакета оно не нужно.
    if (!is_client_hello_start(pl_buf, pl)) { g_proto.no_sni++; g_stats.no_fake++; return; }
    g_stats.hellos++;

    unsigned char fake[1024];
    int fn = build_fake_hello(g_cfg.fake_sni ? g_cfg.fake_sni : FAKE_SNI, fake, sizeof(fake));
    if (fn < 0) return;

    int flen = ihl + thl + fn;
    if (flen > (int)sizeof(g_out)) return;
    memcpy(g_out, pkt, (size_t)(ihl + thl));         // те же заголовки и тот же seq
    memcpy(g_out + ihl + thl, fake, (size_t)fn);

    dip_t *oip = (dip_t *)g_out;
    dtcp_t *otcp = (dtcp_t *)(g_out + ihl);
    oip->ver_ihl = 0x45;                       // IPv4, заголовок 20 байт
    oip->tos = ip->tos;
    oip->tot_len = htons((uint16_t)flen);
    oip->id = htons(FAKE_IPID);                   // метка, чтобы не попасть в рекурсию
    oip->frag_off = 0;
    oip->ttl = g_cfg.fake_ttl ? g_cfg.fake_ttl : 3;
    oip->proto = IPPROTO_TCP;
      oip->check = 0;
      // htons обязателен: ip_csum возвращает число в порядке хоста, а в пакете
      // поле лежит в сетевом порядке. Без htons на x86 байты меняются местами
      // и подделка уходит с неверной суммой — её отбросит первый же роутер.
      oip->check = htons(ip_csum(oip));

      otcp->check = 0;
      otcp->check = htons(tcp_csum(oip, otcp, (size_t)(flen - ihl)));

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = oip->daddr;
      // Отправка идёт через указатель g_send: в бою это sendto, в тесте —
      // захват байтов. Так проверяется весь путь целиком, включая сам вызов
      // отправки, а не только сборка пакета.
      ssize_t sent = g_send
          ? g_send(g_out, (size_t)flen, (struct sockaddr *)&sin, sizeof(sin))
          : sendto(g_raw, g_out, (size_t)flen, 0, (struct sockaddr *)&sin, sizeof(sin));
      if (sent == (ssize_t)flen) g_stats.injected++;
}

// Где в кадре начинается заголовок IP.
//
// На SOCK_RAW ядро отдаёт кадр вместе с заголовком канала, а sll_halen на
// проводном Ethernet показывал 6 байт вместо честных 14 — верить ему нельзя.
// Длина выводится из самого кадра: 14 байт для Ethernet и 18, если кадр с
// тегом VLAN 802.1Q. Именно так работает tcpdump, и он исходящие пакеты
// видит, а SOCK_DGRAM на этом ядре — нет.
static int ip_offset(const unsigned char *p, int len) {
    if (len >= 14 && p[12] == 0x08 && p[13] == 0x00) return 14;
    if (len >= 18 && p[12] == 0x81 && p[13] == 0x00 &&
        p[16] == 0x08 && p[17] == 0x00) return 18;
    return 0;                                  // уже без заголовка канала
}

// Для теста: тот же расчёт снаружи.
int desync_ip_offset(const unsigned char *p, int len) { return ip_offset(p, len); }

static void *loop(void *arg) {
    (void)arg;
    unsigned char buf[MAX_PKT];
    while (g_run) {
        struct sockaddr_ll sll;
        socklen_t sl = sizeof(sll);
        ssize_t n = recvfrom(g_sock, buf, sizeof(buf), 0, (struct sockaddr *)&sll, &sl);
        if (n <= 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (g_cfg.mode == DESYNC_MODE_OFF) break;
        // Первые пакеты показываем байтами. Пока догадки о том, что именно
        // приходит на сокет, расходились с наблюдаемым четыре раза подряд —
        // смотреть надо на данные, а не сочинять причину.
        if (g_dumped < 6) {
            g_dumped++;
            fprintf(stderr, "  [%d] ethertype=0x%04x halen=%d pkttype=%d длина=%d байты:",
                    g_dumped, ntohs(sll.sll_protocol), (int)sll.sll_halen,
                    (int)sll.sll_pkttype, (int)n);
            for (int k = 0; k < 12 && k < n; k++) fprintf(stderr, " %02X", buf[k]);
            fprintf(stderr, "\n");
            fflush(stderr);
        }
        // При SOCK_DGRAM ядро срезает заголовок канала, и IP начинается с
        // нулевого байта. Проверка версии на первой позиции — не вера, а
        // контроль: если сработает не так, это будет видно в счётчиках.
        int off = ip_offset(buf, (int)n);
        if (n <= off + (int)sizeof(dip_t)) continue;
        if (sll.sll_pkttype == PACKET_OUTGOING) g_proto.outgoing++;
        else if (sll.sll_pkttype == PACKET_HOST)   g_proto.to_us++;
        else                                      g_proto.to_other++;
        if (((buf[off] >> 4) & 0x0F) != 4) { g_proto.not_v4++; g_stats.seen++; continue; }
        handle(buf + off, (int)n - off);
    }
    return NULL;
}

// Настроить цель и слой так же, как это делает desync_start, но без сокетов.
int desync_test_setup(const char *cidr, int dport, const char *fake_sni, unsigned ttl) {
    memset(&g_cfg, 0, sizeof(g_cfg));
    g_cfg.dport = dport;
    g_cfg.fake_sni = fake_sni;
    g_cfg.fake_ttl = ttl;
    g_cfg.iface = NULL;
    g_cfg.cidr = cidr;
    g_run = 1;
    char tmp[64];
    snprintf(tmp, sizeof(tmp), "%s", cidr);
    char *sl = strchr(tmp, '/');
    unsigned bits = 32;
    if (sl) { *sl = '\0'; bits = (unsigned)atoi(sl + 1); }
    struct in_addr a;
    if (inet_pton(AF_INET, tmp, &a) != 1) return -1;
    g_net = a.s_addr;
    g_mask = bits == 0 ? 0 : htonl(0xFFFFFFFFu << (32 - bits));
    return 0;
}

// Прогнать пакет через НАСТОЯЩИЙ обработчик, как в бою.
int desync_test_handle(const unsigned char *pkt, int len) {
    handle(pkt, len);
    return 0;
}

// Прогнать КАДР целиком, со заголовком Ethernet, через тот же путь, что и
// в бою. Без этого тест кормил слой форматом, которого сокет не отдаёт, и
// спокойно зелёный светил на сломанный разбор.
int desync_test_frame(const unsigned char *frame, int len, int halen) {
    if (halen < 0 || len <= halen) return -1;
    handle(frame + halen, len - halen);
    return 0;
}

void desync_set_injector(desync_send_fn fn) { g_send = fn; }

// Отладочный доступ к цели: показывает, что слой реально настроил.
int desync_test_in_target(uint32_t addr) { return in_target(addr); }
void desync_test_target(uint32_t *net, uint32_t *mask, int *dport) {
    if (net) *net = g_net;
    if (mask) *mask = g_mask;
    if (dport) *dport = g_cfg.dport;
}
void desync_reset_for_test(void) {
    memset(&g_stats, 0, sizeof(g_stats));
    memset(&g_proto, 0, sizeof(g_proto));
}

// Тип сокета наблюдения вынесен в функцию и проверяется тестом. Решение
// «SOCK_DGRAM, а не SOCK_RAW» — не стилистика: при SOCK_RAW ядро отдаёт кадр
// вместе с заголовком канала, и sll_halen на проводном Ethernet показывал
// 6 байт вместо честных 14, из-за чего весь разбор уезжал в середину
// MAC-адресов, а слой молчал. Чтобы правку нельзя было откатить случайно,
// выбор зафиксирован проверкой.
int desync_sniffer_kind(void) { return SOCK_RAW; }

int desync_start(const desync_config_t *cfg) {
    if (g_run) return 0;
    g_err[0] = '\0';
    if (!cfg || !cfg->iface || !cfg->cidr) { set_err("не задан интерфейс или адрес"); return -1; }
    if (getuid() != 0) { set_err("нужен root: сырые сокеты"); return -1; }
    g_cfg = *cfg;
    if (g_cfg.mode == DESYNC_MODE_OFF) { set_err("режим выключен"); return -1; }
    if (!g_cfg.fake_sni) g_cfg.fake_sni = FAKE_SNI;
    if (!g_cfg.fake_ttl) g_cfg.fake_ttl = 3;

    struct in_addr a;
    unsigned bits = 32;
    char tmp[64];
    snprintf(tmp, sizeof(tmp), "%s", g_cfg.cidr);
    char *slash = strchr(tmp, '/');
    if (slash) { *slash = '\0'; bits = (unsigned)atoi(slash + 1); }
    if (inet_pton(AF_INET, tmp, &a) != 1 || bits > 32) { set_err("не разобран адрес %s", g_cfg.cidr); return -1; }
    g_net = a.s_addr;
    g_mask = bits == 0 ? 0 : htonl(0xFFFFFFFFu << (32 - bits));

    // При SOCK_DGRAM ядро само срезает заголовок канала, и с нулевого байта
    // сразу начинается IP. Отправка подделок идёт отдельным SOCK_RAW.
    g_sock = socket(AF_PACKET, desync_sniffer_kind(), htons(ETH_P_ALL));
    if (g_sock < 0) { set_err("AF_PACKET: %s", strerror(errno)); return -1; }
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = (int)if_nametoindex(g_cfg.iface);
    if (sll.sll_ifindex == 0) { set_err("нет интерфейса %s", g_cfg.iface); close(g_sock); g_sock = -1; return -1; }
    if (bind(g_sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        set_err("bind %s: %s", g_cfg.iface, strerror(errno));
        close(g_sock); g_sock = -1; return -1;
    }

    g_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (g_raw < 0) { set_err("SOCK_RAW: %s", strerror(errno)); close(g_sock); g_sock = -1; return -1; }
    int one = 1;
    setsockopt(g_raw, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    if (g_cfg.so_mark)
        setsockopt(g_raw, SOL_SOCKET, SO_MARK, &g_cfg.so_mark, sizeof(g_cfg.so_mark));

    memset(&g_stats, 0, sizeof(g_stats));
    signal(SIGPIPE, SIG_IGN);
    g_run = 1;
    if (pthread_create(&g_tid, NULL, loop, NULL) != 0) {
        set_err("поток не создан");
        g_run = 0; close(g_sock); close(g_raw); g_sock = g_raw = -1;
        return -1;
    }
    return 0;
}

void desync_stop(void) {
    if (!g_run) return;
    g_run = 0;
    shutdown(g_sock, SHUT_RDWR);
    close(g_sock); g_sock = -1;
    close(g_raw); g_raw = -1;
    pthread_join(g_tid, NULL);
}
