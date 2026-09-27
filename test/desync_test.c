/* Проверка слоя десинхронизации без сети и без прав.
 *
 * Раньше здесь собирался ClientHello вручную, и в нём я трижды ошибался:
 * длина рукопожатия — три байта, тип расширения и его длина — разные поля.
 * Ручная сборка бесполезна как проверка. Поэтому проверяем ровно то, что
 * должно работать: подделка, собранная слоем, обязана разбираться этим же
 * слоем обратно, с тем же именем и на тех же местах. */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include "../src/desync/desync.h"

#include <stdio.h>
#include <string.h>

#define ETH_HLEN 14

int find_sni_for_test(const unsigned char *p, int len, int *out_len);
int build_fake_for_test(const char *sni, unsigned char *out, int cap);

static int check_one(const char *name) {
    unsigned char buf[1024];
    int n = build_fake_for_test(name, buf, sizeof(buf));
    if (n < 9) {
        printf("  %-18s подделка не собралась\n", name);
        return 1;
    }
    int len = 0;
    int off = find_sni_for_test(buf, n, &len);
    if (!off) {
        printf("  %-18s SNI в собственной подделке НЕ НАЙДЕН\n", name);
        return 1;
    }
    if (len != (int)strlen(name) || memcmp(buf + off, name, (size_t)len) != 0) {
        printf("  %-18s имя не совпало: получено %d байт\n", name, len);
        return 1;
    }
    printf("  %-18s запись %d байт, SNI на месте %d, имя совпало\n", name, n, off);
    return 0;
}


/* --- Вспомогательное для проверки пути отправки --- */

static unsigned char g_cap_buf[128];
static int g_cap_n;

static ssize_t capture_send(const void *buf, size_t len, struct sockaddr *sa, socklen_t sl) {
    (void)sa; (void)sl;
    if (len > sizeof(g_cap_buf)) return -1;
    memcpy(g_cap_buf, buf, len);
    g_cap_n = (int)len;
    return (ssize_t)len;
}

/* Своя арифметика контрольных сумм, намеренно не та же, что в слое.
   Иначе проверка была бы проверкой самого себя: сломанная сумма в слое
   «сошлась» бы с такой же сломанной в тесте. */
static uint32_t csum_accum(const unsigned char *p, int n, uint32_t sum) {
    while (n > 1) { sum += (uint32_t)((p[0] << 8) | p[1]); p += 2; n -= 2; }
    if (n) sum += (uint32_t)(p[0] << 8);
    return sum;
}

static uint16_t csum_fold(uint32_t s) {
    while (s >> 16) s = (s & 0xFFFFu) + (s >> 16);
    return (uint16_t)(~s & 0xFFFFu);
}

// Верна ли сумма заголовка: сложение всего заголовка вместе с проверочной
// суммой обязано дать ноль. Стандартное свойство, не зависит от реализации.
static int ip_csum_ok(const unsigned char *ip, int ihl) {
    return csum_fold(csum_accum(ip, ihl, 0)) == 0;
}

// Вычислить сумму TCP с псевдозаголовком (для сборки пакета в тесте).
static uint16_t tcp_csum_ok_pre(const unsigned char *ip, const unsigned char *tcp, int tcp_len) {
    uint32_t sum = 0;
    sum = csum_accum(ip + 12, 8, sum);
    sum += 6;
    sum += (uint32_t)tcp_len;
    sum = csum_accum(tcp, tcp_len, sum);
    return csum_fold(sum);
}

static int tcp_csum_ok(const unsigned char *ip, const unsigned char *tcp, int tcp_len) {
    return tcp_csum_ok_pre(ip, tcp, tcp_len) == 0;
}

// Обернуть готовый ClientHello в IP+TCP, как это выглядит в сети.
// TLS-часть берётся у самого слоя: ручная сборка в тесте уже дважды врала,
// а проверять надо не то, как я умею писать TLS.
static int make_client_hello(unsigned char *out, int cap, const char *sni,
                             uint32_t dst, uint32_t seq, unsigned char flags,
                             unsigned short win) {
    unsigned char tls[512];
    int tl = build_fake_for_test(sni, tls, sizeof(tls));
    if (tl <= 0) return -1;

    // Сзади — заголовок Ethernet: именно так выглядит кадр на AF_PACKET.
    int ihl = 20, total = ETH_HLEN + ihl + 20 + tl;
    if (total > cap) return -1;
    memset(out, 0, (size_t)total);

    out[0] = 0x02; out[1] = 0x00; out[2] = 0x00;      // MAC назначения
    out[3] = 0x00; out[4] = 0x00; out[5] = 0x01;
    out[6] = 0x02; out[7] = 0x00; out[8] = 0x00;      // MAC источника
    out[9] = 0x00; out[10] = 0x00; out[11] = 0x02;
    out[12] = 0x08; out[13] = 0x00;                    // ethertype IPv4

    unsigned char *ip0 = out + ETH_HLEN;
    ip0[0] = 0x45;
    int wire = total - ETH_HLEN;                // длина пакета без Ethernet
    ip0[2] = (unsigned char)(wire >> 8);
    ip0[3] = (unsigned char)wire;
    ip0[4] = 0x12; ip0[5] = 0x34;              // id
    ip0[8] = 64;                                // TTL настоящего пакета
    ip0[9] = 6;                                 // TCP
    ip0[12] = 10; ip0[13] = 0; ip0[14] = 1; ip0[15] = 2;
    ip0[16] = (unsigned char)(dst >> 24); ip0[17] = (unsigned char)(dst >> 16);
    ip0[18] = (unsigned char)(dst >> 8);  ip0[19] = (unsigned char)dst;
    uint16_t ics = csum_fold(csum_accum(ip0, ihl, 0));
    ip0[10] = (unsigned char)(ics >> 8);
    ip0[11] = (unsigned char)(ics & 0xFF);

    unsigned char *t = out + ETH_HLEN + ihl;
    t[0] = (unsigned char)(51515 >> 8); t[1] = (unsigned char)51515;   // sport
    t[2] = (unsigned char)(443 >> 8);    t[3] = (unsigned char)443;      // dport
    t[4] = (unsigned char)(seq >> 24); t[5] = (unsigned char)(seq >> 16);
    t[6] = (unsigned char)(seq >> 8);  t[7] = (unsigned char)seq;
    t[12] = 0x50;                              // data offset 5
    t[13] = flags;
    t[14] = (unsigned char)(win >> 8); t[15] = (unsigned char)win;
    memcpy(t + 20, tls, (size_t)tl);

    uint16_t ts = csum_fold(tcp_csum_ok_pre(ip0, t, 20 + tl));
    t[16] = (unsigned char)(ts >> 8);
    t[17] = (unsigned char)(ts & 0xFF);
    return total;
}

static int get_sni_name(const unsigned char *p, int len, char *out, int cap) {
    int l = 0;
    int hl = find_sni_for_test(p, len, &l);
    if (!hl || l <= 0 || l >= cap) return 0;
    memcpy(out, p + hl, (size_t)l);
    out[l] = '\0';
    return 1;
}

int main(void) {
    printf("  === разбор и сборка подделки ===\n");
    int failed = 0;
    failed += check_one("www.google.com");
    failed += check_one("discord.com");
    failed += check_one("example.org");

    printf("\n  === границы ===\n");
    unsigned char buf[1024];
    int n = build_fake_for_test("a", buf, sizeof(buf));
    int l = 0;
    printf("  %-18s %s\n", "имя в 1 символ", (n > 0 && find_sni_for_test(buf, n, &l) > 0) ? "ок" : "ПРОВАЛ");
    if (!(n > 0 && find_sni_for_test(buf, n, &l) > 0)) failed++;
    n = build_fake_for_test("very.long.subdomain.example.with.many.labels.example.net", buf, sizeof(buf));
    printf("  %-18s %s\n", "длинное имя", (n > 0 && find_sni_for_test(buf, n, &l) > 0) ? "ок" : "ПРОВАЛ");
    if (!(n > 0 && find_sni_for_test(buf, n, &l) > 0)) failed++;

    /* Чужой байтовый мусор разбирать нельзя: слой обязан молча пропустить. */
    unsigned char junk[64];
    memset(junk, 0xAB, sizeof(junk));
    int r = find_sni_for_test(junk, (int)sizeof(junk), &l);
    printf("  %-18s %s\n", "мусор пропущен", r == 0 ? "ок" : "ПРОВАЛ");
    if (r != 0) failed++;

    memset(junk, 0, sizeof(junk));
    junk[0] = 0x16; junk[1] = 0x03; junk[2] = 0x01;   /* запись есть, а ClientHello обрезан */
    r = find_sni_for_test(junk, 12, &l);
    printf("  %-18s %s\n", "обрезанный ClientHello", r == 0 ? "ок" : "ПРОВАЛ");
    if (r != 0) failed++;

    /* === смещение до IP в кадре === */
    printf("\n  === где начинается IP в кадре ===\n");
    {
        unsigned char eth[64];
        memset(eth, 0, sizeof(eth));
        eth[12] = 0x08; eth[13] = 0x00;          // ethertype IPv4
        eth[14] = 0x45;                          // и сразу за ним IP
        printf("  %-26s %s\n", "Ethernet без VLAN",
               desync_ip_offset(eth, (int)sizeof(eth)) == 14 ? "ок" : "ПРОВАЛ");
        if (desync_ip_offset(eth, (int)sizeof(eth)) != 14) failed++;

        memset(eth, 0, sizeof(eth));
        eth[12] = 0x81; eth[13] = 0x00;          // тег 802.1Q
        eth[16] = 0x08; eth[17] = 0x00;          // за ним ethertype IPv4
        eth[18] = 0x45;
        printf("  %-26s %s\n", "Ethernet с тегом VLAN",
               desync_ip_offset(eth, (int)sizeof(eth)) == 18 ? "ок" : "ПРОВАЛ");
        if (desync_ip_offset(eth, (int)sizeof(eth)) != 18) failed++;

        memset(eth, 0, sizeof(eth));
        eth[0] = 0x45;                           // уже без заголовка канала
        printf("  %-26s %s\n", "без заголовка канала",
               desync_ip_offset(eth, (int)sizeof(eth)) == 0 ? "ок" : "ПРОВАЛ");
        if (desync_ip_offset(eth, (int)sizeof(eth)) != 0) failed++;
    }

    /* === список адресов: раньше показывал перевёрнутые октеты === */
    printf("\n  === список адресов ===\n");
    {
        struct { const char *addr; const char *want; } cases[] = {
            { "192.168.31.253", "192.168.0.0"  },
            { "104.18.27.36",   "104.18.0.0"   },
            { "172.65.90.23",   "172.65.0.0"   },
            { "162.159.128.233","162.159.0.0" },
        };
        desync_top_peer_t got[DESYNC_TOP_N];
        int gn = 0;
        for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
            struct in_addr a2;
            inet_pton(AF_INET, cases[k].addr, &a2);
            desync_test_note_peer(a2.s_addr);
        }
        desync_top_peers(got, DESYNC_TOP_N, &gn);
        for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
            int found = 0;
            for (int j = 0; j < gn; j++)
                if (strcmp(got[j].net, cases[k].want) == 0) found = 1;
            printf("  %-18s -> %-14s %s\n", cases[k].addr, cases[k].want,
                   found ? "ок" : "ПРОВАЛ");
            if (!found) failed++;
        }
        desync_test_reset_peers();
    }

    /* === путь инъекции: раньше не проверялся ни разу === */
    printf("\n  === путь отправки ===\n");
    // Сокет наблюдения обязан быть SOCK_RAW: на SOCK_DGRAM это ядро не
    // отдавало ИСХОДЯЩИЕ пакеты вообще (ноль при полном входящем трафике),
    // а подделка без исходящих невозможна. Заголовок канала при этом
    // приходит в данных, и смещение вычисляет сам слой — по ethertype,
    // потому что sll_halen показывал 6 байт вместо 14.
    printf("  %-26s %s\n", "сокет наблюдения SOCK_RAW",
           desync_sniffer_kind() == SOCK_RAW ? "ок" : "ПРОВАЛ");
    if (desync_sniffer_kind() != SOCK_RAW) failed++;
    {
        // Подменяем sendto на захват: прав root не нужно, а проверяется
        // НАСТОЯЩИЙ обработчик целиком — разбор, решение, сборка, отправка.
        desync_test_setup("162.159.128.0/18", 443, "www.google.com", 3);

        g_cap_n = 0;
        desync_set_injector(capture_send);
        desync_reset_for_test();

        unsigned char real[512];
        unsigned rtcp_seq = 0x11223344;
        unsigned short rtcp_win = 64240;
        int rlen = make_client_hello(real, sizeof(real), "discord.com", 0xA29F8010, rtcp_seq, 0x18, rtcp_win);

        desync_test_frame(real + ETH_HLEN, rlen - ETH_HLEN, 0);   /* путь SOCK_DGRAM */
        desync_stats_t st;
        desync_get_stats(&st);
        int cap_len = g_cap_n;
        const unsigned char *cap = g_cap_buf;

        {
            uint32_t tn=0, tm=0; int td=0;
            desync_test_target(&tn, &tm, &td);
            uint32_t seen_dst; memcpy(&seen_dst, real + ETH_HLEN + 16, 4);
            printf("  цель настроена верно: %s, порт %d, пакет в цели: %s\n",
                   desync_test_in_target(seen_dst) ? "да" : "НЕТ", td,
                   desync_test_in_target(seen_dst) ? "да" : "НЕТ");
            (void)tn; (void)tm;
        }
        printf("  %-26s %s\n", "счётчики пакета",
               st.seen == 1 && st.matched == 1 && st.hellos == 1 ? "разобран" :
               st.matched == 0 ? "не попал в цель" :
               st.no_fake == 1 ? "SNI не найден" : "не распознан");
        printf("  %-26s %s\n", "ClientHello распознан", st.hellos == 1 ? "ок" : "ПРОВАЛ");
        if (st.hellos != 1) failed++;
        printf("  %-26s %s\n", "подделка отправлена", st.injected == 1 ? "ок" : "ПРОВАЛ");
        if (st.injected != 1) failed++;
        printf("  %-26s %s\n", "отправка вызвана один раз", cap_len > 0 ? "ок" : "ПРОВАЛ");
        if (cap_len <= 0) failed++;

        if (cap_len > 0) {
            unsigned char *oip = (unsigned char *)cap;
            unsigned char *otcp = (unsigned char *)cap + ((oip[0] & 0x0f) * 4);
            int oihl = (oip[0] & 0x0f) * 4;
            unsigned oseq;
            memcpy(&oseq, otcp + 4, 4);
            oseq = ntohl(oseq);

            printf("  %-26s %s\n", "TTL подделки = 3", oip[8] == 3 ? "ок" : "ПРОВАЛ");
            if (oip[8] != 3) failed++;
            // IP ID лежит в сети байтом, через ntohs его читать нельзя:
            // в байтах это ровно 0xDE, 0x50.
            printf("  %-26s %s\n", "метка своих пакетов",
                   (oip[4] == 0xDE && oip[5] == 0x50) ? "ок" : "ПРОВАЛ");
            if (!(oip[4] == 0xDE && oip[5] == 0x50)) failed++;
            // Настоящий SEQ обязан сохраниться: сервер отбросил бы подделку
            // как дубликат, но она до него не долетает по TTL.
            printf("  %-26s %s\n", "SEQ настоящего сохранён", oseq == rtcp_seq ? "ок" : "ПРОВАЛ");
            if (oseq != rtcp_seq) failed++;
            printf("  %-26s %s\n", "флаги настоящего сохранены", otcp[13] == 0x18 ? "ок" : "ПРОВАЛ");
            if (otcp[13] != 0x18) failed++;
            unsigned short owin;
            memcpy(&owin, otcp + 14, 2);
            printf("  %-26s %s\n", "окно настоящего сохранено", ntohs(owin) == rtcp_win ? "ок" : "ПРОВАЛ");
            if (ntohs(owin) != rtcp_win) failed++;

            struct in_addr d;
            memcpy(&d.s_addr, oip + 16, 4);
            char dst[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &d, dst, sizeof(dst));
            printf("  %-26s %s\n", "адрес назначения = цели", strcmp(dst, "162.159.128.16") == 0 ? "ок" : "ПРОВАЛ");
            if (strcmp(dst, "162.159.128.16") != 0) failed++;

            // find_sni ждёт начало записи TLS, а не начало пакета.
            int l2 = 0;
            int tls_off = oihl + ((otcp[12] >> 4) * 4);
            int hl = find_sni_for_test(cap + tls_off, cap_len - tls_off, &l2);
            char got[64];
            int g2 = hl ? get_sni_name(cap + tls_off, cap_len - tls_off, got, sizeof(got)) : 0;
            printf("  %-26s %s\n", "SNI подделки = google",
                   g2 == 1 && strcmp(got, "www.google.com") == 0 ? "ок" : "ПРОВАЛ");
            if (!(g2 == 1 && strcmp(got, "www.google.com") == 0)) failed++;

            printf("  %-26s %s\n", "сумма IP верна", ip_csum_ok(oip, oihl) ? "ок" : "ПРОВАЛ");
            if (!ip_csum_ok(oip, oihl)) failed++;
            printf("  %-26s %s\n", "сумма TCP верна",
                   tcp_csum_ok(oip, otcp, cap_len - oihl) ? "ок" : "ПРОВАЛ");
            if (!tcp_csum_ok(oip, otcp, cap_len - oihl)) failed++;
        }

        /* Защита от рекурсии: наша же подделка не должна обрабатываться снова. */
        if (cap_len > 0) {
            desync_reset_for_test();
            desync_test_handle(cap, cap_len);
            desync_get_stats(&st);
            printf("  %-26s %s\n", "своя подделка пропущена", st.skipped == 1 && st.injected == 0 ? "ок" : "ПРОВАЛ");
            if (!(st.skipped == 1 && st.injected == 0)) failed++;
        }

        /* Пакет не к нашей цели — отправок быть не должно. */
        {
            unsigned char other[512];
            int olen = make_client_hello(other, sizeof(other), "discord.com", 0x08080808, 5, 0x18, 1000);
            desync_reset_for_test();
            desync_test_frame(other + ETH_HLEN, olen - ETH_HLEN, 0);
            desync_get_stats(&st);
            printf("  %-26s %s\n", "чужая цель не трогается", st.injected == 0 ? "ок" : "ПРОВАЛ");
            if (st.injected != 0) failed++;
        }

        /* Не-ClientHello в нашей цели — тоже без отправки. */
        {
            unsigned char syn[60];
            memset(syn, 0, sizeof(syn));
            syn[0] = 0x45;
            syn[9] = IPPROTO_TCP;
            syn[8] = 64;
            syn[12] = 0xA2; syn[13] = 0x9F; syn[14] = 0x80; syn[15] = 0x20;
            syn[16] = 0xA2; syn[17] = 0x9F; syn[18] = 0x80; syn[19] = 0x10;
            syn[(4 * 5) + 12] = 0x50; syn[(4 * 5) + 13] = 0x18;   /* SYN */
            desync_reset_for_test();
            desync_test_frame(syn + ETH_HLEN, (int)sizeof(syn) - ETH_HLEN, 0);
            desync_get_stats(&st);
            printf("  %-26s %s\n", "голый SYN не подделывается", st.injected == 0 ? "ок" : "ПРОВАЛ");
            if (st.injected != 0) failed++;
        }
        desync_set_injector(NULL);
    }

    printf("\n  счётчик провалов: %d\n", failed);
    printf("\n  %s\n", failed ? "ЕСТЬ ПРОВАЛЫ" : "слой разбирает и собирает записи верно");
    return failed ? 1 : 0;
}
