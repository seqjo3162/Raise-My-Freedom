// discord module test — юнит + сетевые проверки.
//
// Собирается и запускается через src/modules/discord/Makefile:
//     make -C src/modules/discord test
//
// Модуль включается напрямую (.c), чтобы достать static-хелперы.
//
// Проверяется без root и без сети:
//   * разбор адресов и попадание в диапазоны Discord (validate_ip);
//   * граница «можно удалять» (dest_in_discord) — обязана НЕ задевать
//     адреса VRChat, иначе один модуль сносит правила другому;
//   * кодирование домена в wire-паттерн, включая опасные длины лейбла;
//   * разрез SNI и сборка фрагментированного ClientHello — в sni_relay,
//     то есть в том коде, который реально работает, а не в его копии;
//   * чтение webui/discord.conf: все ключи доходят до переменных.
//
// Сетевая часть (DNS, E2E через рель) запускается только при наличии сети
// и не требует root.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "../src/discord_module.c"
#include "../../../common/sni_relay.h"
#include "../../../netfilter/netfilter.h"
#include "../../../dns/dns_resolve.h"

static int failures = 0;
static int checks = 0;
#define CHECK(cond, ...) do { \
    checks++; \
    if (cond) { printf("  [OK]   " __VA_ARGS__); printf("\n"); } \
    else { printf("  [FAIL] " __VA_ARGS__); printf("\n"); failures++; } \
} while (0)
#define INFO(...) do { printf("  [..]   " __VA_ARGS__); printf("\n"); } while (0)

// ── 1. адреса ────────────────────────────────────────────────────────────

static void test_ip_parse(void) {
    printf("[ADDR] разбор адреса\n");
    unsigned char b[4];
    CHECK(parse_ipv4("162.159.128.233", b) && b[0]==162 && b[1]==159 && b[2]==128 && b[3]==233,
          "полный адрес разобран");
    CHECK(parse_ipv4("0.0.0.0", b) && !b[0] && !b[3], "0.0.0.0 разобран");
    // inet_aton согласился бы на «1.2.3» и на «1.2.3.4.5» — здесь нет.
    CHECK(!parse_ipv4("1.2.3", b),        "«1.2.3» отвергнут (inet_aton бы принял)");
    CHECK(!parse_ipv4("1.2.3.4.5", b),    "«1.2.3.4.5» отвергнут");
    CHECK(!parse_ipv4("1.2.3.4 ", b),  "пробел в конце отвергнут");
    CHECK(!parse_ipv4(" 1.2.3.4", b),  "пробел в начале отвергнут");
    CHECK(!parse_ipv4("1.2.3.4x", b), "буква в конце отвергнута");
    CHECK(!parse_ipv4("300.1.1.1", b),    "октет > 255 отвергнут");
    CHECK(!parse_ipv4("1.2.3.04", b),     "ведущий ноль в октете отвергнут");
    CHECK(!parse_ipv4("не ip", b),         "мусор отвергнут");
    CHECK(!parse_ipv4("", b),              "пустая строка отвергнута");
    CHECK(!parse_ipv4(NULL, b),            "NULL отвергнут");
}

static void test_validate_ip(void) {
    printf("[ADDR] валидатор инфраструктуры\n");
    struct { const char *ip; const char *what; int want; } t[] = {
        {"162.159.128.233", "discord.com", 1},
        {"162.159.191.255", "верх /18", 1},
        {"162.159.192.0",   "выше /18", 0},
        {"162.159.127.255", "ниже /18", 0},
        {"104.16.0.0",      "низ 104.16/12", 1},
        {"104.31.255.255",  "верх 104.16/12", 1},
        {"104.32.0.0",      "выше 104.16/12", 0},
        {"104.18.0.0",      "низ 104.18/16", 1},
        {"104.19.0.0",      "внутри 104.16/12 (104.18/16 не покрывает)", 1},
        {"104.18.255.255",  "верх 104.18/16", 1},
        {"34.126.226.51",   "dl2.discordapp.net (GCP)", 1},
        {"34.127.0.1",      "соседний GCP", 0},
        {"8.47.69.0",       "sinkhole (vrchat_module.c:29)", 0},
        {"8.6.112.6",       "ложный ответ dns.google", 0},
        {"143.204.238.8",   "assets.vrchat.com (VRChat)", 0},
        {"108.157.229.62",  "files.vrchat.cloud (VRChat)", 0},
        {"216.198.53.6",    "help.vrchat.com (VRChat)", 0},
        {"1.1.1.1",         "Cloudflare DNS", 0},
        {"8.8.8.8",         "Google DNS", 0},
        {"127.0.0.1",       "localhost", 0},
        {NULL, NULL, 0}
    };
    for (int i = 0; t[i].ip; i++)
        CHECK(discord_validate_ip(t[i].ip) == t[i].want,
              "%-16s -> %d  %s", t[i].ip, t[i].want, t[i].what);

    // Честная граница метода: эти адреса Cloudflare, и по адресу нельзя
    // отличить Discord от чужого сайта. Документируем, чтобы правка списка
    // диапазонов не выглядела случайной.
    INFO("Cloudflare общий, валидатор их пропускает: x.com=%d docs.vrchat.com=%d "
         "- по адресу их от Discord не отличить",
         discord_validate_ip("162.159.140.229"), discord_validate_ip("104.16.241.118"));
}

static void test_dest_scope(void) {
    printf("[ADDR] граница «разрешено удалять»\n");
    // Должны сниматься: адреса пинов и всё, что внутри 162.159.128.0/18.
    CHECK(dest_in_discord("162.159.128.233"), "пин discord.com в границе");
    CHECK(dest_in_discord("162.159.137.232"), "legacy-хвост внутри /18 в границе");
    CHECK(dest_in_discord("104.18.48.115"),   "пин dl.discordapp.net в границе");
    CHECK(dest_in_discord("34.126.226.51"),   "пин dl2.discordapp.net в границе");
    CHECK(dest_in_discord("162.159.128.0/18"),"с префиксом /18 распознан");
    // НЕ должны: чужие модули и всё, что не наше.
    CHECK(!dest_in_discord("104.18.26.36"),  "api.vrchat.com НЕ в границе");
    CHECK(!dest_in_discord("104.18.6.156"),  "unity-frontend VRChat НЕ в границе");
    CHECK(!dest_in_discord("104.16.241.118"),"docs.vrchat.com НЕ в границе");
    // Остаточная экспозиция, зафиксированная осознанно: x.com лежит в
    // 162.159.128.0/18, поэтому формально попадает в границу удаления.
    // Сегодня это безвредно — у x.com нет ни модуля, ни правил iptables, есть
    // только запись в hosts.txt, а та clean-up не трогает. Но если у x.com
    // появится модуль со своим правилом на этом /32, Discord его снесёт.
    CHECK(dest_in_discord("162.159.140.229"),
          "x.com в границе (адрес внутри /18) - задокументировано");
    CHECK(!dest_in_discord("1.1.1.1"),        "1.1.1.1 НЕ в границе");
    CHECK(!dest_in_discord("192.168.1.0/24"), "локальная сеть НЕ в границе");
    CHECK(!dest_in_discord("104.16.0.0/12"),  "широкий 104.16/12 НЕ в границе");
    CHECK(!dest_in_discord("104.18.0.0/16"),  "широкий 104.18/16 НЕ в границе");
    CHECK(!dest_in_discord("мусор"),          "мусор отвергнут");
    CHECK(!dest_in_discord(NULL),             "NULL отвергнут");
}

// ── 2. wire-паттерн ──────────────────────────────────────────────────────

static void test_wire_hex(void) {
    printf("[DNS] шаблон домена уходит в iptables только как hex\n");
    char hex[256] = {0};
    int n = nf_wire_hex_pattern("discord.com", hex, sizeof hex);
    CHECK(n > 0, "discord.com закодирован (%d симв.)", n);
    CHECK(strcmp(hex, "07646973636F726403636F6D") == 0,
          "точное значение: %s", hex);
    CHECK(strncmp(hex, "07", 2) == 0, "длина первого лейбла = 07");

    nf_wire_hex_pattern("dl.discordapp.net", hex, sizeof hex);
    CHECK(strcmp(hex, "02646C0A646973636F7264617070036E6574") == 0,
          "dl.discordapp.net: %s", hex);

    // Главное свойство: на выходе только 0-9A-F, поэтому ни один байт не
    // может стать кавычкой, долларом или обратным слэшем для shell.
    // Длины лейбла 34, 36 и 39 давали 0x22, 0x24 и 0x27.
    char label[80];
    int all_bad[4] = { 0, 0, 0, 0 };
    const char *marks = "\"$`&|;<>";
    for (int len = 1; len <= 63; len++) {
        char dom[128];
        label[0] = 'a';
        memset(label + 1, 'z', (size_t)(len - 1));
        label[len] = '\0';
        snprintf(dom, sizeof dom, "%s.example.com", label);
        char h2[512] = {0};
        if (nf_wire_hex_pattern(dom, h2, sizeof h2) < 0) { all_bad[3]++; continue; }
        for (const char *q = h2; *q; q++)
            if (!((*q >= '0' && *q <= '9') || (*q >= 'A' && *q <= 'F'))) all_bad[0]++;
        for (const char *m = marks; *m; m++)
            if (strchr(h2, *m)) all_bad[1]++;
        /* 2 (длина) + 2*len + 16 ("example") + 8 ("com") */
        if ((int)strlen(h2) != 2 * len + 26) all_bad[2]++;
    }
    CHECK(all_bad[0] == 0, "ни одного символа вне 0-9A-F на 63 длинах");
    CHECK(all_bad[1] == 0, "ни одного shell-метасимвола в выводе");
    CHECK(all_bad[2] == 0, "длина hex совпадает с (лейбл+1)*2 на всех длинах");
    CHECK(all_bad[3] == 0, "ни одна длина 1..63 не отвергнута");

    CHECK(nf_wire_hex_pattern("", hex, sizeof hex) < 0, "пустой домен отвергнут");
    CHECK(nf_wire_hex_pattern(NULL, hex, sizeof hex) < 0, "NULL отвергнут");
    CHECK(nf_wire_hex_pattern("discord..com", hex, sizeof hex) < 0, "пустой лейбл отвергнут");
    char tiny[4];
    CHECK(nf_wire_hex_pattern("discord.com", tiny, sizeof tiny) < 0,
          "тесный буфер отвергнут, а не переполнен");
}

// ── 3. разрез SNI (в sni_relay, а не в его копии) ────────────────────────

static void put16(unsigned char *p, unsigned v) { p[0] = (unsigned char)(v >> 8); p[1] = (unsigned char)v; }

static int build_ch(unsigned char *out, int cap, const char *host) {
    unsigned char body[2048];
    int p = 0;
    body[p++] = 0x03; body[p++] = 0x03;
    for (int i = 0; i < 32; i++) body[p++] = (unsigned char)(i * 7 + 3);
    body[p++] = 0x00;
    static const unsigned char cs[] = {
        0x13,0x01, 0x13,0x02, 0x13,0x03, 0xc0,0x2b, 0xc0,0x2f,
        0xc0,0x2c, 0xc0,0x30, 0xc0,0x13, 0xc0,0x14, 0x00,0x9e, 0x00,0x9f };
    put16(body + p, sizeof cs); p += 2;
    memcpy(body + p, cs, sizeof cs); p += (int)sizeof cs;
    body[p++] = 0x01; body[p++] = 0x00;

    int hl = (int)strlen(host);
    unsigned char exts[1024];
    int e = 0;
    int sni_body = 5 + hl;
    put16(exts + e, 0x0000); e += 2;
    put16(exts + e, sni_body); e += 2;
    put16(exts + e, sni_body - 2); e += 2;
    exts[e++] = 0x00;
    put16(exts + e, hl); e += 2;
    memcpy(exts + e, host, (size_t)hl); e += hl;
    put16(exts + e, 0x000a); e += 2;  put16(exts + e, 8); e += 2;
    exts[e++] = 0x00; exts[e++] = 0x1d;
    put16(exts + e, 0x000b); e += 2;  put16(exts + e, 2); e += 2;
    exts[e++] = 0x01; exts[e++] = 0x00;
    put16(body + p, e); p += 2;
    memcpy(body + p, exts, (size_t)e); p += e;

    unsigned char hs[2048];
    hs[0] = 0x01;
    hs[1] = (unsigned char)(p >> 16); hs[2] = (unsigned char)(p >> 8); hs[3] = (unsigned char)p;
    memcpy(hs + 4, body, (size_t)p);
    int hs_len = 4 + p;
    if (hs_len > cap) return -1;
    memcpy(out, hs, (size_t)hs_len);
    return hs_len;
}

static void test_sni_split(void) {
    printf("[TLS] разрез SNI (sni_relay, реальный код реля)\n");
    unsigned char hs[4096];
    int hl = build_ch(hs, (int)sizeof hs, "discord.com");
    CHECK(hl > 46, "ClientHello собран (%d B)", hl);

    int cut = sni_find_split(hs, hl);
    int name_at = -1;
    for (int i = 4; i < hl - 10; i++)
        if (memcmp(hs + i, "discord.com", 11) == 0) { name_at = i; break; }
    CHECK(name_at > 0, "имя найдено в ClientHello @%d", name_at);
    CHECK(cut > name_at && cut < name_at + 11,
          "разрез внутри имени (cut=%d, имя %d..%d)", cut, name_at, name_at + 11);

    unsigned char frag[8192];
    int first_seg = 0;
    int flen = sni_build_fragmented_ch(hs, hl, frag, (int)sizeof frag, &first_seg);
    CHECK(flen > 0, "фрагментированный ClientHello собран (%d B)", flen);
    if (flen > 0) {
        CHECK(frag[0] == 0x16 && frag[1] == 0x03 && frag[2] == 0x01, "заголовок record1");
        int r1_pl = (frag[3] << 8) | frag[4];
        int r1 = 5 + r1_pl;
        CHECK(r1 < flen && frag[r1] == 0x16 && frag[r1 + 1] == 0x03, "заголовок record2 @%d", r1);
        int r2_pl = (frag[r1 + 3] << 8) | frag[r1 + 4];
        CHECK(r1_pl + r2_pl == hl &&
              memcmp(frag + 5, hs, (size_t)r1_pl) == 0 &&
              memcmp(frag + r1 + 5, hs + r1_pl, (size_t)(hl - r1_pl)) == 0,
              "склейка record'ов даёт исходный ClientHello");
        CHECK(first_seg >= 1 && first_seg < r1,
              "первый сегмент (%d) меньше record1 (%d)", first_seg, r1);
        CHECK(cut <= r1, "разрез имени не позже границы record1");
    }

    // Мусор на входе обязан отбиваться, а не читаться за пределами буфера.
    CHECK(sni_find_split(NULL, 100) == -1, "NULL отбит");
    CHECK(sni_find_split(hs, 10) == -1,     "слишком короткий отбит");
    CHECK(sni_find_split(hs, -5) == -1,     "отрицательная длина отбита");
    unsigned char junk[64];
    memset(junk, 0xFF, sizeof junk);
    CHECK(sni_find_split(junk, (int)sizeof junk) == -1, "мусор отбит");
}

// ── 4. конфиг ────────────────────────────────────────────────────────────

static void test_conf(void) {
    printf("[CONF] webui/discord.conf -> переменные модуля\n");
    load_conf();
    // Сверять переменные модуля надо с тем же путём, который он сам ищет.
    // DISCORD_CONF — относительный путь, и из каталога сборки теста он не
    // открывается: conf_int вернул бы дефолт, и проверка врала бы.
    char cpath[1200] = {0};
    discord_conf_path(cpath, sizeof cpath);
    // Ключи, которые раньше читались вхолостую.
    CHECK(opt_no_split_hs  == conf_int(cpath, "no_split_hs", 1),
          "no_split_hs доходит до модуля (%d)", opt_no_split_hs);
    CHECK(opt_split_ch     == conf_int(cpath, "split_ch", 1),
          "split_ch = %d", opt_split_ch);
    CHECK(opt_frag_first_seg >= 1, "frag_first_seg >= 1 (%d)", opt_frag_first_seg);
    CHECK(opt_split_size >= 1,    "split_size >= 1 (%d)", opt_split_size);
    CHECK(opt_relay_chunk >= 0,   "relay_chunk >= 0 (%d)", opt_relay_chunk);
    // -1 = «без пауз», и он обязан доживать до sni_relay. Раньше load_conf
    // обнулял отрицательное значение, и объявленный в sni_relay.h способ
    // отключить паузу был недостижим.
    CHECK(opt_relay_pause_ms == -1 || opt_relay_pause_ms >= 0,
          "relay_pause_ms = %d (-1 = без пауз, 0 = дефолт реля в 1 мс)", opt_relay_pause_ms);
    CHECK(opt_frag_delay_ms >= 0, "frag_delay_ms >= 0 (%d)", opt_frag_delay_ms);
    CHECK(opt_shift_sni == 0 || opt_shift_sni == 1, "shift_sni = %d", opt_shift_sni);
    CHECK(opt_relay_cidr == conf_int(cpath, "relay_cidr", 0),
          "relay_cidr доходит до модуля (%d)", opt_relay_cidr);
    CHECK(opt_probe_pins == conf_int(cpath, "probe_pins", 0),
          "probe_pins доходит до модуля (%d)", opt_probe_pins);
    CHECK(opt_multi_parts == conf_int(cpath, "multi_parts", 2),
          "multi_parts доходит до модуля (%d)", opt_multi_parts);
    CHECK(opt_multi_parts >= 2, "multi_parts >= 2 (%d)", opt_multi_parts);

    // Ключ, которого нет в файле, обязан давать дефолт, а не мусор.
    int d = conf_int("/nonexistent/discord.conf", "split_ch", 7);
    CHECK(d == 7, "conf_int на отсутствующем файле даёт дефолт (%d)", d);

    // Конфиг обязан находиться независимо от рабочего каталога. Раньше путь
    // был относительным, и модуль молча уходил на дефолты при запуске не из
    // корня проекта.
    char conf[1200] = {0};
    discord_conf_path(conf, sizeof conf);
    CHECK(access(conf, R_OK) == 0, "конфиг найден из этого каталога: %s", conf);
    CHECK(strstr(conf, "discord.conf") != NULL, "путь указывает на discord.conf");
    if (getenv("RMF_ROOT")) {
        char probe[1200] = {0};
        setenv("RMF_ROOT", "/nonexistent-root", 1);
        discord_conf_path(probe, sizeof probe);
        setenv("RMF_ROOT", getenv("RMF_ROOT") ? "" : "", 1);
        CHECK(strcmp(probe, conf) != 0,
              "при неверном RMF_ROOT ищем дальше, а не берём мусорный путь");
    }
}

// ── 5. сеть (необязательно) ─────────────────────────────────────────────

static int tcp_reachable(const char *ip, int port, int timeout_s) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct timeval tv = { timeout_s, 0 };
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET; a.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &a.sin_addr) != 1) { close(fd); return -1; }
    int ok = connect(fd, (struct sockaddr *)&a, sizeof a) == 0;
    close(fd);
    return ok ? 0 : -1;
}

static void test_network(void) {
    printf("[NET] сеть (пропускается, если её нет)\n");
    char ip[64] = {0};
    int got = 0;
    const char *dns[] = { "1.1.1.1", "8.8.8.8", NULL };
    for (int i = 0; dns[i] && !got; i++)
        if (dns_resolve_udp(dns[i], "discord.com", ip, sizeof ip) == 0) got = 1;
    if (!got) { INFO("DNS не отвечает — сетевые проверки пропущены"); return; }
    INFO("discord.com -> %s", ip);
    if (!discord_validate_ip(ip))
        INFO("ВНИМАНИЕ: ответ DNS вне наших диапазонов — модуль его отсечёт, "
             "и это может быть подмена");
    else
        INFO("ответ в наших диапазонах, валидатор его пропустит");

    // Раньше здесь стояло CHECK(1, ...). Это тавтология: она не может упасть
    // и ничего не проверяет, но попадала в итоговый счётчик и раздувала его на
    // единицу. Плюс блок условный, и когда сеть была поднята, счётчик давал
    // 88, а когда лежала — 87: число «проверок» зависело от состояния сети.
    // Теперь это честная INFO, а счётчик всегда один и тот же.
    if (tcp_reachable(ip, 443, 3) == 0) {
        INFO("TCP 443 до %s открывается — обход не нужен, можно прямо", ip);
    } else {
        INFO("TCP 443 до %s не открылся — это ожидаемо при блокировке по SNI, "
             "обход делает рель", ip);
    }
}

// ── main ────────────────────────────────────────────────────────────────

int main(void) {
    printf("[DISCORD TEST] ==============================================\n");
    printf("[DISCORD TEST] юнит-проверки модуля discord\n");
    printf("[DISCORD TEST] ==============================================\n");

    discord_config_t cfg = { .primary_dns = "1.1.1.1", .fallback_dns = "8.8.8.8",
                             .relay_port = 19443 };
    discord_module_init(&cfg);

    test_ip_parse();
    test_validate_ip();
    test_dest_scope();
    test_wire_hex();
    test_sni_split();
    test_conf();
    test_network();

    discord_module_cleanup();

    printf("[DISCORD TEST] ==============================================\n");
    printf("[DISCORD TEST] проверок: %d, провалено: %d\n", checks, failures);
    if (failures == 0) printf("[DISCORD TEST] ВСЁ ЗЕЛЁНОЕ\n");
    else printf("[DISCORD TEST] ЕСТЬ ПРОВАЛЫ\n");
    return failures == 0 ? 0 : 1;
}
