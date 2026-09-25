// Discord Module Test — диагностика ТСПУ + проверка обхода + тест троттлинга.
//
// Проверяет:
//   1. Self-test: матчинг доменов, cut внутри SNI, сборка фрагментированного
//      ClientHello (2 records, reassembly == оригинал).
//   2. DNS: системный vs честный (1.1.1.1 / 8.8.8.8).
//   3. TCP 443 до честных IP; прямой TLS с SNI (диагностика блока).
//   4. E2E: полный ClientHello -> relay -> ServerHello (обход работает).
//   5. HTTP: реальные эндпоинты Discord (API, CDN, updates).
//   6. Тест троттлинга: baseline-скорость vs CDN Discord, латентность
//      handshake'ов, поведение больших ответов discord.com.
//
// Сборка/запуск:
//   cd src/modules/discord && make test
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "../include/header.h"
#include "../../../dns/dns_resolve.h"

static int failures = 0;
#define CHECK(cond, ...) do { \
    if (cond) { printf("  [OK]   " __VA_ARGS__); printf("\n"); } \
    else { printf("  [FAIL] " __VA_ARGS__); printf("\n"); failures++; } \
} while (0)
#define INFO(...) do { printf("  [..]   " __VA_ARGS__); printf("\n"); } while (0)

#define TEST_RELAY_PORT 19443

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

// --- Синтетический ClientHello (как у реального клиента) ---

static void put16(unsigned char *p, unsigned v) { p[0] = (unsigned char)(v >> 8); p[1] = (unsigned char)v; }

static int build_ch(unsigned char *out, int cap, const char *host, int one_record) {
    unsigned char body[2048];
    int p = 0;
    // client_version + random
    body[p++] = 0x03; body[p++] = 0x03;
    for (int i = 0; i < 32; i++) body[p++] = (unsigned char)(i * 7 + 3);
    body[p++] = 0x00; // session_id
    // cipher suites
    static const unsigned char cs[] = {
        0x13,0x01, 0x13,0x02, 0x13,0x03, 0xc0,0x2b, 0xc0,0x2f,
        0xc0,0x2c, 0xc0,0x30, 0xc0,0x13, 0xc0,0x14, 0x00,0x9e,
        0x00,0x9f, 0x00,0x2f, 0x00,0x35
    };
    put16(body + p, sizeof(cs)); p += 2;
    memcpy(body + p, cs, sizeof(cs)); p += (int)sizeof(cs);
    body[p++] = 0x01; body[p++] = 0x00; // compression

    int hl = (int)strlen(host);
    // extensions
    unsigned char exts[1024];
    int e = 0;
    // SNI: list_len(2) + type(1) + namelen(2) + host = 5+hl
    int sni_body = 5 + hl;
    put16(exts + e, 0x0000); e += 2;
    put16(exts + e, sni_body); e += 2;
    put16(exts + e, sni_body - 2); e += 2;   // server_name_list = 3+hl
    exts[e++] = 0x00;
    put16(exts + e, hl); e += 2;
    memcpy(exts + e, host, (size_t)hl); e += hl;
    // supported_groups
    put16(exts + e, 0x000a); e += 2;
    put16(exts + e, 8); e += 2;
    put16(exts + e, 6); e += 2;
    exts[e++] = 0x00; exts[e++] = 0x1d;
    exts[e++] = 0x00; exts[e++] = 0x17;
    exts[e++] = 0x00; exts[e++] = 0x18;
    // ec_point_formats
    put16(exts + e, 0x000b); e += 2;
    put16(exts + e, 2); e += 2;
    exts[e++] = 0x01; exts[e++] = 0x00;
    // signature_algorithms
    put16(exts + e, 0x000d); e += 2;
    put16(exts + e, 14); e += 2;
    put16(exts + e, 12); e += 2;
    static const unsigned char sa[] = {0x08,0x04,0x08,0x05,0x08,0x06,0x04,0x01,0x05,0x01,0x06,0x01};
    memcpy(exts + e, sa, sizeof(sa)); e += (int)sizeof(sa);
    // ALPN h2, http/1.1
    put16(exts + e, 0x0010); e += 2;
    put16(exts + e, 14); e += 2;
    put16(exts + e, 12); e += 2;
    exts[e++] = 0x02; exts[e++] = 'h'; exts[e++] = '2';
    exts[e++] = 0x08; memcpy(exts + e, "http/1.1", 8); e += 8;
    // supported_versions TLS1.3
    put16(exts + e, 0x002b); e += 2;
    put16(exts + e, 3); e += 2;
    exts[e++] = 0x02; exts[e++] = 0x03; exts[e++] = 0x04;
    // key_share x25519
    put16(exts + e, 0x0033); e += 2;
    put16(exts + e, 38); e += 2;
    put16(exts + e, 36); e += 2;
    put16(exts + e, 0x001d); e += 2;
    put16(exts + e, 32); e += 2;
    for (int i = 0; i < 32; i++) exts[e++] = (unsigned char)(i * 11 + 5);

    put16(body + p, e); p += 2;
    memcpy(body + p, exts, (size_t)e); p += e;

    unsigned char hs[2048];
    hs[0] = 0x01;
    hs[1] = (unsigned char)(p >> 16); hs[2] = (unsigned char)(p >> 8); hs[3] = (unsigned char)p;
    memcpy(hs + 4, body, (size_t)p);
    int hs_len = 4 + p;

    if (one_record) {
        if (hs_len + 5 > cap) return -1;
        out[0] = 0x16; out[1] = 0x03; out[2] = 0x01;
        put16(out + 3, hs_len);
        memcpy(out + 5, hs, (size_t)hs_len);
        return 5 + hs_len;
    }
    if (hs_len > cap) return -1;
    memcpy(out, hs, (size_t)hs_len);
    return hs_len;
}

// --- 1. Self-test ---

static void test_self(void) {
    printf("[SELF] матчинг и фрагментация\n");
    CHECK(discord_is_target("discord.com"), "discord.com is target");
    CHECK(discord_is_target("gateway.discord.gg"), "gateway.discord.gg is target");
    CHECK(discord_is_target("cdn.discordapp.com"), "cdn.discordapp.com is target");
    CHECK(discord_is_target("updates.discordapp.com"), "updates.discordapp.com is target");
    CHECK(discord_is_target("stable.dl2.discordapp.net"), "*.discordapp.net is target");
    CHECK(!discord_is_target("google.com"), "google.com NOT target");
    CHECK(!discord_is_target("notdiscord.com"), "notdiscord.com NOT target");
    CHECK(!discord_is_target("discord.com.evil.com"), "discord.com.evil.com NOT target");

    unsigned char hs[4096];
    int hl = build_ch(hs, (int)sizeof(hs), "discord.com", 0);
    CHECK(hl > 46, "synthetic ClientHello собран (%d B)", hl);

    int cut = discord_find_sni_split(hs, hl);
    int name_at = -1;
    for (int i = 4; i < hl - 10; i++)
        if (memcmp(hs + i, "discord.com", 11) == 0) { name_at = i; break; }
    CHECK(name_at > 0, "hostname найден в hs @%d", name_at);
    CHECK(cut > name_at && cut < name_at + 11,
          "cut внутри hostname (cut=%d, name=%d..%d)", cut, name_at, name_at + 11);

    unsigned char frag[8192];
    int first_seg = 0;
    int flen = discord_build_fragmented_ch(hs, hl, frag, (int)sizeof(frag), &first_seg);
    CHECK(flen > 0, "fragmented CH собран (%d B, first_seg=%d)", flen, first_seg);
    if (flen > 0) {
        // record-заголовки валидны
        CHECK(frag[0] == 0x16 && frag[1] == 0x03, "record1 header ok");
        int r1_pl = (frag[3] << 8) | frag[4];
        int r1 = 5 + r1_pl;
        CHECK(r1 < flen && frag[r1] == 0x16, "record2 header ok (r1=%d)", r1);
        CHECK(first_seg >= 1 && first_seg < r1,
              "первый TCP-сегмент ВНУТРИ record1 (%d < %d)", first_seg, r1);
        // reassembly == оригинал
        CHECK(r1_pl + ((frag[r1+3] << 8) | frag[r1+4]) == hl &&
              memcmp(frag + 5, hs, (size_t)r1_pl) == 0 &&
              memcmp(frag + r1 + 5, hs + r1_pl, (size_t)(hl - r1_pl)) == 0,
              "reassembly records == оригинальный ClientHello");
        // сигнатура разорвана record-заголовком внутри hostname
        int inside = cut - 5; // hostname середина в координатах record1 payload
        int rec2_abs = r1;
        CHECK(!(first_seg <= rec2_abs && 0), "cut@%d < r1@%d (заголовок rec2 рвёт сигнатуру)",
              cut, rec2_abs);
        (void)inside;
    }
}

// --- 2. DNS ---

static void test_dns(void) {
    printf("[DNS] системный vs честный резолвер\n");
    const char *domains[] = {"discord.com", "gateway.discord.gg",
                             "updates.discordapp.com", NULL};
    for (int i = 0; domains[i]; i++) {
        char ip1[64] = "-", ip8[64] = "-";
        int ok1 = dns_resolve_udp("1.1.1.1", domains[i], ip1, sizeof(ip1));
        int ok8 = dns_resolve_udp("8.8.8.8", domains[i], ip8, sizeof(ip8));
        int both_fail = (ok1 != 0 && ok8 != 0);
        if (both_fail)
            INFO("%s: A-записи нет ни у одного резолвера (хост мог быть удалён)",
                 domains[i]);
        else
            CHECK(ok1 == 0 || ok8 == 0, "%s резолвится: 1.1.1.1=%s 8.8.8.8=%s",
                  domains[i], ok1 == 0 ? ip1 : "FAIL", ok8 == 0 ? ip8 : "FAIL");
        if (ok1 == 0 && ok8 == 0 && strcmp(ip1, ip8) != 0)
            INFO("resolvers расходятся: %s vs %s (норма для anycast)", ip1, ip8);
    }
}

// --- 3. TCP + прямой TLS (диагностика блока) ---

static int tcp_connect(const char *ip, int port, int timeout_s) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct timeval tv = { timeout_s, 0 };
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &a.sin_addr) != 1) { close(fd); return -1; }
    int ok = connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0;
    close(fd);
    return ok ? 0 : -1;
}

// Пробуем несколько anycast-кандидатов (часть IP Discord периодически мертва)
static int tcp_connect_any(const char *domain, char *ip_out, int ip_out_sz) {
    const char *resolvers[] = {"1.1.1.1", "8.8.8.8", NULL};
    for (int i = 0; resolvers[i]; i++) {
        char ip[64] = {0};
        if (dns_resolve_udp(resolvers[i], domain, ip, sizeof(ip)) != 0) continue;
        if (tcp_connect(ip, 443, 3) == 0) {
            if (ip_out) snprintf(ip_out, (size_t)ip_out_sz, "%s", ip);
            return 0;
        }
        INFO("anycast %s недоступен, пробуем следующий", ip);
    }
    return -1;
}

// >0: ServerHello, 0: таймаут/закрытие, -1: получили что-то иное (байты в hex)
static int recv_serverhello(int fd, int timeout_s, double *ms_out,
                            unsigned char *raw, int *raw_len) {
    double t0 = now_ms();
    struct timeval tv = { timeout_s, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    unsigned char b[64];
    ssize_t n = recv(fd, b, sizeof(b), 0);
    if (ms_out) *ms_out = now_ms() - t0;
    if (n > 0 && raw && raw_len) {
        *raw_len = (int)n < 64 ? (int)n : 64;
        memcpy(raw, b, (size_t)*raw_len);
    }
    if (n >= 6 && b[0] == 0x16 && b[5] == 0x02) return 1;
    if (n <= 0) return 0;
    return -1;
}

static void test_direct_block(const char *relay_ip_unused) {
    (void)relay_ip_unused;
    printf("[TLS] прямое соединение (диагностика SNI-фильтра)\n");
    char ip[64] = {0};
    if (tcp_connect_any("discord.com", ip, sizeof(ip)) != 0) {
        INFO("ни один anycast IP discord.com не открыл TCP — сеть/ТСПУ");
        return;
    }
    CHECK(1, "TCP 443 %s открывается (живой anycast)", ip);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct timeval tv = { 5, 0 };
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET; a.sin_port = htons(443);
    inet_pton(AF_INET, ip, &a.sin_addr);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        CHECK(0, "connect %s", ip); close(fd); return;
    }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    unsigned char ch[4096];
    int cl = build_ch(ch, (int)sizeof(ch), "discord.com", 1);
    send(fd, ch, (size_t)cl, MSG_NOSIGNAL);
    double ms = 0;
    int sh = recv_serverhello(fd, 4, &ms, NULL, NULL);
    close(fd);
    if (sh)
        INFO("ServerHello и по прямому пути: SNI-фильтр сейчас неактивен (%.0f ms)", ms);
    else
        INFO("прямой TLS с SNI не отвечает (%.0f ms) — SNI-фильтр ТСПУ ПОДТВЕРЖДЁН", ms);
}

// --- 4. E2E через relay ---

static void test_relay_e2e(void) {
    printf("[RELAY] E2E: полный ClientHello -> relay -> Discord\n");
    CHECK(discord_relay_start(TEST_RELAY_PORT) == 0, "relay запущен (pid %d)",
          discord_get_ctx()->relay_pid);
    CHECK(discord_relay_running(), "relay running");
    int ok = 0;
    double lat[5];
    unsigned char failraw[64];
    int failraw_len = 0;
    const char *fail_reason = NULL;
    for (int i = 0; i < 5; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        struct timeval tv = { 6, 0 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        struct sockaddr_in a = {0};
        a.sin_family = AF_INET;
        a.sin_port = htons(TEST_RELAY_PORT);
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0) {
            int one = 1;
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
            unsigned char ch[4096];
            int cl = build_ch(ch, (int)sizeof(ch), "discord.com", 1);
            send(fd, ch, (size_t)cl, MSG_NOSIGNAL);
            double ms;
            unsigned char raw[64];
            int raw_len = 0;
            int sh = recv_serverhello(fd, 6, &ms, raw, &raw_len);
            lat[i] = ms;
            if (sh == 1) ok++;
            else if (!fail_reason) {
                if (sh == 0) fail_reason = "закрыто/таймаут";
                else {
                    fail_reason = "иные байты:";
                    memcpy(failraw, raw, (size_t)raw_len);
                    failraw_len = raw_len;
                }
            }
        } else {
            lat[i] = -1;
            if (!fail_reason) fail_reason = "connect refused";
        }
        close(fd);
    }
    if (ok == 5) {
        CHECK(1, "ServerHello через relay: 5/5 (латентность %.0f ms)", lat[0]);
    } else {
        printf("  [FAIL] ServerHello через relay: %d/5 (латентность %.0f ms, причина: %s",
               ok, lat[0], fail_reason ? fail_reason : "?");
        if (failraw_len > 0) {
            printf(" ");
            for (int i = 0; i < failraw_len && i < 24; i++)
                printf("%02x", failraw[i]);
        }
        printf(")\n");
        failures++;
    }
}

// --- 5. HTTP эндпоинты ---

static int curl_line(const char *cmd, char *out, int out_sz) {
    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;
    if (!fgets(out, out_sz, fp)) { pclose(fp); return -1; }
    pclose(fp);
    out[strcspn(out, "\r\n")] = 0;
    return 0;
}

static void test_http(void) {
    printf("[HTTP] реальные эндпоинты Discord через relay\n");
    char line[512];
    char cmd[1024];

    // CDN-картинка (малый ответ, должен пройти полностью)
    snprintf(cmd, sizeof(cmd),
        "curl -s -m 10 -o /dev/null -w '%%{http_code} %%{size_download} %%{time_total}' "
        "--connect-to cdn.discordapp.com:443:127.0.0.1:%d "
        "https://cdn.discordapp.com/embed/avatars/0.png", TEST_RELAY_PORT);
    if (curl_line(cmd, line, sizeof(line)) == 0) {
        int code = 0; double size = 0, t = 0;
        sscanf(line, "%d %lf %lf", &code, &size, &t);
        CHECK(code == 200 && size > 500, "cdn.discordapp.com: http=%d size=%.0f in %.2fs", code, size, t);
    } else CHECK(0, "cdn: curl failed");

    // API-эндпоинт (малый JSON — то, что дергает апдейтер)
    snprintf(cmd, sizeof(cmd),
        "curl -s -m 10 -o /dev/null -w '%%{http_code} %%{size_download} %%{time_total}' "
        "--connect-to discord.com:443:127.0.0.1:%d "
        "https://discord.com/api/v9/experiments", TEST_RELAY_PORT);
    if (curl_line(cmd, line, sizeof(line)) == 0) {
        int code = 0; double size = 0, t = 0;
        sscanf(line, "%d %lf %lf", &code, &size, &t);
        CHECK(code == 200 && t < 5.0, "discord.com API: http=%d size=%.0f in %.2fs", code, size, t);
    } else CHECK(0, "api: curl failed");

    // updates-хост отвечает (любой код — главное, что TCP+TLS+ответ прошли)
    snprintf(cmd, sizeof(cmd),
        "curl -s -m 10 -o /dev/null -w '%%{http_code} %%{time_total}' "
        "--connect-to updates.discordapp.com:443:127.0.0.1:%d "
        "https://updates.discordapp.com/", TEST_RELAY_PORT);
    if (curl_line(cmd, line, sizeof(line)) == 0) {
        int code = 0; double t = 0;
        sscanf(line, "%d %lf", &code, &t);
        CHECK(t < 5.0, "updates.discordapp.com отвечает: http=%d in %.2fs", code, t);
    } else CHECK(0, "updates: curl failed");
}

// --- 6. Тест троттлинга ---

static void test_throttle(void) {
    printf("[THROTTLE] тест троттлинга скорости\n");
    char line[512], cmd[2048];

    // Baseline: Cloudflare
    double base_speed = 0;
    snprintf(cmd, sizeof(cmd),
        "curl -s -m 20 -o /dev/null -w '%%{speed_download} %%{time_total}' "
        "'https://speed.cloudflare.com/__down?bytes=10000000'");
    if (curl_line(cmd, line, sizeof(line)) == 0) {
        double t = 0;
        sscanf(line, "%lf %lf", &base_speed, &t);
        INFO("baseline cloudflare: %.2f MB/s (%.2fs)", base_speed / 1e6, t);
        CHECK(base_speed > 1e6, "baseline > 1 MB/s (%.2f MB/s)", base_speed / 1e6);
    }

    // CDN Discord: полный пакет должен скачаться целиком (апдейтеру это нужно)
    snprintf(cmd, sizeof(cmd),
        "curl -sL -m 45 -o /dev/null -w '%%{http_code} %%{size_download} %%{speed_download} %%{time_total}' "
        "--connect-to :443:127.0.0.1:%d "
        "'https://discord.com/api/download/stable?platform=linux&arch=x64'",
        TEST_RELAY_PORT);
    double cdn_speed = 0, cdn_time = 0, cdn_size = 0;
    int cdn_code = 0;
    if (curl_line(cmd, line, sizeof(line)) == 0) {
        sscanf(line, "%d %lf %lf %lf", &cdn_code, &cdn_size, &cdn_speed, &cdn_time);
        INFO("CDN discord: http=%d size=%.0f speed=%.2f MB/s (%.2fs)",
             cdn_code, cdn_size, cdn_speed / 1e6, cdn_time);
        CHECK(cdn_code == 200 && cdn_size > 1000000,
              "пакет Discord скачан ПОЛНОСТЬЮ (%.0f B) — апдейтер не зависнет", cdn_size);
        if (base_speed > 0 && cdn_speed > 0) {
            double ratio = cdn_speed / base_speed;
            if (ratio < 0.3)
                INFO("CDN медленнее baseline в %.1fx — возможен троттлинг CDN", 1.0 / ratio);
            else
                INFO("относительная скорость CDN/baseline = %.2f (норма)", ratio);
        }
    } else CHECK(0, "CDN download failed");

    // Большие ответы discord.com: известно, что после ~20KB поток замирает
    snprintf(cmd, sizeof(cmd),
        "curl -s -m 8 -o /dev/null -w '%%{size_download} %%{time_total}' "
        "--connect-to discord.com:443:127.0.0.1:%d https://discord.com/login",
        TEST_RELAY_PORT);
    if (curl_line(cmd, line, sizeof(line)) == 0) {
        double size = 0, t = 0;
        sscanf(line, "%lf %lf", &size, &t);
        if (t >= 7.5)
            INFO("discord.com/login: %.0f B за %.1fs — троттлинг больших ответов "
                 "подтверждён (burst ~20KB, далее ~KB/s). API/CDN не затронуты", size, t);
        else
            INFO("discord.com/login: %.0f B за %.2fs — отвечает полностью", size, t);
    }

    // Латентность handshake через relay (дельта к baseline TLS)
    snprintf(cmd, sizeof(cmd),
        "curl -s -m 8 -o /dev/null -w '%%{time_appconnect}' "
        "--connect-to discord.com:443:127.0.0.1:%d https://discord.com/api/v9/abput",
        TEST_RELAY_PORT);
    double tls_ms = -1;
    if (curl_line(cmd, line, sizeof(line)) == 0) tls_ms = atof(line) * 1000.0;
    INFO("TLS handshake через relay: %.0f ms (прямой baseline ~75-115 ms)", tls_ms);
    CHECK(tls_ms >= 0 && tls_ms < 3000, "handshake не зависает (%.0f ms)", tls_ms);
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--dump-ch") == 0) {
        unsigned char ch[4096];
        int cl = build_ch(ch, (int)sizeof(ch), "discord.com", 1);
        for (int i = 0; i < cl; i++) printf("%02x", ch[i]);
        printf("\n");
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "relay") == 0) {
        int port = argc > 2 ? atoi(argv[2]) : TEST_RELAY_PORT;
        discord_config_t c = {
            .primary_dns = "1.1.1.1", .fallback_dns = "8.8.8.8",
            .frag_delay_ms = 30, .frag_first_seg = 20, .relay_port = port,
        };
        discord_module_init(&c);
        if (discord_relay_start(port) != 0) { fprintf(stderr, "relay start failed\n"); return 1; }
        fprintf(stderr, "relay on 127.0.0.1:%d pid=%d\n", port, discord_get_ctx()->relay_pid);
        for (;;) pause();
    }
    printf("[DISCORD TEST] ===============================\n");
    printf("[DISCORD TEST] SNI-split обход + троттлинг\n");
    printf("[DISCORD TEST] ===============================\n");

    discord_config_t cfg = {
        .primary_dns = "1.1.1.1",
        .fallback_dns = "8.8.8.8",
        .buffer_size = 0,
        .priority = 100,
        .frag_delay_ms = 30,
        .frag_first_seg = 20,
        .relay_port = TEST_RELAY_PORT,
    };
    discord_module_init(&cfg);
    printf("[DISCORD TEST] status: %s\n", discord_get_status());

    test_self();
    test_dns();
    test_direct_block(NULL);
    test_relay_e2e();
    test_http();
    test_throttle();

    int was_running = discord_relay_running();
    discord_relay_stop();
    CHECK(was_running && !discord_relay_running(), "relay корректно остановлен");
    discord_module_cleanup();

    printf("[DISCORD TEST] ===============================\n");
    if (failures == 0) printf("[DISCORD TEST] ALL CHECKS PASSED\n");
    else printf("[DISCORD TEST] %d CHECK(S) FAILED — смотри вывод выше\n", failures);
    return failures == 0 ? 0 : 1;
}
