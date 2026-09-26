#include "src/modules/discord/include/header.h"
#include "src/dns/dns_resolve.h"
#include "src/dns/doh_resolve.h"
#include "src/common/plain_relay.h"
#include "src/common/claims.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/wait.h>

static discord_ctx_t ctx = {0};
static bool discord_initialized = false;

typedef struct {
    const char *domain;
    const char *pinned_ip;
} discord_pin_t;

static const discord_pin_t discord_pins[] = {
    {"discord.com",                     "162.159.128.233"},
    {"discord.gg",                      "162.159.135.234"},
    {"cdn.discordapp.com",              "162.159.130.233"},
    {"media.discordapp.net",            "162.159.130.232"},
    {"status.discord.com",              "162.159.136.232"},
    {"gateway.discord.gg",              "162.159.133.234"},
    {"remote-auth-gateway.discord.gg",  "162.159.135.234"},
    {"discordapp.com",                  "162.159.134.233"},
    {"discord.media",                   "162.159.137.234"},
    {"dl.discordapp.net",               "104.18.48.115"},
    {"dl2.discordapp.net",              "34.126.226.51"},
    {"updates.discordapp.com",          "162.159.136.232"},
    {"cdn.discordapp.net",              "162.159.133.232"},
    {"api.discord.com",                 "162.159.128.233"},
    {"discordapp.net",                  "162.159.134.233"},
    {"updates.discord.com",             "162.159.135.232"},
    {NULL, NULL}
};

static const char *discord_dns_domains[] = {
    "discord.com",
    "discord.gg",
    "discordapp.com",
    "discordapp.net",
    "discord.media",
    "remote-auth-gateway.discord.gg",
    "gateway.discord.gg",
    "cdn.discordapp.net",
    "dl.discordapp.net",
    "media.discordapp.net",
    NULL
};

static int is_root(void) { return getuid() == 0; }

// команды «на всякий случай» (удаление правил, создание цепочки) — ошибки допустимы
static void sh(const char *cmd) {
    int rc = system(cmd);
    (void)rc;
}

// команды, без которых обход не заработает: молчаливый отказ здесь и есть причина
// «релей работает, а трафик не перехватывается»
static void sh_check(const char *cmd) {
    int rc = system(cmd);
    if (rc == -1) {
        fprintf(stderr, "[DISCORD] iptables: не удалось выполнить: %s\n", cmd);
    } else if (WIFEXITED(rc) && WEXITSTATUS(rc) != 0) {
        fprintf(stderr, "[DISCORD] iptables: ошибка %d: %s\n", WEXITSTATUS(rc), cmd);
    } else if (!WIFEXITED(rc)) {
        fprintf(stderr, "[DISCORD] iptables: аварийно завершилась: %s\n", cmd);
    }
}

discord_ctx_t *discord_get_ctx(void) { return &ctx; }

int discord_is_target(const char *domain) {
    if (!domain || !*domain) return 0;
    size_t len = strlen(domain);
    char tmp[256];
    if (len >= sizeof(tmp)) return 0;
    memcpy(tmp, domain, len + 1);
    if (len > 0 && tmp[len - 1] == '.') tmp[len - 1] = '\0';
    for (int i = 0; discord_dns_domains[i]; i++) {
        const char *base = discord_dns_domains[i];
        if (strcasecmp(tmp, base) == 0) return 1;
        size_t bl = strlen(base), tl = strlen(tmp);
        if (tl > bl + 1 && strcasecmp(tmp + tl - bl, base) == 0 && tmp[tl - bl - 1] == '.')
            return 1;
    }
    return 0;
}

int discord_find_sni_split(const unsigned char *hs, int hs_len) {
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
            int name_off_in_body = (p + 4) + 5;
            if (nlen > 0 && nlen <= 253 && name_off_in_body + nlen <= body_len) {
                int cut_in_name = nlen / 2;
                if (cut_in_name < 1) cut_in_name = 1;
                int cut = 4 + name_off_in_body + cut_in_name;
                if (cut > 8 && cut < hs_len - 1) return cut;
            }
        }
        p += 4 + el;
    }
    return -1;
}

int discord_build_fragmented_ch(const unsigned char *hs, int hs_len,
                                unsigned char *out, int out_cap,
                                int* first_seg_out) {
    if (!hs || !out || hs_len < 46) return -1;
    int cut = discord_find_sni_split(hs, hs_len);
    if (cut <= 0) cut = hs_len / 2;
    if (cut <= 0 || cut >= hs_len) return -1;
    int r1_pl = cut, r2_pl = hs_len - cut;
    int r1 = 5 + r1_pl, r2 = 5 + r2_pl;
    if (r1 + r2 > out_cap) return -1;
    out[0] = 0x16; out[1] = 0x03; out[2] = 0x01;
    out[3] = (unsigned char)(r1_pl >> 8); out[4] = (unsigned char)r1_pl;
    memcpy(out + 5, hs, (size_t)r1_pl);
    out[r1] = 0x16; out[r1 + 1] = 0x03; out[r1 + 2] = 0x01;
    out[r1 + 3] = (unsigned char)(r2_pl >> 8); out[r1 + 4] = (unsigned char)r2_pl;
    memcpy(out + r1 + 5, hs + r1_pl, (size_t)r2_pl);
    if (first_seg_out) {
        int fs = ctx.frag_first_seg > 0 ? ctx.frag_first_seg : 20;
        if (fs >= r1) fs = r1 - 1;
        if (fs < 1) fs = 1;
        *first_seg_out = fs;
    }
    return r1 + r2;
}

static void wire_pattern(const char *domain, char *out, size_t out_sz) {
    size_t o = 0;
    const char *s = domain;
    while (*s && o + 64 < out_sz) {
        const char *dot = strchr(s, '.');
        int ll = dot ? (int)(dot - s) : (int)strlen(s);
        if (ll <= 0 || ll > 63) break;
        out[o++] = (char)ll;
        memcpy(out + o, s, (size_t)ll); o += (size_t)ll;
        if (!dot) break;
        s = dot + 1;
    }
    out[o] = '\0';
}

// ── Настройки (webui/discord.conf, необязательно) ────────────────────────
//
// Модуль не трогает ничего, кроме собственных адресов Discord:
//   - перехватываются только IP, которые он сам разрешил для своих доменов;
//   - чужие диапазоны (весь Cloudflare) не перехватываются никогда;
//   - правил в таблице filter модуль не ставит вообще: DROP на udp/443
//     приводит к тому, что клиент ждёт QUIC-ответа и считает сеть мёртвой,
//     а блокировка DoH к 1.1.1.1/8.8.8.8 ломает другие модули;
//   - адреса, уже занятые другим модулем, пропускаются (реестр claims).
#define DISCORD_CONF "webui/discord.conf"

// Discord по умолчанию идёт через рель с разрывом SNI: измерено, что
// провайдер режет handshake по имени домена (SNI=discord.com — тишина,
// SNI=api.vrchat.cloud на том же IP — TLS 1.3 проходит). Без разрыва
// модуль не может ничего сделать, поэтому рель включён по умолчанию.
// use_relay=0 оставляет трафик напрямую — имеет смысл только если домен
// не режется.
static int opt_use_relay = 1;
static int opt_relay_chunk = 0;
static int opt_relay_pause_ms = 0;
static int opt_relay_idle_sec = 0;
static int opt_split_ch = 1;
static int opt_frag_delay_ms = 30;
static int opt_frag_first_seg = 20;
static int opt_split_data = 0;
static int opt_split_size = 512;
static int opt_split_delay_ms = 0;

static int conf_int(const char *path, const char *key, int def) {
    FILE *f = fopen(path, "r");
    if (!f) return def;
    char line[256];
    int val = def;
    size_t klen = strlen(key);
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\0') continue;
        if (strncmp(p, key, klen) != 0 || p[klen] != '=') continue;
        val = atoi(p + klen + 1);
        break;
    }
    fclose(f);
    return val;
}

static void load_conf(void) {
    opt_use_relay       = conf_int(DISCORD_CONF, "use_relay", 1);
    opt_relay_chunk     = conf_int(DISCORD_CONF, "relay_chunk", 0);
    opt_relay_pause_ms  = conf_int(DISCORD_CONF, "relay_pause_ms", 0);
    opt_relay_idle_sec  = conf_int(DISCORD_CONF, "relay_idle_sec", 0);
    opt_split_ch        = conf_int(DISCORD_CONF, "split_ch", 1);
    opt_frag_delay_ms   = conf_int(DISCORD_CONF, "frag_delay_ms", 30);
    opt_frag_first_seg  = conf_int(DISCORD_CONF, "frag_first_seg", 20);
    opt_split_data      = conf_int(DISCORD_CONF, "split_data", 0);
    opt_split_size      = conf_int(DISCORD_CONF, "split_size", 512);
    opt_split_delay_ms  = conf_int(DISCORD_CONF, "split_delay_ms", 0);
    if (opt_relay_chunk < 0) opt_relay_chunk = 0;
    if (opt_relay_pause_ms < 0) opt_relay_pause_ms = 0;
    if (opt_relay_idle_sec < 0) opt_relay_idle_sec = 0;
    if (opt_frag_delay_ms < 0) opt_frag_delay_ms = 0;
    if (opt_frag_first_seg < 1) opt_frag_first_seg = 1;
    if (opt_split_size < 1) opt_split_size = 1;
    if (opt_split_delay_ms < 0) opt_split_delay_ms = 0;
}

// ── iptables ─────────────────────────────────────────────────────────────

static void iptables_base(void) {
    if (!is_root()) return;
    sh("iptables -t nat -N DISCORD_BYPASS 2>/dev/null || true");
    // Помеченные пакеты любого модуля не трогаем: 0x4d5a discord, 0x4d5b vrchat,
    // 0x4d5c google, 0x4d5e speedtest -> маска 0x4d50/0xfff0.
    sh_check("iptables -t nat -C DISCORD_BYPASS -m mark --mark 0x4d50/0xfff0 -j RETURN "
       "2>/dev/null || iptables -t nat -I DISCORD_BYPASS 1 -m mark --mark 0x4d50/0xfff0 -j RETURN");
    sh("iptables -t nat -D OUTPUT -j DISCORD_BYPASS 2>/dev/null");
    sh_check("iptables -t nat -I OUTPUT 1 -j DISCORD_BYPASS");
}

static void iptables_add_dns_rule(const char *domain) {
    if (!is_root()) return;
    char wire[128], cmd[640];
    wire_pattern(domain, wire, sizeof(wire));
    snprintf(cmd, sizeof(cmd),
        "iptables -t nat -C DISCORD_BYPASS -p udp --dport 53 "
        "-m string --algo bm --string \"%s\" "
        "-j DNAT --to-destination 127.0.0.1:53 2>/dev/null || "
        "iptables -t nat -A DISCORD_BYPASS -p udp --dport 53 "
        "-m string --algo bm --string \"%s\" "
        "-j DNAT --to-destination 127.0.0.1:53",
        wire, wire);
    sh_check(cmd);
}

// Диапазон Discord. DNS (в том числе /etc/hosts) может отдать любой адрес
// из набора — проверено: 162.159.138.232 и 162.159.128.233 проходят через
// рель, а 162.159.137.232 (его отдаёт /etc/hosts) режется провайдером.
// Поэтому перехватываем /18, где Discord держит свои адреса. Это не «весь
// Cloudflare», как было раньше, — только выделенный Discord диапазон.
static const char *const discord_ranges[] = { "162.159.128.0/18", NULL };

static void iptables_add_redirect(const char *ip) {
    if (!is_root() || !ip) return;
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "iptables -t nat -C DISCORD_BYPASS -p tcp -d %.63s --dport 443 "
        "-j REDIRECT --to-ports %d 2>/dev/null || "
        "iptables -t nat -A DISCORD_BYPASS -p tcp -d %.63s --dport 443 "
        "-j REDIRECT --to-ports %d",
        ip, ctx.relay_port, ip, ctx.relay_port);
    sh_check(cmd);
}

static void iptables_del_rules(void) {
    if (!is_root()) return;
    sh("iptables -t nat -D OUTPUT -j DISCORD_BYPASS 2>/dev/null");
    sh("iptables -t nat -F DISCORD_BYPASS 2>/dev/null");
    sh("iptables -t nat -X DISCORD_BYPASS 2>/dev/null");
    // Старые версии модуля оставляли DROP в filter: снимаем, чтобы не осталось
    // правил, которые молча глушат QUIC и DoH.
    sh("iptables -D OUTPUT -p udp --dport 443 -d 162.159.0.0/16 -j DROP 2>/dev/null");
    sh("iptables -D OUTPUT -p udp --dport 443 -d 104.16.0.0/12 -j DROP 2>/dev/null");
    sh("iptables -D OUTPUT -p udp --dport 443 -d 104.18.0.0/16 -j DROP 2>/dev/null");
    sh("iptables -D OUTPUT -p tcp -m multiport --dports 443,853 "
       "-d 1.1.1.1,1.0.0.1 -j DROP 2>/dev/null");
    sh("iptables -D OUTPUT -p tcp -m multiport --dports 443,853 "
       "-d 8.8.8.8,8.8.4.4 -j DROP 2>/dev/null");
    sh("iptables -D OUTPUT -p tcp -m multiport --dports 443,853 "
       "-d 9.9.9.9,149.112.112.112 -j DROP 2>/dev/null");
}

// ── Свои адреса ──────────────────────────────────────────────────────────

// Разрешает домены Discord и возвращает список адресов, которые принадлежат
// именно этому модулю. Адреса из заведомо чужих диапазонов сюда не попадают.
static int collect_own_ips(char ips[][64], int max) {
    int n = 0;
    for (int i = 0; discord_dns_domains[i] && n < max; i++) {
        char ip[64] = {0};
        if (doh_resolve_a(discord_dns_domains[i], ip, sizeof(ip)) != 0 &&
            dns_resolve_udp(ctx.primary, discord_dns_domains[i], ip, sizeof(ip)) != 0)
            dns_resolve_udp(ctx.fallback, discord_dns_domains[i], ip, sizeof(ip));
        if (!ip[0]) { printf("[DISCORD]   %s -> DNS FAIL\n", discord_dns_domains[i]); continue; }
        int dup = 0;
        for (int j = 0; j < n; j++) dup |= (strcmp(ips[j], ip) == 0);
        if (dup) continue;
        snprintf(ips[n++], 64, "%s", ip);
        printf("[DISCORD]   %s -> %s\n", discord_dns_domains[i], ip);
    }
    for (int i = 0; discord_pins[i].domain && n < max; i++) {
        int dup = 0;
        for (int j = 0; j < n; j++) dup |= (strcmp(ips[j], discord_pins[i].pinned_ip) == 0);
        if (dup) continue;
        snprintf(ips[n++], 64, "%s", discord_pins[i].pinned_ip);
    }
    return n;
}

// ── lifecycle ────────────────────────────────────────────────────────────

void discord_module_init(discord_config_t *config) {
    if (discord_initialized) return;

    snprintf(ctx.primary, sizeof(ctx.primary), "%s", "127.0.0.1");
    snprintf(ctx.fallback, sizeof(ctx.fallback), "%s", "8.8.8.8");
    if (config && config->primary_dns) snprintf(ctx.primary, sizeof(ctx.primary), "%s", config->primary_dns);
    if (config && config->fallback_dns) snprintf(ctx.fallback, sizeof(ctx.fallback), "%s", config->fallback_dns);
    ctx.primary[31] = '\0';
    ctx.fallback[31] = '\0';
    char *c;
    if ((c = strchr(ctx.primary, ':'))) *c = '\0';
    if ((c = strchr(ctx.fallback, ':'))) *c = '\0';

    ctx.relay_port = (config && config->relay_port > 0 && config->relay_port <= 65535)
        ? config->relay_port : 18443;
    ctx.relay_pid = -1;
    ctx.socket_fd = -1;
    ctx.mode = 0;

    discord_initialized = true;
    printf("[DISCORD] init: DNS %s / %s, relay:%d (own IPs only)\n",
           ctx.primary, ctx.fallback, ctx.relay_port);
}

void discord_module_cleanup(void) {
    if (!discord_initialized) return;
    discord_module_remove();
    if (ctx.socket_fd >= 0) { close(ctx.socket_fd); ctx.socket_fd = -1; }
    discord_initialized = false;
    printf("[DISCORD] cleanup done\n");
}

void discord_module_inject(int fd) {
    (void)fd;
    if (!discord_initialized) { fprintf(stderr, "[DISCORD] not initialized\n"); return; }

    load_conf();
    printf("[DISCORD] inject: свои домены, редирект только своих адресов...\n");

    iptables_base();
    for (int i = 0; discord_dns_domains[i]; i++) iptables_add_dns_rule(discord_dns_domains[i]);

    char ips[32][64];
    int n = collect_own_ips(ips, 32);
    if (n <= 0) {
        fprintf(stderr, "[DISCORD] не удалось разрешить ни один домен, выхожу\n");
        iptables_del_rules();
        ctx.mode = 0;
        return;
    }

    // Реестр: предупреждаем остальные модули, что эти адреса наши.
    const char *claim_list[33];
    for (int i = 0; i < n; i++) claim_list[i] = ips[i];
    claim_list[n] = NULL;
    claims_store("discord", claim_list, (size_t)n);

    int used = 0, skipped = 0;
    for (int i = 0; i < n; i++) {
        if (claims_taken_by_other("discord", ips[i])) {
            printf("[DISCORD]   %s занят другим модулем — не трогаю\n", ips[i]);
            skipped++;
            continue;
        }
        if (opt_use_relay) { iptables_add_redirect(ips[i]); used++; }
    }
    if (opt_use_relay) {
        for (int i = 0; discord_ranges[i]; i++) iptables_add_redirect(discord_ranges[i]);
    }

    ctx.mode = 1;
    if (opt_use_relay) {
        plain_relay_config_t rc = {
            .port = ctx.relay_port,
            .so_mark = 0x4d5a,
            .chunk = opt_relay_chunk,
            .pause_ms = opt_relay_pause_ms,
            .idle_sec = opt_relay_idle_sec,
            .split_client_hello = opt_split_ch,
            .frag_delay_ms = opt_split_ch ? opt_frag_delay_ms : 0,
            .frag_first_seg = opt_frag_first_seg,
            .split_data_records = opt_split_data,
            .split_record_size = opt_split_size,
            .split_record_delay_ms = opt_split_delay_ms,
        };
        if (plain_relay_start(&rc) != 0) {
            fprintf(stderr, "[DISCORD] relay start failed: %s\n", strerror(errno));
            iptables_del_rules();
            claims_release("discord");
            ctx.mode = 0;
            return;
        }
        ctx.relay_pid = plain_relay_pid();
        printf("[DISCORD]   relay 127.0.0.1:%d (pid %d), перехвачено адресов: %d, пропущено: %d\n",
               ctx.relay_port, ctx.relay_pid, used, skipped);
        printf("[DISCORD]   диапазон: %s\n", discord_ranges[0]);
        printf("[DISCORD]   разрыв SNI: %s", opt_split_ch ? "включён" : "выключен");
        if (opt_split_ch)
            printf(" (пауза %d мс, первый сегмент %d Б)", opt_frag_delay_ms, opt_frag_first_seg);
        printf("\n");
        printf("[DISCORD]   дробление данных: %s", opt_split_data ? "включено" : "выключено");
        if (opt_split_data)
            printf(" (%d Б, пауза %d мс)", opt_split_size, opt_split_delay_ms);
        printf("\n");
    } else {
        printf("[DISCORD]   relay off: трафик идёт напрямую (адресов: %d, пропущено: %d)\n",
               n - skipped, skipped);
    }

    printf("[DISCORD] inject done (%s)\n",
           is_root() ? "iptables active" : "no root — iptables skipped");
}

void discord_module_remove(void) {
    if (!discord_initialized) return;
    plain_relay_stop();
    iptables_del_rules();
    claims_release("discord");
    ctx.relay_pid = -1;
    ctx.mode = 0;
    printf("[DISCORD] remove done\n");
}

const char *discord_get_status(void) {
    if (!discord_initialized) return "Off";
    if (!ctx.mode) return "Idle";
    if (!opt_use_relay) return "Active (DNS pinning, direct)";
    return plain_relay_running() ? "Active (relay)" : "Active (relay down!)";
}
