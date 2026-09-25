#include "src/modules/discord/include/header.h"
#include "src/dns/dns_resolve.h"
#include "src/dns/doh_resolve.h"
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

static void iptables_add_quic_drop(const char *ip) {
    if (!is_root() || !ip) return;
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "iptables -C OUTPUT -p udp --dport 443 -d %.63s -j DROP 2>/dev/null || "
             "iptables -I OUTPUT -p udp --dport 443 -d %.63s -j DROP",
             ip, ip);
    sh_check(cmd);
}

static void iptables_del_quic_drop(const char *ip) {
    if (!is_root() || !ip) return;
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "iptables -D OUTPUT -p udp --dport 443 -d %.63s -j DROP 2>/dev/null",
             ip);
    sh(cmd);
}

static void iptables_base(void) {
    if (!is_root()) return;
    sh("iptables -t nat -N DISCORD_BYPASS 2>/dev/null || true");
    // Не трогаем помеченные пакеты любого модуля; исключения VRChat добавляются отдельно.
    sh_check("iptables -t nat -C DISCORD_BYPASS -m mark --mark 0x4d50/0xfff0 -j RETURN "
       "2>/dev/null || iptables -t nat -I DISCORD_BYPASS 1 -m mark --mark 0x4d50/0xfff0 -j RETURN");
    sh_check("iptables -t nat -C DISCORD_BYPASS -m mark --mark 0x4d5a -j RETURN "
       "2>/dev/null || iptables -t nat -I DISCORD_BYPASS 2 -m mark --mark 0x4d5a -j RETURN");
    sh("iptables -t nat -D OUTPUT -j DISCORD_BYPASS 2>/dev/null");
    sh_check("iptables -t nat -A OUTPUT -j DISCORD_BYPASS");
    for (int i = 0; discord_pins[i].domain; i++)
        iptables_add_quic_drop(discord_pins[i].pinned_ip);

}

static void iptables_add_vrchat_exceptions(void) {
    if (!is_root()) return;
    static const char *const ips[] = {
        "104.18.26.36", "104.18.6.156", "104.16.241.118",
        "65.9.106.85", "3.174.18.93", "216.198.53.6", NULL
    };

    for (int i = 0; ips[i]; i++) {
        char cmd[512];
        snprintf(cmd, sizeof(cmd),
            "iptables -t nat -C DISCORD_BYPASS -p tcp -d %s --dport 443 -j RETURN 2>/dev/null || "
            "iptables -t nat -I DISCORD_BYPASS 1 -p tcp -d %s --dport 443 -j RETURN",
            ips[i], ips[i]);
        sh(cmd);
    }
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

static void iptables_add_redirect(const char *ip) {
    if (!is_root()) return;
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
        "iptables -t nat -C DISCORD_BYPASS -p tcp -d %.15s --dport 443 "
        "-j REDIRECT --to-ports %d 2>/dev/null || "
        "iptables -t nat -A DISCORD_BYPASS -p tcp -d %.15s --dport 443 "
        "-j REDIRECT --to-ports %d",
        ip, ctx.relay_port, ip, ctx.relay_port);
    sh_check(cmd);
}

static void iptables_add_redirect_range(void) {
    if (!is_root()) return;
    static const char *nets[] = {"162.159.0.0/16", "104.16.0.0/12", "104.18.0.0/16", NULL};
    for (int i = 0; nets[i]; i++) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd),
            "iptables -t nat -C DISCORD_BYPASS -p tcp -d %s --dport 443 "
            "-j REDIRECT --to-ports %d 2>/dev/null || "
            "iptables -t nat -A DISCORD_BYPASS -p tcp -d %s --dport 443 "
            "-j REDIRECT --to-ports %d",
            nets[i], ctx.relay_port, nets[i], ctx.relay_port);
        sh_check(cmd);
    }
}

static void iptables_del_rules(void) {
    if (!is_root()) return;
    for (int i = 0; discord_pins[i].domain; i++)
        iptables_del_quic_drop(discord_pins[i].pinned_ip);
    sh("iptables -D OUTPUT -p udp --dport 443 -d 162.159.0.0/16 -j DROP 2>/dev/null");
    sh("iptables -D OUTPUT -p udp --dport 443 -d 104.16.0.0/12 -j DROP 2>/dev/null");
    sh("iptables -D OUTPUT -p udp --dport 443 -d 104.18.0.0/16 -j DROP 2>/dev/null");
    sh("iptables -D OUTPUT -p tcp -m multiport --dports 443,853 "
       "-d 1.1.1.1,1.0.0.1 -j DROP 2>/dev/null");
    sh("iptables -D OUTPUT -p tcp -m multiport --dports 443,853 "
       "-d 8.8.8.8,8.8.4.4 -j DROP 2>/dev/null");
    sh("iptables -D OUTPUT -p tcp -m multiport --dports 443,853 "
       "-d 9.9.9.9,149.112.112.112 -j DROP 2>/dev/null");
    sh("iptables -t nat -D OUTPUT -j DISCORD_BYPASS 2>/dev/null");
    sh("iptables -t nat -F DISCORD_BYPASS 2>/dev/null");
    sh("iptables -t nat -X DISCORD_BYPASS 2>/dev/null");
}

static void resolve_and_redirect(void) {
    char seen[32][64];
    int nseen = 0;

    for (int i = 0; discord_dns_domains[i]; i++) {
        char ip[64] = {0};
        if (doh_resolve_a(discord_dns_domains[i], ip, sizeof(ip)) != 0 &&
            dns_resolve_udp(ctx.primary, discord_dns_domains[i], ip, sizeof(ip)) != 0)
            dns_resolve_udp(ctx.fallback, discord_dns_domains[i], ip, sizeof(ip));
        if (ip[0]) {
            int dup = 0;
            for (int j = 0; j < nseen; j++) dup |= (strcmp(seen[j], ip) == 0);
            if (!dup && nseen < 32) {
                snprintf(seen[nseen], sizeof(seen[0]), "%s", ip);
                printf("[DISCORD]   %s -> %s\n", discord_dns_domains[i], ip);
                nseen++;
            }
        } else {
            printf("[DISCORD]   %s -> DNS FAIL\n", discord_dns_domains[i]);
        }
    }
    for (int i = 0; discord_pins[i].domain; i++) {
        int dup = 0;
        for (int j = 0; j < nseen; j++) dup |= (strcmp(seen[j], discord_pins[i].pinned_ip) == 0);
        if (!dup && nseen < 32) {
            snprintf(seen[nseen], sizeof(seen[0]), "%s", discord_pins[i].pinned_ip);
            nseen++;
        }
    }
    for (int i = 0; i < nseen; i++) {
        iptables_add_quic_drop(seen[i]);
        iptables_add_redirect(seen[i]);
    }
}

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

    ctx.frag_delay_ms = (config && config->frag_delay_ms > 0) ? config->frag_delay_ms : 30;
    ctx.frag_first_seg = (config && config->frag_first_seg > 0) ? config->frag_first_seg : 20;
    ctx.relay_port = (config && config->relay_port > 0 && config->relay_port <= 65535)
        ? config->relay_port : 18443;
    ctx.relay_pid = -1;
    ctx.socket_fd = -1;
    ctx.mode = 0;

    discord_initialized = true;
    printf("[DISCORD] init: DNS %s / %s, SNI-split relay (delay=%dms first=%dB) relay:%d\n",
           ctx.primary, ctx.fallback, ctx.frag_delay_ms, ctx.frag_first_seg, ctx.relay_port);
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

    printf("[DISCORD] inject: DNS pinning + relay bypass...\n");
    iptables_base();
    iptables_add_vrchat_exceptions();
    for (int i = 0; discord_dns_domains[i]; i++) iptables_add_dns_rule(discord_dns_domains[i]);
    resolve_and_redirect();
    iptables_add_redirect_range();

    if (discord_relay_start(ctx.relay_port) == 0) {
        ctx.mode = 1;
        printf("[DISCORD]   SNI-split relay: 127.0.0.1:%d (pid %d)\n",
               ctx.relay_port, discord_get_ctx()->relay_pid);
    } else {
        fprintf(stderr, "[DISCORD]   relay start FAILED: %s\n", strerror(errno));
        iptables_del_rules();
        ctx.mode = 0;
        return;
    }

    printf("[DISCORD] inject done (%s)\n",
           is_root() ? "iptables + relay active" : "relay only (no root: iptables skipped)");
}

void discord_module_remove(void) {
    if (!discord_initialized) return;
    discord_relay_stop();
    iptables_del_rules();
    ctx.mode = 0;
    printf("[DISCORD] remove done\n");
}

const char *discord_get_status(void) {
    if (!discord_initialized) return "Off";
    if (!ctx.mode) return "Idle";
    return discord_relay_running() ? "Active (SNI-split relay)" : "Active (relay down!)";
}
