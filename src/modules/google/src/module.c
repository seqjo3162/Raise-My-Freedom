#include "src/modules/google/include/header.h"
#include "src/dns/dns_resolve.h"
#include "src/dns/doh_resolve.h"
#include "src/common/sni_relay.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <stdlib.h>

// Google/YouTube module: DoH DNS pins + SNI-split relay (record fragmentation).
//
// Diagnosis:
//   - Plain DNS for youtube.com / www.youtube.com is poisoned (NXDOMAIN or fake IPs)
//     even toward 1.1.1.1/8.8.8.8. DoH works.
//   - TLS handshake with SNI www.youtube.com times out; without SNI it succeeds
//     => DPI cuts on SNI. Record-fragmentation (2 TLS records, cut mid-hostname,
//     first TCP segment inside record1) defeats it — verified E2E.
//   - Old iptables rules (string match on ASCII domain, DNAT :5353) were dead.

static google_ctx_t ctx = {0};
static bool google_initialized = false;

typedef struct {
    const char *domain;
    const char *ip;
} pin_t;

// Pins from DoH (stable anycast/edge ranges; refreshed at inject via DoH too)
static const pin_t youtube_pins[] = {
    {"www.youtube.com",  "142.251.154.4"},
    {"youtube.com",      "142.251.154.4"},
    {"m.youtube.com",    "142.251.154.4"},
    {"youtu.be",         "142.251.154.4"},
    {"ytimg.com",        "142.251.154.4"},
    {"i.ytimg.com",      "142.251.154.4"},
    {"s.ytimg.com",      "142.251.154.4"},
    {"googlevideo.com",  "142.251.38.68"},
    {"yt3.ggpht.com",    "142.251.154.4"},
    {"fonts.googleapis.com", "142.251.154.4"},
    {NULL, NULL}
};

static const char *google_dns_domains[] = {
    "www.youtube.com", "youtube.com", "m.youtube.com", "youtu.be",
    "ytimg.com", "i.ytimg.com", "s.ytimg.com",
    "googlevideo.com", "yt3.ggpht.com",
    "google.com", "www.google.com",
    NULL
};

// Relay port — must not clash with discord (18443) or mDNS 5353
#define GOOGLE_RELAY_PORT 18445
#define GOOGLE_SO_MARK    0x4d5c

static int is_root(void) { return getuid() == 0; }

static void sh(const char *cmd) {
    int rc = system(cmd);
    (void)rc;
}

google_ctx_t *google_get_ctx(void) { return &ctx; }

int google_is_target(const char *domain) {
    if (!domain || !*domain) return 0;
    size_t len = strlen(domain);
    char tmp[256];
    if (len >= sizeof(tmp)) return 0;
    memcpy(tmp, domain, len + 1);
    if (len > 0 && tmp[len - 1] == '.') tmp[len - 1] = '\0';

    for (int i = 0; google_dns_domains[i]; i++) {
        const char *base = google_dns_domains[i];
        if (strcasecmp(tmp, base) == 0) return 1;
        size_t bl = strlen(base), tl = strlen(tmp);
        if (tl > bl + 1 && strcasecmp(tmp + tl - bl, base) == 0 &&
            tmp[tl - bl - 1] == '.')
            return 1;
    }
    return 0;
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
        s += ll + 1;
    }
    out[o] = '\0';
}

static void iptables_base(void) {
    if (!is_root()) return;
    sh("iptables -t nat -N GOOGLE_YT_BYPASS 2>/dev/null || true");
    sh("iptables -t nat -C GOOGLE_YT_BYPASS -m mark --mark 0x4d50/0xfff0 -j RETURN "
       "2>/dev/null || iptables -t nat -I GOOGLE_YT_BYPASS 1 -m mark --mark 0x4d50/0xfff0 -j RETURN");
    sh("iptables -t nat -C GOOGLE_YT_BYPASS -m mark --mark 0x4d5c -j RETURN "
       "2>/dev/null || iptables -t nat -I GOOGLE_YT_BYPASS 2 -m mark --mark 0x4d5c -j RETURN");
    // Force TCP for YouTube (drop QUIC) so SNI-split applies
    sh("iptables -C OUTPUT -p udp --dport 443 -d 142.251.0.0/16 -j DROP 2>/dev/null || "
       "iptables -I OUTPUT -p udp --dport 443 -d 142.251.0.0/16 -j DROP");
    sh("iptables -C OUTPUT -p udp --dport 443 -d 172.217.0.0/16 -j DROP 2>/dev/null || "
       "iptables -I OUTPUT -p udp --dport 443 -d 172.217.0.0/16 -j DROP");
    sh("iptables -C OUTPUT -p udp --dport 443 -d 216.239.0.0/16 -j DROP 2>/dev/null || "
       "iptables -I OUTPUT -p udp --dport 443 -d 216.239.0.0/16 -j DROP");
    sh("iptables -t nat -D OUTPUT -j GOOGLE_YT_BYPASS 2>/dev/null");
    sh("iptables -t nat -A OUTPUT -j GOOGLE_YT_BYPASS");
}

static void iptables_add_dns_rule(const char *domain) {
    if (!is_root()) return;
    char wire[128], cmd[1024];
    wire_pattern(domain, wire, sizeof(wire));
    snprintf(cmd, sizeof(cmd),
        "iptables -t nat -C GOOGLE_YT_BYPASS -p udp --dport 53 "
        "-m string --algo bm --string \"%s\" "
        "-j DNAT --to-destination 127.0.0.1:53 2>/dev/null || "
        "iptables -t nat -A GOOGLE_YT_BYPASS -p udp --dport 53 "
        "-m string --algo bm --string \"%s\" "
        "-j DNAT --to-destination 127.0.0.1:53",
        wire, wire);
    sh(cmd);
}

static void iptables_add_redirect(const char *ip) {
    if (!is_root()) return;
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
        "iptables -t nat -C GOOGLE_YT_BYPASS -p tcp -d %.64s --dport 443 "
        "-j REDIRECT --to-ports %d 2>/dev/null || "
        "iptables -t nat -A GOOGLE_YT_BYPASS -p tcp -d %.64s --dport 443 "
        "-j REDIRECT --to-ports %d",
        ip, GOOGLE_RELAY_PORT, ip, GOOGLE_RELAY_PORT);
    sh(cmd);
}

static void iptables_del_rules(void) {
    if (!is_root()) return;
    sh("iptables -D OUTPUT -p udp --dport 443 -d 142.251.0.0/16 -j DROP 2>/dev/null");
    sh("iptables -D OUTPUT -p udp --dport 443 -d 172.217.0.0/16 -j DROP 2>/dev/null");
    sh("iptables -D OUTPUT -p udp --dport 443 -d 216.239.0.0/16 -j DROP 2>/dev/null");
    sh("iptables -t nat -D OUTPUT -j GOOGLE_YT_BYPASS 2>/dev/null");
    sh("iptables -t nat -F GOOGLE_YT_BYPASS 2>/dev/null");
    sh("iptables -t nat -X GOOGLE_YT_BYPASS 2>/dev/null");
}

static void resolve_and_redirect(void) {
    char seen[32][64];
    int nseen = 0;

    for (int i = 0; google_dns_domains[i]; i++) {
        char ip[64] = {0};
        if (doh_resolve_a(google_dns_domains[i], ip, sizeof(ip)) != 0) {
            if (dns_resolve_udp(ctx.primary, google_dns_domains[i], ip, sizeof(ip)) != 0)
                dns_resolve_udp(ctx.fallback, google_dns_domains[i], ip, sizeof(ip));
        }
        if (ip[0]) {
            int dup = 0;
            for (int j = 0; j < nseen; j++) dup |= (strcmp(seen[j], ip) == 0);
            if (!dup && nseen < 32) {
                snprintf(seen[nseen], sizeof(seen[0]), "%s", ip);
                printf("[GOOGLE]   %s -> %s\n", google_dns_domains[i], ip);
                nseen++;
            }
        } else {
            printf("[GOOGLE]   %s -> DNS FAIL\n", google_dns_domains[i]);
        }
    }
    for (int i = 0; youtube_pins[i].domain; i++) {
        int dup = 0;
        for (int j = 0; j < nseen; j++) dup |= (strcmp(seen[j], youtube_pins[i].ip) == 0);
        if (!dup && nseen < 32) {
            snprintf(seen[nseen], sizeof(seen[0]), "%s", youtube_pins[i].ip);
            nseen++;
        }
    }
    for (int i = 0; i < nseen; i++) iptables_add_redirect(seen[i]);
}

void google_module_init(google_config_t *config) {
    if (google_initialized) return;
    ctx.socket_fd = -1;
    snprintf(ctx.primary, sizeof(ctx.primary), "%s", "127.0.0.1");
    snprintf(ctx.fallback, sizeof(ctx.fallback), "%s", "8.8.8.8");
    if (config && config->primary_dns) snprintf(ctx.primary, sizeof(ctx.primary), "%s", config->primary_dns);
    if (config && config->fallback_dns) snprintf(ctx.fallback, sizeof(ctx.fallback), "%s", config->fallback_dns);
    ctx.primary[31] = '\0'; ctx.fallback[31] = '\0';
    char *c;
    if ((c = strchr(ctx.primary, ':'))) *c = '\0';
    if ((c = strchr(ctx.fallback, ':'))) *c = '\0';

    ctx.socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctx.socket_fd < 0) { fprintf(stderr, "[GOOGLE] socket: %s\n", strerror(errno)); return; }
    google_initialized = true;
    printf("[GOOGLE] init: DoH+DNS %s / %s, SNI-split relay:%d\n",
           ctx.primary, ctx.fallback, GOOGLE_RELAY_PORT);
}

void google_module_cleanup(void) {
    if (!google_initialized) return;
    google_module_remove();
    if (ctx.socket_fd >= 0) { close(ctx.socket_fd); ctx.socket_fd = -1; }
    google_initialized = false;
    printf("[GOOGLE] cleanup done\n");
}

void google_module_inject(int fd) {
    (void)fd;
    if (!google_initialized) { fprintf(stderr, "[GOOGLE] not initialized\n"); return; }

    printf("[GOOGLE] inject: YouTube SNI-split + DoH pins...\n");
    iptables_base();
    for (int i = 0; google_dns_domains[i]; i++) iptables_add_dns_rule(google_dns_domains[i]);
    resolve_and_redirect();

    sni_relay_config_t rc = {
        .port = GOOGLE_RELAY_PORT,
        .so_mark = GOOGLE_SO_MARK,
        .frag_delay_ms = 30,
        .frag_first_seg = 20,
        .primary_dns = ctx.primary,
        .fallback_dns = ctx.fallback,
    };
    if (sni_relay_start(&rc) != 0) {
        fprintf(stderr, "[GOOGLE] relay start failed: %s\n", strerror(errno));
        iptables_del_rules();
        ctx.mode = 0;
        return;
    }
    printf("[GOOGLE]   SNI-split relay: 127.0.0.1:%d (pid %d)\n",
           GOOGLE_RELAY_PORT, sni_relay_pid());

    ctx.mode = 1;
    printf("[GOOGLE] inject done (%s)\n",
           is_root() ? "iptables + relay active" : "relay only (no root: iptables skipped)");
}

void google_module_remove(void) {
    if (!google_initialized) return;
    sni_relay_stop();
    iptables_del_rules();
    ctx.mode = 0;
    printf("[GOOGLE] remove done\n");
}

const char *google_get_status(void) {
    if (!google_initialized) return "Off";
    if (!ctx.mode) return "Idle";
    return sni_relay_running() ? "Active (SNI-split relay)" : "Active (relay down!)";
}
