#include "src/modules/xcom/include/header.h"
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

// X.com module: DoH DNS pins + SNI-split relay.
// TLS with SNI x.com times out (DPI cut); record-fragmentation works.

static xcom_ctx_t ctx = {0};
static bool xcom_initialized = false;

typedef struct {
    const char *domain;
    const char *ip;
} pin_t;

static const pin_t xcom_pins[] = {
    {"x.com",       "162.159.140.229"},
    {"twitter.com", "172.66.0.227"},
    {"api.x.com",   "162.159.140.229"},
    {"abs.twimg.com",   "162.159.140.229"},
    {"pbs.twimg.com",   "162.159.140.229"},
    {"video.twimg.com", "162.159.140.229"},
    {"ton.twimg.com",   "162.159.140.229"},
    {NULL, NULL}
};

static const char *xcom_dns_domains[] = {
    "x.com", "twitter.com", "api.x.com", "api.twitter.com",
    "abs.twimg.com", "pbs.twimg.com", "video.twimg.com",
    "ton.twimg.com", "cdn.syndication.twimg.com",
    NULL
};

#define XCOM_RELAY_PORT 18446
#define XCOM_SO_MARK    0x4d5d

static int is_root(void) { return getuid() == 0; }

static void sh(const char *cmd) {
    int rc = system(cmd);
    (void)rc;
}

xcom_ctx_t *xcom_get_ctx(void) { return &ctx; }

int xcom_is_target(const char *domain) {
    if (!domain || !*domain) return 0;
    size_t len = strlen(domain);
    char tmp[256];
    if (len >= sizeof(tmp)) return 0;
    memcpy(tmp, domain, len + 1);
    if (len > 0 && tmp[len - 1] == '.') tmp[len - 1] = '\0';

    for (int i = 0; xcom_dns_domains[i]; i++) {
        const char *base = xcom_dns_domains[i];
        if (strcasecmp(tmp, base) == 0) return 1;
        size_t bl = strlen(base), tl = strlen(tmp);
        if (tl > bl + 1 && strcasecmp(tmp + tl - bl, base) == 0 &&
            tmp[tl - bl - 1] == '.')
            return 1;
    }
    // twimg / xdomain suffixes
    if (strstr(tmp, ".twimg.com") || strstr(tmp, ".x.com")) return 1;
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
    sh("iptables -t nat -N XCOM_BYPASS 2>/dev/null || true");
    sh("iptables -t nat -C XCOM_BYPASS -m mark --mark 0x4d5d -j RETURN "
       "2>/dev/null || iptables -t nat -I XCOM_BYPASS 1 -m mark --mark 0x4d5d -j RETURN");
    sh("iptables -t nat -C OUTPUT -j XCOM_BYPASS 2>/dev/null || "
       "iptables -t nat -I OUTPUT -j XCOM_BYPASS");
}

static void iptables_add_dns_rule(const char *domain) {
    if (!is_root()) return;
    char wire[128], cmd[512];
    wire_pattern(domain, wire, sizeof(wire));
    snprintf(cmd, sizeof(cmd),
        "iptables -t nat -C XCOM_BYPASS -p udp --dport 53 "
        "-m string --algo bm --string \"%s\" "
        "-j DNAT --to-destination 127.0.0.1:53 2>/dev/null || "
        "iptables -t nat -A XCOM_BYPASS -p udp --dport 53 "
        "-m string --algo bm --string \"%s\" "
        "-j DNAT --to-destination 127.0.0.1:53",
        wire, wire);
    sh(cmd);
}

static void iptables_add_redirect(const char *ip) {
    if (!is_root()) return;
    char cmd[4096];
    snprintf(cmd, sizeof(cmd),
        "iptables -t nat -A XCOM_BYPASS -p tcp -d %s --dport 443 "
        "-j REDIRECT --to-ports %d",
        ip, XCOM_RELAY_PORT);
    sh(cmd);
}

static void iptables_del_rules(void) {
    if (!is_root()) return;
    sh("iptables -t nat -D OUTPUT -j XCOM_BYPASS 2>/dev/null");
    sh("iptables -t nat -F XCOM_BYPASS 2>/dev/null");
    sh("iptables -t nat -X XCOM_BYPASS 2>/dev/null");
}

static void resolve_and_redirect(void) {
    char seen[32][64];
    int nseen = 0;

    for (int i = 0; xcom_dns_domains[i]; i++) {
        char ip[64] = {0};
        if (doh_resolve_a(xcom_dns_domains[i], ip, sizeof(ip)) != 0) {
            if (dns_resolve_udp(ctx.primary, xcom_dns_domains[i], ip, sizeof(ip)) != 0)
                dns_resolve_udp(ctx.fallback, xcom_dns_domains[i], ip, sizeof(ip));
        }
        if (ip[0]) {
            int dup = 0;
            for (int j = 0; j < nseen; j++) dup |= (strcmp(seen[j], ip) == 0);
            if (!dup && nseen < 32) {
                snprintf(seen[nseen], sizeof(seen[0]), "%s", ip);
                printf("[X]   %s -> %s\n", xcom_dns_domains[i], ip);
                nseen++;
            }
        } else {
            printf("[X]   %s -> DNS FAIL\n", xcom_dns_domains[i]);
        }
    }
    for (int i = 0; xcom_pins[i].domain; i++) {
        int dup = 0;
        for (int j = 0; j < nseen; j++) dup |= (strcmp(seen[j], xcom_pins[i].ip) == 0);
        if (!dup && nseen < 32) {
            snprintf(seen[nseen], sizeof(seen[0]), "%s", xcom_pins[i].ip);
            nseen++;
        }
    }
    for (int i = 0; i < nseen; i++) iptables_add_redirect(seen[i]);
}

void xcom_module_init(xcom_config_t *config) {
    if (xcom_initialized) return;
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
    if (ctx.socket_fd < 0) { fprintf(stderr, "[X] socket: %s\n", strerror(errno)); return; }
    xcom_initialized = true;
    printf("[X] init: DoH+DNS %s / %s, SNI-split relay:%d\n",
           ctx.primary, ctx.fallback, XCOM_RELAY_PORT);
}

void xcom_module_cleanup(void) {
    if (!xcom_initialized) return;
    xcom_module_remove();
    if (ctx.socket_fd >= 0) { close(ctx.socket_fd); ctx.socket_fd = -1; }
    xcom_initialized = false;
    printf("[X] cleanup done\n");
}

void xcom_module_inject(int fd) {
    (void)fd;
    if (!xcom_initialized) { fprintf(stderr, "[X] not initialized\n"); return; }

    printf("[X] inject: SNI-split + DoH pins...\n");
    iptables_base();
    for (int i = 0; xcom_dns_domains[i]; i++) iptables_add_dns_rule(xcom_dns_domains[i]);
    resolve_and_redirect();

    sni_relay_config_t rc = {
        .port = XCOM_RELAY_PORT,
        .so_mark = XCOM_SO_MARK,
        .frag_delay_ms = 30,
        .frag_first_seg = 20,
        .primary_dns = ctx.primary,
        .fallback_dns = ctx.fallback,
    };
    if (sni_relay_start(&rc) != 0) {
        fprintf(stderr, "[X] relay start failed: %s\n", strerror(errno));
        iptables_del_rules();
        ctx.mode = 0;
        return;
    }
    printf("[X]   SNI-split relay: 127.0.0.1:%d (pid %d)\n",
           XCOM_RELAY_PORT, sni_relay_pid());

    ctx.mode = 1;
    printf("[X] inject done (%s)\n",
           is_root() ? "iptables + relay active" : "relay only (no root: iptables skipped)");
}

void xcom_module_remove(void) {
    if (!xcom_initialized) return;
    sni_relay_stop();
    iptables_del_rules();
    ctx.mode = 0;
    printf("[X] remove done\n");
}

const char *xcom_get_status(void) {
    if (!xcom_initialized) return "Off";
    if (!ctx.mode) return "Idle";
    return sni_relay_running() ? "Active (SNI-split relay)" : "Active (relay down!)";
}
