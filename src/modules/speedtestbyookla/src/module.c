#include "src/modules/speedtestbyookla/include/header.h"
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
#include <sys/time.h>
#include <stdlib.h>

// Speedtest by Ookla: DoH pins + SNI-split relay.
// c.speedtest.net TLS with SNI times out (DPI); record-fragmentation works.

static speedtestbyookla_ctx_t ctx = {0};
static bool speedtestbyookla_initialized = false;

typedef struct {
    const char *domain;
    const char *ip;
} pin_t;

static const pin_t speedtest_pins[] = {
    {"www.speedtest.net", "104.17.147.22"},
    {"c.speedtest.net",   "151.101.2.219"},
    {"speedtest.net",     "151.101.2.219"},
    {"fast.com",          "104.17.147.22"},
    {NULL, NULL}
};

static const char *speedtest_dns_domains[] = {
    "www.speedtest.net", "c.speedtest.net", "speedtest.net",
    "fast.com",
    NULL
};

#define SPEEDTEST_RELAY_PORT 18447
#define SPEEDTEST_SO_MARK    0x4d5e

static int is_root(void) { return getuid() == 0; }

static void sh(const char *cmd) {
    int rc = system(cmd);
    (void)rc;
}

speedtestbyookla_ctx_t *speedtestbyookla_get_ctx(void) { return &ctx; }

int speedtestbyookla_is_target(const char *domain) {
    if (!domain || !*domain) return 0;
    size_t len = strlen(domain);
    char tmp[256];
    if (len >= sizeof(tmp)) return 0;
    memcpy(tmp, domain, len + 1);
    if (len > 0 && tmp[len - 1] == '.') tmp[len - 1] = '\0';

    for (int i = 0; speedtest_dns_domains[i]; i++) {
        const char *base = speedtest_dns_domains[i];
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
    sh("iptables -t nat -N SPEEDTEST_BYPASS 2>/dev/null || true");
    sh("iptables -t nat -C SPEEDTEST_BYPASS -m mark --mark 0x4d5e -j RETURN "
       "2>/dev/null || iptables -t nat -I SPEEDTEST_BYPASS 1 -m mark --mark 0x4d5e -j RETURN");
    sh("iptables -t nat -C OUTPUT -j SPEEDTEST_BYPASS 2>/dev/null || "
       "iptables -t nat -I OUTPUT -j SPEEDTEST_BYPASS");
}

static void iptables_add_dns_rule(const char *domain) {
    if (!is_root()) return;
    char wire[256], cmd[2048];
    wire_pattern(domain, wire, sizeof(wire));
    snprintf(cmd, sizeof(cmd),
        "iptables -t nat -C SPEEDTEST_BYPASS -p udp --dport 53 "
        "-m string --algo bm --string \"%s\" "
        "-j DNAT --to-destination 127.0.0.1:53 2>/dev/null || "
        "iptables -t nat -A SPEEDTEST_BYPASS -p udp --dport 53 "
        "-m string --algo bm --string \"%s\" "
        "-j DNAT --to-destination 127.0.0.1:53",
        wire, wire);
    sh(cmd);
}

static void iptables_add_redirect(const char *ip) {
    if (!is_root()) return;
    char cmd[4096];
    snprintf(cmd, sizeof(cmd),
        "iptables -t nat -A SPEEDTEST_BYPASS -p tcp -d %s --dport 443 "
        "-j REDIRECT --to-ports %d",
        ip, SPEEDTEST_RELAY_PORT);
    sh(cmd);
}

static void iptables_del_rules(void) {
    if (!is_root()) return;
    sh("iptables -t nat -D OUTPUT -j SPEEDTEST_BYPASS 2>/dev/null");
    sh("iptables -t nat -F SPEEDTEST_BYPASS 2>/dev/null");
    sh("iptables -t nat -X SPEEDTEST_BYPASS 2>/dev/null");
}

static void resolve_and_redirect(void) {
    char seen[32][64];
    int nseen = 0;

    for (int i = 0; speedtest_dns_domains[i]; i++) {
        char ip[64] = {0};
        if (doh_resolve_a(speedtest_dns_domains[i], ip, sizeof(ip)) != 0) {
            if (dns_resolve_udp(ctx.primary, speedtest_dns_domains[i], ip, sizeof(ip)) != 0)
                dns_resolve_udp(ctx.fallback, speedtest_dns_domains[i], ip, sizeof(ip));
        }
        if (ip[0]) {
            int dup = 0;
            for (int j = 0; j < nseen; j++) dup |= (strcmp(seen[j], ip) == 0);
            if (!dup && nseen < 32) {
                snprintf(seen[nseen], sizeof(seen[0]), "%s", ip);
                printf("[SPEEDTEST]   %s -> %s\n", speedtest_dns_domains[i], ip);
                nseen++;
            }
        } else {
            printf("[SPEEDTEST]   %s -> DNS FAIL\n", speedtest_dns_domains[i]);
        }
    }
    for (int i = 0; speedtest_pins[i].domain; i++) {
        int dup = 0;
        for (int j = 0; j < nseen; j++) dup |= (strcmp(seen[j], speedtest_pins[i].ip) == 0);
        if (!dup && nseen < 32) {
            snprintf(seen[nseen], sizeof(seen[0]), "%s", speedtest_pins[i].ip);
            nseen++;
        }
    }
    for (int i = 0; i < nseen; i++) iptables_add_redirect(seen[i]);
}

void speedtestbyookla_module_init(speedtestbyookla_config_t *config) {
    if (speedtestbyookla_initialized) return;
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
    if (ctx.socket_fd < 0) { fprintf(stderr, "[SPEEDTESTBYOOKLA] socket failed\n"); return; }
    speedtestbyookla_initialized = true;
    printf("[SPEEDTESTBYOOKLA] init: DoH+DNS %s / %s, SNI-split relay:%d\n",
           ctx.primary, ctx.fallback, SPEEDTEST_RELAY_PORT);
}

void speedtestbyookla_module_cleanup(void) {
    if (!speedtestbyookla_initialized) return;
    speedtestbyookla_module_remove();
    if (ctx.socket_fd >= 0) { close(ctx.socket_fd); ctx.socket_fd = -1; }
    speedtestbyookla_initialized = false;
    printf("[SPEEDTESTBYOOKLA] cleanup done\n");
}

void speedtestbyookla_module_inject(int fd) {
    (void)fd;
    if (!speedtestbyookla_initialized) { fprintf(stderr, "[SPEEDTESTBYOOKLA] Not initialized!\n"); return; }

    printf("[SPEEDTESTBYOOKLA] inject: SNI-split + DoH pins...\n");
    iptables_base();
    for (int i = 0; speedtest_dns_domains[i]; i++) iptables_add_dns_rule(speedtest_dns_domains[i]);
    resolve_and_redirect();

    sni_relay_config_t rc = {
        .port = SPEEDTEST_RELAY_PORT,
        .so_mark = SPEEDTEST_SO_MARK,
        .frag_delay_ms = 30,
        .frag_first_seg = 20,
        .primary_dns = ctx.primary,
        .fallback_dns = ctx.fallback,
    };
    if (sni_relay_start(&rc) != 0) {
        fprintf(stderr, "[SPEEDTESTBYOOKLA] relay start failed: %s\n", strerror(errno));
        iptables_del_rules();
        ctx.mode = 0;
        return;
    }
    printf("[SPEEDTESTBYOOKLA]   SNI-split relay: 127.0.0.1:%d (pid %d)\n",
           SPEEDTEST_RELAY_PORT, sni_relay_pid());

    ctx.mode = 1;
    printf("[SPEEDTESTBYOOKLA] inject done (%s)\n",
           is_root() ? "iptables + relay active" : "relay only (no root: iptables skipped)");
}

void speedtestbyookla_module_remove(void) {
    if (!speedtestbyookla_initialized) return;
    sni_relay_stop();
    iptables_del_rules();
    ctx.mode = 0;
    printf("[SPEEDTESTBYOOKLA] remove done\n");
}

float speedtestbyookla_speed_test(const char *domain) {
    if (!domain || !speedtestbyookla_initialized) return -1.0f;
    char resolved[64] = {0};
    if (doh_resolve_a(domain, resolved, sizeof(resolved)) != 0 &&
        dns_resolve_udp(ctx.primary, domain, resolved, sizeof(resolved)) != 0) {
        fprintf(stderr, "[SPEEDTESTBYOOKLA] Cannot resolve %s\n", domain);
        return -1.0f;
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1.0f;
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(443);
    if (inet_pton(AF_INET, resolved, &addr.sin_addr) != 1) {
        close(fd);
        return -1.0f;
    }
    struct timeval start, end;
    gettimeofday(&start, NULL);
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1.0f;
    }
    gettimeofday(&end, NULL);
    close(fd);
    float ms = (end.tv_sec - start.tv_sec) * 1000.0f + (end.tv_usec - start.tv_usec) / 1000.0f;
    printf("[SPEEDTESTBYOOKLA] %s connect: %.1fms\n", domain, ms);
    return ms;
}

const char* speedtestbyookla_get_status(void) {
    if (!speedtestbyookla_initialized) return "Off";
    if (!ctx.mode) return "Idle";
    return sni_relay_running() ? "Active (SNI-split relay)" : "Active (relay down!)";
}
