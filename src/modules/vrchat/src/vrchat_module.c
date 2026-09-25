#include "src/modules/vrchat/include/header.h"
#include "src/common/sni_relay.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <signal.h>
#include <poll.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

// VRChat module: DNS pinning via module-owned responder + SNI-split relay.
//
// Diagnosis (login/registration was broken):
//   - plain DNS for vrchat.com / vrchat.cloud is poisoned on this network:
//     api.vrchat.cloud -> 8.47.69.0 sinkhole instead of 104.18.26.36 (DoH);
//   - old iptables rules matched ASCII "auth.vrchat.cloud", but a DNS wire
//     packet stores labels length-prefixed (\x07vrchat\x05cloud...) — the rule
//     could never match, so nothing was ever redirected;
//   - the core proxy has no pin for auth/api and would forward vrchat queries
//     into the poisoned upstream anyway;
//   - TLS to the real IPs works (SNI is not cut), so the module pins DNS and
//     additionally runs the shared SNI-split relay like google/xcom/discord.
//
// All pins below were verified against DoH (cloudflare-dns.com) on 2026-09-24.

#define VRCHAT_DNS_PORT   15353   // module-owned DNS responder (not the core :53 proxy)
#define VRCHAT_RELAY_PORT 18444   // free: discord 18443, google 18445, xcom 18446, speedtest 18447
#define VRCHAT_SO_MARK    0x4d5b  // sni_relay default mark, reserved for vrchat

static vrchat_ctx_t ctx = {0};
static bool vrchat_initialized = false;

typedef struct {
    const char *domain;
    const char *ip;
} vrchat_pin_t;

// Exact matches first (checked before suffix pins).
static const vrchat_pin_t vrchat_pins[] = {
    {"api.vrchat.cloud",     "104.18.26.36"},   // Cloudflare
    {"pipeline.vrchat.cloud","104.18.26.36"},   // Cloudflare
    {"www.vrchat.com",       "104.18.6.156"},   // Cloudflare
    {"vrchat.com",           "104.18.6.156"},   // Cloudflare
    {"docs.vrchat.com",      "104.16.241.118"}, // ReadMe (CF)
    {"assets.vrchat.com",    "65.9.106.85"},    // CloudFront (*.vrchat.com cert ok)
    {"files.vrchat.cloud",   "3.174.18.93"},    // CloudFront (*.vrchat.cloud cert ok)
    {"help.vrchat.com",      "216.198.53.6"},   // Zendesk
    {NULL, NULL}
};

// Suffix fallbacks: every other *.vrchat.cloud / *.vrchat.com name
// (auth, worlds, avatars, groups, status, unknown future subdomains...).
static const vrchat_pin_t vrchat_suffix_pins[] = {
    {"vrchat.cloud", "104.18.26.36"},
    {"vrchat.com",   "104.18.6.156"},
    {NULL, NULL}
};

// iptables string-match zones: one wire-pattern rule per zone covers the zone
// and all of its subdomains (labels are length-prefixed, so "\x07vrchat\x03com"
// is a true label-anchored suffix match).
static const char *vrchat_zones[] = {
    "vrchat.com",
    "vrchat.cloud",
    NULL
};

// Known-good names, printed at inject to show what the responder will answer.
static const char *vrchat_notable[] = {
    "api.vrchat.cloud",
    "pipeline.vrchat.cloud",
    "www.vrchat.com",
    "vrchat.com",
    "docs.vrchat.com",
    "assets.vrchat.com",
    "files.vrchat.cloud",
    "help.vrchat.com",
    "status.vrchat.com",
    NULL
};

static pid_t responder_pid = -1;

static int is_root(void) { return getuid() == 0; }

static void sh(const char *cmd) {
    int rc = system(cmd);
    (void)rc;
}

// ── DNS wire encoding for iptables -m string ─────────────────────────────
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

// ── iptables ─────────────────────────────────────────────────────────────
static void iptables_base(void) {
    if (!is_root()) return;
    sh("iptables -t nat -N VRCHAT_BYPASS 2>/dev/null || true");
    // Не трогаем помеченные пакеты ЛЮБОГО модуля (0x4d5a discord, 0x4d5b vrchat,
    // 0x4d5c google, 0x4d5e speedtest -> маска 0xfff0 = 0x4d50/0xfff0).
    sh("iptables -t nat -C VRCHAT_BYPASS -m mark --mark 0x4d50/0xfff0 -j RETURN "
       "2>/dev/null || iptables -t nat -I VRCHAT_BYPASS 1 -m mark --mark 0x4d50/0xfff0 -j RETURN");
    sh("iptables -t nat -C VRCHAT_BYPASS -m mark --mark 0x4d5b -j RETURN "
       "2>/dev/null || iptables -t nat -I VRCHAT_BYPASS 2 -m mark --mark 0x4d5b -j RETURN");
    // Прыжок обязан быть ПЕРВЫМ в OUTPUT: у discord есть широкие CIDR
    // (104.16.0.0/12, 104.18.0.0/16 -> REDIRECT 18443), которые перехватывают
    // наши IP (104.18.26.36, 104.18.6.156, 104.16.241.118), если он стоит выше.
    // Поэтому пересоздаём прыжок на позиции 1 при каждом inject.
    sh("iptables -t nat -D OUTPUT -j VRCHAT_BYPASS 2>/dev/null");
    sh("iptables -t nat -I OUTPUT 1 -j VRCHAT_BYPASS");
}

static void iptables_add_dns_rule(const char *zone) {
    if (!is_root()) return;
    char wire[128], cmd[1024];
    wire_pattern(zone, wire, sizeof(wire));
    // -C перед -A: при повторном inject правило не задваивается
    snprintf(cmd, sizeof(cmd),
        "iptables -t nat -C VRCHAT_BYPASS -p udp --dport 53 "
        "-m string --algo bm --string \"%s\" "
        "-j DNAT --to-destination 127.0.0.1:%d 2>/dev/null || "
        "iptables -t nat -A VRCHAT_BYPASS -p udp --dport 53 "
        "-m string --algo bm --string \"%s\" "
        "-j DNAT --to-destination 127.0.0.1:%d",
        wire, VRCHAT_DNS_PORT, wire, VRCHAT_DNS_PORT);
    sh(cmd);
}

static void iptables_add_redirect(const char *ip) {
    if (!is_root()) return;
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "iptables -t nat -C VRCHAT_BYPASS -p tcp -d %.64s --dport 443 "
        "-j REDIRECT --to-ports %d 2>/dev/null || "
        "iptables -t nat -A VRCHAT_BYPASS -p tcp -d %.64s --dport 443 "
        "-j REDIRECT --to-ports %d",
        ip, VRCHAT_RELAY_PORT, ip, VRCHAT_RELAY_PORT);
    sh(cmd);
}

static void iptables_del_rules(void) {
    if (!is_root()) return;
    sh("iptables -t nat -D OUTPUT -j VRCHAT_BYPASS 2>/dev/null");
    sh("iptables -t nat -D OUTPUT -p udp --dport 53 -j VRCHAT_BYPASS 2>/dev/null");
    sh("iptables -t nat -F VRCHAT_BYPASS 2>/dev/null");
    sh("iptables -t nat -X VRCHAT_BYPASS 2>/dev/null");
}

// ── pin lookup (exact, then zone suffix) ─────────────────────────────────
static const char *lookup_ip(const char *domain) {
    if (!domain || !*domain) return NULL;
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s", domain);
    size_t l = strlen(tmp);
    while (l > 0 && tmp[l - 1] == '.') tmp[--l] = '\0';

    for (int i = 0; vrchat_pins[i].domain; i++) {
        if (strcasecmp(tmp, vrchat_pins[i].domain) == 0)
            return vrchat_pins[i].ip;
    }
    for (int i = 0; vrchat_suffix_pins[i].domain; i++) {
        const char *base = vrchat_suffix_pins[i].domain;
        size_t bl = strlen(base), tl = strlen(tmp);
        if (tl == bl && strcasecmp(tmp, base) == 0)
            return vrchat_suffix_pins[i].ip;
        if (tl > bl && tmp[tl - bl - 1] == '.' &&
            strcasecmp(tmp + tl - bl, base) == 0)
            return vrchat_suffix_pins[i].ip;
    }
    return NULL;
}

// ── minimal DNS message helpers (same shape as core proxy) ───────────────
static void get_qname(const unsigned char *pkt, int len, char *out, int outlen) {
    int pos = 12, o = 0;
    while (pos < len && pkt[pos] != 0 && o < outlen - 1) {
        int ll = pkt[pos++];
        if ((ll & 0xC0) == 0xC0) break;
        if (o > 0) out[o++] = '.';
        for (int i = 0; i < ll && pos < len && o < outlen - 1; i++)
            out[o++] = (char)pkt[pos++];
    }
    out[o] = 0;
}

static int skip_qname(const unsigned char *pkt, int len) {
    int pos = 12;
    while (pos < len && pkt[pos] != 0) {
        int ll = pkt[pos++];
        if ((ll & 0xC0) == 0xC0) { pos += 1; break; }
        pos += ll;
    }
    if (pos < len) pos++;
    return pos;
}

static int build_a_resp(const unsigned char *q, int ql, unsigned char *buf,
                        int buflen, const char *ip) {
    int qpos = skip_qname(q, ql);
    int qsection_len = qpos + 4;
    if (qsection_len > ql || buflen < qsection_len + 24) return -1;
    memset(buf, 0, buflen);
    memcpy(buf, q, qsection_len);
    unsigned char *r = buf;
    r[2] = 0x81; r[3] = 0x80;
    r[4] = 0; r[5] = 1;   // QDCOUNT
    r[6] = 0; r[7] = 1;   // ANCOUNT
    r[8] = 0; r[9] = 0;   // NSCOUNT
    int o = qsection_len;
    r[o++] = 0xC0; r[o++] = 0x0C;
    r[o++] = 0x00; r[o++] = 0x01;   // A
    r[o++] = 0x00; r[o++] = 0x01;   // IN
    r[o++] = 0x00; r[o++] = 0x00; r[o++] = 0x00; r[o++] = 0x78;
    r[o++] = 0x00; r[o++] = 0x04;
    struct in_addr a;
    if (inet_pton(AF_INET, ip, &a) != 1) return -1;
    memcpy(r + o, &a, 4);
    o += 4;
    r[10] = 0; r[11] = 0;
    return o;
}

// NOERROR with empty answer (AAAA/SVCB/TXT on a pinned name: "no such record").
static int build_empty_resp(const unsigned char *q, int ql,
                            unsigned char *buf, int buflen) {
    int qpos = skip_qname(q, ql);
    int qsection_len = qpos + 4;
    if (qsection_len > ql || buflen < qsection_len) return -1;
    memset(buf, 0, buflen);
    memcpy(buf, q, qsection_len);
    unsigned char *r = buf;
    r[2] = 0x81; r[3] = 0x80;
    r[4] = 0; r[5] = 1;   // QDCOUNT
    r[6] = 0; r[7] = 0;   // ANCOUNT (empty)
    r[8] = 0; r[9] = 0;   // NSCOUNT
    r[10] = 0; r[11] = 0; // ARCOUNT
    return qsection_len;
}

// Forward a non-vrchat query upstream (marked so our own DNAT rules skip it).
static int forward_query(const unsigned char *q, int ql,
                         unsigned char *ans, int anslen) {
    const char *servers[3];
    int ns = 0;
    if (ctx.primary[0]) servers[ns++] = ctx.primary;
    if (ctx.fallback[0]) servers[ns++] = ctx.fallback;
    servers[ns++] = NULL;

    for (int i = 0; servers[i]; i++) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) return -1;
        unsigned int mark = VRCHAT_SO_MARK;
        setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)); // ok if it fails (no root)
        struct timeval tv = {2, 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        struct sockaddr_in dst = {0};
        dst.sin_family = AF_INET;
        dst.sin_port = htons(53);
        if (inet_pton(AF_INET, servers[i], &dst.sin_addr) != 1) { close(fd); continue; }
        ssize_t sent = sendto(fd, q, (size_t)ql, 0,
                              (struct sockaddr *)&dst, sizeof(dst));
        if (sent == ql) {
            ssize_t n = recvfrom(fd, ans, (size_t)anslen, 0, NULL, NULL);
            close(fd);
            if (n >= 12 && ans[0] == q[0] && ans[1] == q[1]) return (int)n;
        } else {
            close(fd);
        }
    }
    return -1;
}

// ── DNS responder (forked child, answers from the pin table) ─────────────
static void responder_loop(int ready_fd) {
    prctl(PR_SET_PDEATHSIG, SIGTERM);
    if (getppid() == 1) _exit(0);   // parent died before prctl
    setsid();
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGTERM, SIG_DFL);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) _exit(1);
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons(VRCHAT_DNS_PORT);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0) _exit(2);

    if (ready_fd >= 0) {
        char ok = 1;
        if (write(ready_fd, &ok, 1) != 1) _exit(5);
        close(ready_fd);
    }

    unsigned char q[4096], r[4096];
    for (;;) {
        struct sockaddr_in cli;
        socklen_t cl = sizeof(cli);
        ssize_t n = recvfrom(fd, q, sizeof(q), 0, (struct sockaddr *)&cli, &cl);
        if (n < 12) continue;

        char dom[256];
        get_qname(q, (int)n, dom, sizeof(dom));
        int qpos = skip_qname(q, (int)n);
        int qtype = (qpos + 1 < n) ? (q[qpos] << 8) | q[qpos + 1] : 0;

        const char *ip = lookup_ip(dom);
        int rl;
        if (ip) {
            rl = (qtype == 1) ? build_a_resp(q, (int)n, r, sizeof(r), ip)
                              : build_empty_resp(q, (int)n, r, sizeof(r));
        } else {
            rl = forward_query(q, (int)n, r, sizeof(r));
        }
        if (rl > 0)
            sendto(fd, r, (size_t)rl, 0, (struct sockaddr *)&cli, cl);
    }
}

static void responder_stop(void) {
    if (responder_pid <= 0) return;
    kill(responder_pid, SIGTERM);
    for (int i = 0; i < 20; i++) {
        if (waitpid(responder_pid, NULL, WNOHANG) == responder_pid) {
            responder_pid = -1;
            return;
        }
        usleep(50000);
    }
    kill(responder_pid, SIGKILL);
    waitpid(responder_pid, NULL, 0);
    responder_pid = -1;
}

static int responder_start(void) {
    if (responder_pid > 0 && kill(responder_pid, 0) == 0) return 0;

    int pfd[2];
    if (pipe(pfd) != 0) return -1;
    pid_t p = fork();
    if (p < 0) { close(pfd[0]); close(pfd[1]); return -1; }
    if (p == 0) {
        close(pfd[0]);
        responder_loop(pfd[1]);
        _exit(0);
    }
    close(pfd[1]);
    responder_pid = p;

    char ok = 0;
    struct pollfd pfd_ev = { .fd = pfd[0], .events = POLLIN };
    int pr = poll(&pfd_ev, 1, 2000);
    int got = (pr > 0) ? (int)read(pfd[0], &ok, 1) : 0;
    close(pfd[0]);
    if (got != 1 || !ok) { responder_stop(); return -1; }
    return 0;
}

// ── lifecycle ────────────────────────────────────────────────────────────
void vrchat_module_init(vrchat_config_t *config) {
    if (vrchat_initialized) return;

    strncpy(ctx.primary, "1.1.1.1", 31);
    strncpy(ctx.fallback, "8.8.8.8", 31);
    if (config && config->primary_dns) strncpy(ctx.primary, config->primary_dns, 31);
    if (config && config->fallback_dns) strncpy(ctx.fallback, config->fallback_dns, 31);
    ctx.primary[31] = '\0';
    ctx.fallback[31] = '\0';
    char *c;
    if ((c = strchr(ctx.primary, ':'))) *c = '\0';
    if ((c = strchr(ctx.fallback, ':'))) *c = '\0';

    ctx.socket_fd = -1;
    ctx.socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctx.socket_fd < 0) {
        fprintf(stderr, "[VRCHAT] socket: %s\n", strerror(errno));
        return;
    }

    vrchat_initialized = true;
    printf("[VRCHAT] init: DNS %s / %s, responder:%d relay:%d\n",
           ctx.primary, ctx.fallback, VRCHAT_DNS_PORT, VRCHAT_RELAY_PORT);
}

void vrchat_module_cleanup(void) {
    if (!vrchat_initialized) return;
    vrchat_module_remove();
    if (ctx.socket_fd >= 0) {
        close(ctx.socket_fd);
        ctx.socket_fd = -1;
    }
    vrchat_initialized = false;
    printf("[VRCHAT] cleanup done\n");
}

void vrchat_module_inject(int fd) {
    (void)fd;
    if (!vrchat_initialized) {
        fprintf(stderr, "[VRCHAT] not initialized\n");
        return;
    }

    if (responder_start() != 0) {
        fprintf(stderr, "[VRCHAT] responder start failed: %s\n", strerror(errno));
        ctx.mode = 0;
        return;
    }

    iptables_base();
    for (int i = 0; vrchat_zones[i]; i++)
        iptables_add_dns_rule(vrchat_zones[i]);

    printf("[VRCHAT] inject: zone rules -> 127.0.0.1:%d, relay :%d\n",
           VRCHAT_DNS_PORT, VRCHAT_RELAY_PORT);
    for (int i = 0; vrchat_notable[i]; i++) {
        const char *ip = lookup_ip(vrchat_notable[i]);
        printf("[VRCHAT]   %s -> %s\n", vrchat_notable[i], ip ? ip : "?");
    }

    // TLS redirect to the SNI-split relay for every pinned address.
    char seen[32][64];
    int nseen = 0;
    for (int i = 0; vrchat_pins[i].domain; i++) {
        const char *ip = vrchat_pins[i].ip;
        int dup = 0;
        for (int j = 0; j < nseen; j++) dup |= (strcmp(seen[j], ip) == 0);
        if (!dup && nseen < 32) {
            snprintf(seen[nseen], sizeof(seen[0]), "%s", ip);
            nseen++;
        }
    }
    for (int i = 0; i < nseen; i++)
        iptables_add_redirect(seen[i]);

    sni_relay_config_t rc = {
        .port = VRCHAT_RELAY_PORT,
        .so_mark = VRCHAT_SO_MARK,
        .frag_delay_ms = 30,
        .frag_first_seg = 20,
        .primary_dns = ctx.primary,
        .fallback_dns = ctx.fallback,
    };
    if (sni_relay_start(&rc) != 0) {
        fprintf(stderr, "[VRCHAT] relay start failed: %s\n", strerror(errno));
        iptables_del_rules();
        responder_stop();
        ctx.mode = 0;
        return;
    }
    printf("[VRCHAT]   SNI-split relay: 127.0.0.1:%d (pid %d)\n",
           VRCHAT_RELAY_PORT, sni_relay_pid());

    ctx.mode = 1;
    printf("[VRCHAT] inject done (responder pid %d, %s)\n",
           (int)responder_pid,
           is_root() ? "iptables active" : "no root — iptables skipped");
}

void vrchat_module_remove(void) {
    if (!vrchat_initialized) return;
    iptables_del_rules();
    responder_stop();
    sni_relay_stop();
    ctx.mode = 0;
    printf("[VRCHAT] remove done\n");
}

const char *vrchat_get_status(void) {
    if (!vrchat_initialized) return "Off";
    if (!ctx.mode) return "Idle";
    if (responder_pid <= 0 || !sni_relay_running()) return "Active (relay down!)";
    return "Active (SNI-split relay)";
}
