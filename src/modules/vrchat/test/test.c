// vrchat module test — unit + E2E (no root required).
//
// Build & run (from repo root):
//   gcc -std=gnu11 -Wall -Wextra -O2 -I. -o /tmp/vrchat_test
//       src/modules/vrchat/test/test.c
//       src/dns/dns_resolve.c src/dns/doh_resolve.c src/common/sni_relay.c
//   /tmp/vrchat_test
//
// (test.c includes vrchat_module.c directly to reach static helpers)
//
// Checks: iptables wire-format encoding (the old ASCII matcher could never
// match a real DNS packet), module init/inject, pin/suffix DNS answers from
// the module's own responder (127.0.0.1:15353), empty NOERROR for AAAA,
// SNI-split relay up, full cleanup (ports released).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>

#include "src/modules/vrchat/src/vrchat_module.c"

#define TEST_DNS_PORT 15353

static int failed = 0;

#define CHECK(cond, fmt, ...) do { \
    if (cond) printf("  ok   " fmt "\n", ##__VA_ARGS__); \
    else { printf("  FAIL " fmt "\n", ##__VA_ARGS__); failed++; } \
} while (0)

static int build_query(unsigned char *buf, int cap, const char *name, int qtype) {
    if (cap < 64) return -1;
    memset(buf, 0, cap);
    buf[0] = 0x12; buf[1] = 0x34;
    buf[2] = 0x01; buf[3] = 0x00;
    buf[5] = 0x01;
    int o = 12;
    const char *s = name;
    while (*s) {
        const char *dot = strchr(s, '.');
        int ll = dot ? (int)(dot - s) : (int)strlen(s);
        if (ll <= 0 || ll > 63 || o + ll + 6 >= cap) return -1;
        buf[o++] = (unsigned char)ll;
        memcpy(buf + o, s, (size_t)ll);
        o += ll;
        if (!dot) break;
        s = dot + 1;
    }
    buf[o++] = 0;
    buf[o++] = (unsigned char)(qtype >> 8);
    buf[o++] = (unsigned char)(qtype & 0xFF);
    buf[o++] = 0x00;
    buf[o++] = 0x01;
    return o;
}

// Returns response length (>0) or 0 on timeout.
static int dns_query(int qtype, const char *name, unsigned char *out, int outlen) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return 0;
    unsigned char q[512];
    int ql = build_query(q, sizeof(q), name, qtype);
    if (ql < 0) { close(fd); return 0; }
    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(TEST_DNS_PORT);
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (sendto(fd, q, (size_t)ql, 0, (struct sockaddr *)&dst, sizeof(dst)) != ql) {
        close(fd);
        return 0;
    }
    struct pollfd p = { .fd = fd, .events = POLLIN };
    int n = 0;
    if (poll(&p, 1, 1500) > 0)
        n = (int)recvfrom(fd, out, (size_t)outlen, 0, NULL, NULL);
    close(fd);
    return n > 0 ? n : 0;
}

static int resp_rcode(const unsigned char *r, int n) {
    return (n >= 4) ? (r[3] & 0x0F) : -1;
}

static int resp_ancount(const unsigned char *r, int n) {
    return (n >= 8) ? ((r[6] << 8) | r[7]) : -1;
}

// Extract first A record answer (returns 1 + fills ip).
static int resp_first_a(const unsigned char *r, int n, char *ip, int iplen) {
    if (n < 12) return 0;
    int i = 12;
    while (i < n && r[i] != 0) {
        if (r[i] & 0xC0) { i += 2; break; }
        i += r[i] + 1;
    }
    if (i < n && r[i] == 0) i++;
    i += 4;
    int an = (r[6] << 8) | r[7];
    for (int k = 0; k < an && i + 10 <= n; k++) {
        if (r[i] & 0xC0) i += 2;
        else {
            while (i < n && r[i] != 0 && !(r[i] & 0xC0)) i += r[i] + 1;
            if (i < n && r[i] == 0) i++;
            else if (i < n) i += 2;
        }
        if (i + 10 > n) return 0;
        int type = (r[i] << 8) | r[i + 1];
        int rdlen = (r[i + 8] << 8) | r[i + 9];
        i += 10;
        if (type == 1 && rdlen == 4 && i + 4 <= n) {
            snprintf(ip, (size_t)iplen, "%u.%u.%u.%u",
                     r[i], r[i + 1], r[i + 2], r[i + 3]);
            return 1;
        }
        i += rdlen;
    }
    return 0;
}

static int port_alive(int tcp, int port) {
    int fd = socket(AF_INET, tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
    if (fd < 0) return 0;
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int alive = 0;
    if (tcp) {
        struct timeval tv = {1, 0};
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        alive = (connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0);
    } else {
        unsigned char q[64];
        int ql = build_query(q, sizeof(q), "port-check.example.com", 1);
        sendto(fd, q, (size_t)ql, 0, (struct sockaddr *)&a, sizeof(a));
        struct pollfd p = { .fd = fd, .events = POLLIN };
        alive = (poll(&p, 1, 700) > 0);
    }
    close(fd);
    return alive;
}

static void expect_a(const char *name, const char *want, int quiet) {
    unsigned char r[4096];
    char ip[64] = {0};
    int n = dns_query(1, name, r, sizeof(r));
    int got = (n > 0) && resp_rcode(r, n) == 0 && resp_first_a(r, n, ip, sizeof(ip));
    if (quiet) {
        if (!(got && strcmp(ip, want) == 0)) {
            printf("  FAIL %s -> %s (want %s)\n", name, got ? ip : "no A", want);
            failed++;
        }
        return;
    }
    CHECK(got && strcmp(ip, want) == 0, "%s A -> %s (want %s)",
          name, got ? ip : "no A/err", want);
}

// Child process count (baseline includes the transient popen shell itself).
static int child_count(void) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ps --ppid %d -o pid= | wc -l", (int)getpid());
    FILE *p = popen(cmd, "r");
    int n = -1;
    if (p) { if (fscanf(p, "%d", &n) != 1) n = -1; pclose(p); }
    return n;
}

static const unsigned char *mem_find(const unsigned char *h, int hn,
                                     const void *nd, int nn) {
    if (nn <= 0 || nn > hn) return NULL;
    for (int i = 0; i + nn <= hn; i++)
        if (memcmp(h + i, nd, (size_t)nn) == 0) return h + i;
    return NULL;
}

int main(void) {
    printf("[TEST] vrchat module\n");

    // ── iptables wire encoding: the core of the old bug ──────────────────
    {
        char wire[128];
        unsigned char q[512];
        int ql;

        wire_pattern("vrchat.cloud", wire, sizeof(wire));
        ql = build_query(q, sizeof(q), "api.vrchat.cloud", 1);
        CHECK(ql > 0 && mem_find(q, ql, wire, (int)strlen(wire)) != NULL,
              "zone wire 'vrchat.cloud' found in api.vrchat.cloud query");

        wire_pattern("vrchat.com", wire, sizeof(wire));
        ql = build_query(q, sizeof(q), "www.vrchat.com", 1);
        CHECK(ql > 0 && mem_find(q, ql, wire, (int)strlen(wire)) != NULL,
              "zone wire 'vrchat.com' found in www.vrchat.com query");

        // what the OLD module put into --string: plain ASCII never matches
        ql = build_query(q, sizeof(q), "www.vrchat.com", 1);
        CHECK(mem_find(q, ql, "vrchat.com", 10) == NULL,
              "ASCII 'vrchat.com' absent from wire packet (old rules were dead)");

        // label-anchored: unrelated names must NOT trigger the zone rule
        ql = build_query(q, sizeof(q), "myvrchat.com", 1);
        CHECK(ql > 0 && mem_find(q, ql, wire, (int)strlen(wire)) == NULL,
              "unrelated 'myvrchat.com' does not match zone rule");
    }

    int baseline_children = child_count();

    // ── init / inject (non-root: iptables skipped, responder+relay must run) ──
    vrchat_module_init(NULL);
    vrchat_module_inject(-1);
    CHECK(strcmp(vrchat_get_status(), "Off") != 0, "status after inject: %s",
          vrchat_get_status());

    // ── responder answers from pin table ─────────────────────────────────
    printf("[TEST] DNS responder\n");
    expect_a("api.vrchat.cloud", "104.18.26.36", 0);      // exact pin
    expect_a("www.vrchat.com", "104.18.6.156", 0);        // exact pin
    expect_a("files.vrchat.cloud", "3.174.18.93", 0);     // exact pin
    expect_a("auth.vrchat.cloud", "104.18.26.36", 1);     // suffix zone (login!)
    expect_a("ANYTHING.vrchat.cloud", "104.18.26.36", 1); // unknown subdomain, zone suffix
    expect_a("sub.deep.vrchat.com", "104.18.6.156", 1);   // nested subdomain
    expect_a("docs.vrchat.com", "104.16.241.118", 1);     // exact pin beats suffix
    expect_a("API.VRCHAT.CLOUD", "104.18.26.36", 1);      // case-insensitive

    // AAAA on a pinned name: valid NOERROR, empty answer
    {
        unsigned char r[4096];
        int n = dns_query(28, "www.vrchat.com", r, sizeof(r));
        CHECK(n > 0 && resp_rcode(r, n) == 0 && resp_ancount(r, n) == 0,
              "www.vrchat.com AAAA -> NOERROR/empty");
    }

    // ── SNI-split relay up ───────────────────────────────────────────────
    CHECK(sni_relay_running() == 1, "sni_relay running (port 18444)");
    CHECK(port_alive(1, 18444), "relay port 18444 listening");

    // ── unknown (non-vrchat) queries are forwarded upstream, not dropped ─
    {
        unsigned char r[4096];
        char ip[64] = {0};
        int n = dns_query(1, "example.com", r, sizeof(r));
        int got = (n > 0) && resp_rcode(r, n) == 0 && resp_first_a(r, n, ip, sizeof(ip));
        if (got) printf("  ok   forward example.com -> %s\n", ip);
        else printf("  skip forward example.com (no network) — non-fatal\n");
    }

    // ── cleanup: ports must be released ──────────────────────────────────
    vrchat_module_cleanup();
    CHECK(strcmp(vrchat_get_status(), "Off") == 0, "status after cleanup: Off");
    CHECK(sni_relay_running() == 0, "relay stopped");
    CHECK(!port_alive(0, TEST_DNS_PORT), "responder port released");
    CHECK(!port_alive(1, 18444), "relay port released");

    // no stray children (responder/relay reaped by cleanup)
    {
        int after = child_count();
        CHECK(after == baseline_children,
              "no stray child processes (%d, baseline %d)", after, baseline_children);
    }

    printf(failed ? "[TEST] FAILED (%d)\n" : "[TEST] PASSED\n", failed);
    return failed ? 1 : 0;
}
