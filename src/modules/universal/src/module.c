#include "src/modules/universal/include/universal.h"
#include "src/dns/dns_resolve.h"
#include "src/dns/doh_resolve.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <signal.h>
#include <poll.h>

static universal_ctx_t ctx = {0};
static int packet_count = 0;
static volatile int proxy_running = 0;
static pthread_t proxy_thread_id;
static int proxy_thread_started;

#define MAX_REGISTERED_DOMAINS 256
#define MAX_DOMAIN_LEN 256
#define MAX_UPSTREAM_LEN 32
#define UNIVERSAL_SO_MARK 0x4d73

static struct {
    char domain[MAX_DOMAIN_LEN];
    char upstream[MAX_UPSTREAM_LEN];
} domain_registry[MAX_REGISTERED_DOMAINS];

static int domain_count = 0;

static void run_command(const char *cmd) {
    int rc = system(cmd);
    (void)rc;
}

static int wire_hex_pattern(const char *domain, char *out, size_t out_size) {
    if (!domain || !out || out_size == 0) return -1;
    size_t used = 0;
    const char *s = domain;
    while (*s) {
        const char *dot = strchr(s, '.');
        size_t len = dot ? (size_t)(dot - s) : strlen(s);
        if (len == 0 || len > 63) return -1;
        char label[8];
        int n = snprintf(label, sizeof(label), "%02X", (unsigned char)len);
        if (n < 0 || used + (size_t)n >= out_size) return -1;
        memcpy(out + used, label, (size_t)n);
        used += (size_t)n;
        for (size_t i = 0; i < len; i++) {
            n = snprintf(out + used, out_size - used, "%02X", (unsigned char)s[i]);
            if (n < 0 || used + (size_t)n >= out_size) return -1;
            used += (size_t)n;
        }
        if (!dot) break;
        s += len + 1;
    }
    out[used] = '\0';
    return (int)used;
}

static void extract_domain(const unsigned char *query, int len, char *out, int out_len) {
    if (len < 13 || !out || out_len <= 0) { if (out_len > 0) out[0] = '\0'; return; }
    int off = 12, pos = 0;
    while (off < len && query[off] != 0 && pos < out_len - 1) {
        int ll = query[off];
        if ((ll & 0xC0) == 0xC0) break;
        off++;
        if (pos > 0 && pos < out_len - 1) out[pos++] = '.';
        for (int i = 0; i < ll && off < len && pos < out_len - 1; i++)
            out[pos++] = (char)query[off++];
    }
    out[pos] = '\0';
}

static int build_a_response(const unsigned char *query, int query_len,
                             unsigned char *response, int response_len,
                             const char *ip) {
    if (query_len < 13 || response_len < 512) return -1;
    int off = 12;
    while (off < query_len && query[off] != 0) {
        int label = query[off++];
        if ((label & 0xc0) == 0xc0 || label == 0 || label > 63 ||
            off + label >= query_len) return -1;
        off += label;
    }
    if (off >= query_len) return -1;
    off++;
    if (off + 4 > query_len || off + 28 > response_len) return -1;
    memcpy(response, query, (size_t)(off + 4));
    response[2] = 0x81;
    response[3] = 0x80;
    response[6] = 0;
    response[7] = 1;
    response[8] = 0;
    response[9] = 0;
    response[10] = 0;
    response[11] = 0;
    int out = off + 4;
    response[out++] = 0xc0;
    response[out++] = 0x0c;
    response[out++] = 0;
    response[out++] = 1;
    response[out++] = 0;
    response[out++] = 1;
    response[out++] = 0;
    response[out++] = 0;
    response[out++] = 0;
    response[out++] = 120;
    response[out++] = 0;
    response[out++] = 4;
    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) != 1) return -1;
    memcpy(response + out, &addr, 4);
    return out + 4;
}

static int extract_qtype(const unsigned char *query, int len) {
    if (!query || len < 13) return -1;
    int off = 12;
    while (off < len && query[off] != 0) {
        int label = query[off++];
        if ((label & 0xc0) == 0xc0 || label == 0 || label > 63 || off + label >= len)
            return -1;
        off += label;
    }
    if (off + 5 > len) return -1;
    return (query[off + 1] << 8) | query[off + 2];
}

static const char *find_upstream(const char *domain) {
    if (!domain) return ctx.default_upstream;
    for (int i = 0; i < domain_count; i++)
        if (strcasecmp(domain_registry[i].domain, domain) == 0)
            return domain_registry[i].upstream;
    for (int i = 0; i < domain_count; i++) {
        const char *reg = domain_registry[i].domain;
        size_t rlen = strlen(reg), dlen = strlen(domain);
        if (dlen > rlen && domain[dlen - rlen - 1] == '.')
            if (strcasecmp(domain + dlen - rlen, reg) == 0)
                return domain_registry[i].upstream;
    }
    return ctx.default_upstream;
}

static int forward_to_upstream(const unsigned char *query, int qlen,
                               unsigned char *resp, int rlen,
                               const char *upstream) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    unsigned int mark = UNIVERSAL_SO_MARK;
    setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
    struct timeval tv = {3, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(53);
    if (inet_pton(AF_INET, upstream, &dst.sin_addr) != 1) { close(fd); return -1; }
    if (sendto(fd, query, (size_t)qlen, 0, (struct sockaddr *)&dst, sizeof(dst)) != qlen) {
        close(fd); return -1;
    }
    ssize_t n = recvfrom(fd, resp, (size_t)rlen, 0, NULL, NULL);
    close(fd);
    if (n >= 12 && (resp[0] != query[0] || resp[1] != query[1])) return -1;
    return (int)n;
}

static int build_servfail(const unsigned char *query, int qlen,
                          unsigned char *resp, int rlen) {
    if (!query || !resp || qlen < 12 || rlen < 12) return -1;
    int n = qlen < rlen ? qlen : rlen;
    memcpy(resp, query, (size_t)n);
    resp[2] = (unsigned char)(0x80 | 0x02);
    resp[3] = (unsigned char)(resp[3] & 0x00);
    resp[6] = 0; resp[7] = 0;
    resp[8] = 0; resp[9] = 0;
    return n;
}

typedef struct {
    unsigned char query[512];
    int qlen;
    struct sockaddr_in client;
    socklen_t clen;
} dns_job_t;

static volatile int inflight = 0;

#define DNS_MAX_INFLIGHT 64

static int resolve_and_reply(const unsigned char *query, int qlen,
                             unsigned char *response, int rlen,
                             char *domain_out, size_t domain_size) {
    char domain[MAX_DOMAIN_LEN];
    extract_domain(query, qlen, domain, sizeof(domain));
    if (domain_out && domain_size) snprintf(domain_out, domain_size, "%s", domain);
    const char *upstream = find_upstream(domain);
    int r = -1;
    if (extract_qtype(query, qlen) == 1) {
        char doh_ip[64] = {0};
        if (doh_resolve_a(domain, doh_ip, sizeof(doh_ip)) == 0)
            r = build_a_response(query, qlen, response, rlen, doh_ip);
    }
    if (r < 12) r = forward_to_upstream(query, qlen, response, rlen, upstream);
    if (r < 12) {
        const char *fb = (strcmp(upstream, "8.8.8.8") == 0) ? "1.1.1.1" : "8.8.8.8";
        r = forward_to_upstream(query, qlen, response, rlen, fb);
    }
    if (r < 12) r = build_servfail(query, qlen, response, rlen);
    return r;
}

static void *dns_worker(void *arg) {
    dns_job_t *job = (dns_job_t *)arg;
    unsigned char response[512];
    char domain[MAX_DOMAIN_LEN] = {0};
    packet_count++;
    int rlen = resolve_and_reply(job->query, job->qlen, response, sizeof(response),
                                 domain, sizeof(domain));
    if (rlen < 12) {
        fprintf(stderr, "[UNIVERSAL] FAIL: %s\n", domain);
    } else {
        sendto(ctx.socket_fd, response, (size_t)rlen, 0,
               (struct sockaddr *)&job->client, job->clen);
    }
    free(job);
    __sync_fetch_and_sub(&inflight, 1);
    return NULL;
}

static void *dns_proxy_thread(void *arg) {
    (void)arg;
    while (proxy_running) {
        struct pollfd pfd = { .fd = ctx.socket_fd, .events = POLLIN };
        int ready = poll(&pfd, 1, 500);
        if (ready <= 0) continue;
        dns_job_t *job = calloc(1, sizeof(*job));
        if (!job) continue;
        ssize_t n = recvfrom(ctx.socket_fd, job->query, sizeof(job->query), 0,
                             (struct sockaddr *)&job->client, &job->clen);
        if (n < 12) { free(job); continue; }
        job->qlen = (int)n;
        __sync_fetch_and_add(&inflight, 1);
        pthread_t tid;
        if (__sync_fetch_and_add(&inflight, 0) < DNS_MAX_INFLIGHT &&
            pthread_create(&tid, NULL, dns_worker, job) == 0) {
            pthread_detach(tid);
        } else {
            dns_worker(job);
        }
    }
    return NULL;
}

static void refresh_dns_rules(void) {
    if (getuid() != 0) return;
    char hex[1100], pat[1104], cmd[4096];
    run_command("iptables -t nat -F RMF_DNS 2>/dev/null");
    run_command("iptables -t nat -N RMF_DNS 2>/dev/null");
    run_command("iptables -t nat -A RMF_DNS -m mark --mark 0x4d50/0xfff0 -j RETURN");
    for (int i = 0; i < domain_count; i++) {
        if (wire_hex_pattern(domain_registry[i].domain, hex, sizeof(hex)) < 0) continue;
        snprintf(pat, sizeof(pat), "|%s|", hex);
        snprintf(cmd, sizeof(cmd),
                 "iptables -t nat -A RMF_DNS -p udp --dport 53 -m string --algo bm "
                 "--hex-string \"%s\" -j DNAT --to-destination 127.0.0.1:%d",
                 pat, ctx.listen_port);
        run_command(cmd);
    }
    run_command("iptables -t nat -A RMF_DNS -j RETURN");
    run_command("iptables -t nat -C OUTPUT -p udp --dport 53 -j RMF_DNS 2>/dev/null || "
                "iptables -t nat -I OUTPUT -p udp --dport 53 -j RMF_DNS");
    run_command("iptables -t nat -C PREROUTING -p udp --dport 53 -j RMF_DNS 2>/dev/null || "
                "iptables -t nat -A PREROUTING -p udp --dport 53 -j RMF_DNS");
    printf("[UNIVERSAL] iptables: %d domains -> 127.0.0.1:%d\n", domain_count, ctx.listen_port);
}

static void setup_iptables_redirect(void) {
    refresh_dns_rules();
}

static void cleanup_iptables_redirect(void) {
    if (getuid() != 0) return;
    run_command("iptables -t nat -D OUTPUT -p udp --dport 53 -j RMF_DNS 2>/dev/null");
    run_command("iptables -t nat -D PREROUTING -p udp --dport 53 -j RMF_DNS 2>/dev/null");
    run_command("iptables -t nat -F RMF_DNS 2>/dev/null");
    run_command("iptables -t nat -X RMF_DNS 2>/dev/null");
    printf("[UNIVERSAL] iptables: cleanup done\n");
}

void universal_module_init(universal_config_t *config) {
    (void)config;
    if (proxy_running) return; // already running

    printf("[UNIVERSAL] Initializing DNS proxy...\n");
    ctx.socket_fd = -1;
    snprintf(ctx.default_upstream, sizeof(ctx.default_upstream), "%s", "1.1.1.1");
    ctx.listen_port = 53;

    ctx.socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctx.socket_fd < 0) { fprintf(stderr, "[UNIVERSAL] socket: %s\n", strerror(errno)); return; }

    int reuse = 1;
    setsockopt(ctx.socket_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(0);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (bind(ctx.socket_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        fprintf(stderr, "[UNIVERSAL] bind: %s\n", strerror(errno));
        close(ctx.socket_fd);
        ctx.socket_fd = -1;
        return;
    }
    socklen_t alen = sizeof(addr);
    if (getsockname(ctx.socket_fd, (struct sockaddr *)&addr, &alen) == 0)
        ctx.listen_port = ntohs(addr.sin_port);
    printf("[UNIVERSAL] Listening on 127.0.0.1:%d\n", ctx.listen_port);

    proxy_running = 1;
    if (pthread_create(&proxy_thread_id, NULL, dns_proxy_thread, NULL) != 0) {
        fprintf(stderr, "[UNIVERSAL] pthread: %s\n", strerror(errno));
        close(ctx.socket_fd);
        ctx.socket_fd = -1;
        proxy_running = 0;
        return;
    }
    proxy_thread_started = 1;

    // Setup iptables and resolv.conf (requires root)
    if (getuid() == 0) {
        setup_iptables_redirect();
    } else {
        printf("[UNIVERSAL] Not root — manual setup needed:\n");
        printf("  sudo resolvectl dns %s 127.0.0.1  OR  echo 'nameserver 127.0.0.1' | sudo tee /etc/resolv.conf\n",
               getenv("DEVICE") ? getenv("DEVICE") : "eth0");
    }

    packet_count = 0;
    domain_count = 0;
}

void universal_module_cleanup(void) {
    proxy_running = 0;
    if (ctx.socket_fd >= 0) {
        shutdown(ctx.socket_fd, SHUT_RDWR);
    }
    if (proxy_thread_started) {
        pthread_join(proxy_thread_id, NULL);
        proxy_thread_started = 0;
    }
    if (ctx.socket_fd >= 0) {
        close(ctx.socket_fd);
        ctx.socket_fd = -1;
    }
    if (getuid() == 0) {
        cleanup_iptables_redirect();
    }
    printf("[UNIVERSAL] Cleaned up (%d queries, %d domains)\n", packet_count, domain_count);
    domain_count = 0;
}

uint32_t universal_get_packet_count(void) { return (uint32_t)packet_count; }

const char *universal_get_status(void) {
    if (!proxy_running || ctx.socket_fd < 0) return "Off";
    return "Active (DNS proxy)";
}

int universal_process_dns(const unsigned char *buffer, uint16_t len) {
    if (!buffer || len < 12) return -1;
    unsigned char resp[512];
    char domain[MAX_DOMAIN_LEN];
    extract_domain(buffer, len, domain, sizeof(domain));
    const char *upstream = find_upstream(domain);
    int rlen = -1;
    if (extract_qtype(buffer, len) == 1) {
        char doh_ip[64] = {0};
        if (doh_resolve_a(domain, doh_ip, sizeof(doh_ip)) == 0)
            rlen = build_a_response(buffer, len, resp, sizeof(resp), doh_ip);
    }
    if (rlen < 12)
        rlen = forward_to_upstream(buffer, len, resp, sizeof(resp), upstream);
    return rlen >= 12 ? 0 : -1;
}

int universal_register_domain(const char *domain, const char *upstream_dns) {
    if (!domain || !upstream_dns) return -1;
    if (domain_count >= MAX_REGISTERED_DOMAINS) return -1;
    for (int i = 0; i < domain_count; i++) {
        if (strcasecmp(domain_registry[i].domain, domain) == 0) {
            snprintf(domain_registry[i].upstream, sizeof(domain_registry[i].upstream), "%s", upstream_dns);
            refresh_dns_rules();
            return 0;
        }
    }
    snprintf(domain_registry[domain_count].domain, sizeof(domain_registry[domain_count].domain), "%s", domain);
    snprintf(domain_registry[domain_count].upstream, sizeof(domain_registry[domain_count].upstream), "%s", upstream_dns);
    domain_count++;
    return 0;
}

int universal_unregister_domain(const char *domain) {
    if (!domain) return -1;
    for (int i = 0; i < domain_count; i++) {
        if (strcasecmp(domain_registry[i].domain, domain) == 0) {
            domain_registry[i] = domain_registry[domain_count - 1];
            domain_count--;
            return 0;
        }
    }
    return -1;
}

int universal_get_domain_count(void) { return domain_count; }
