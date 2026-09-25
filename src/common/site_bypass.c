#define _GNU_SOURCE
#include "src/common/site_bypass.h"
#include "src/dns/dns_resolve.h"
#include "src/dns/doh_resolve.h"
#include "src/common/sni_relay.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_SITE_DOMAINS 64
#define DNS_READY_TIMEOUT_MS 2000

typedef struct {
    char domain[256];
    char ip[64];
} site_pin_t;

static site_pin_t site_pins[MAX_SITE_DOMAINS];
static int site_pin_count;
static int (*site_ip_validator)(const char *ip);
static const char *site_fallback_ips[16];
static size_t site_fallback_count;

static int site_ip_allowed(const char *ip) {
    struct in_addr parsed;
    if (!ip || inet_pton(AF_INET, ip, &parsed) != 1) return 0;
    return !site_ip_validator || site_ip_validator(ip);
}

static int run_cmd(const char *cmd) {
    return system(cmd);
}

static int valid_token(const char *value) {
    if (!value || !*value || strlen(value) > 63) return 0;
    for (const unsigned char *p = (const unsigned char *)value; *p; p++)
        if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
            (*p >= '0' && *p <= '9') || *p == '_' || *p == '-')
            continue;
        else
            return 0;
    return 1;
}

static void normalize_domain(const char *input, char *out, size_t out_size) {
    if (!input || !out || out_size == 0) return;
    snprintf(out, out_size, "%s", input);
    size_t len = strlen(out);
    while (len > 0 && out[len - 1] == '.') out[--len] = '\0';
}

static int domain_matches(const char *query, const char *base) {
    if (!query || !base) return 0;
    size_t qlen = strlen(query);
    size_t blen = strlen(base);
    if (strcasecmp(query, base) == 0) return 1;
    return qlen > blen && query[qlen - blen - 1] == '.' &&
           strcasecmp(query + qlen - blen, base) == 0;
}

static const char *lookup_pin(const char *domain) {
    for (int i = 0; i < site_pin_count; i++)
        if (domain_matches(domain, site_pins[i].domain)) return site_pins[i].ip;
    return NULL;
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

static void iptables_add_dns_rule(const site_bypass_state_t *state, const char *domain) {
    if (getuid() != 0 || !state || !domain) return;
    char hex[1100], cmd[4096];
    if (wire_hex_pattern(domain, hex, sizeof(hex)) < 0) return;
    snprintf(cmd, sizeof(cmd),
             "iptables -t nat -C %s -p udp --dport 53 -m string --algo bm --hex-string \"%s\" "
             "-j DNAT --to-destination 127.0.0.1:%d 2>/dev/null || "
             "iptables -t nat -A %s -p udp --dport 53 -m string --algo bm --hex-string \"%s\" "
             "-j DNAT --to-destination 127.0.0.1:%d",
             state->chain, hex, state->dns_port, state->chain, hex, state->dns_port);
    run_cmd(cmd);
}

static void iptables_add_redirect(const site_bypass_state_t *state, const char *ip) {
    if (getuid() != 0 || !state || !ip) return;
    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) != 1) return;
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "iptables -t nat -C %s -p tcp -d %s --dport 443 "
             "-j REDIRECT --to-ports %d 2>/dev/null || "
             "iptables -t nat -A %s -p tcp -d %s --dport 443 "
             "-j REDIRECT --to-ports %d",
             state->chain, ip, state->relay_port, state->chain, ip, state->relay_port);
    run_cmd(cmd);
}

static void iptables_install(site_bypass_state_t *state, const site_bypass_config_t *config) {
    if (getuid() != 0 || !state || !config) return;
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "iptables -t nat -N %s 2>/dev/null || true; "
             "iptables -t nat -C %s -m mark --mark 0x4d50/0xfff0 -j RETURN 2>/dev/null || "
             "iptables -t nat -I %s 1 -m mark --mark 0x4d50/0xfff0 -j RETURN; "
             "iptables -t nat -D OUTPUT -j %s 2>/dev/null || true; "
             "iptables -t nat -I OUTPUT 1 -j %s",
             state->chain, state->chain, state->chain, state->chain, state->chain);
    run_cmd(cmd);
    for (size_t i = 0; i < config->domain_count; i++) {
        if (!config->domains || !config->domains[i]) continue;
        char domain[256];
        normalize_domain(config->domains[i], domain, sizeof(domain));
        if (domain[0]) iptables_add_dns_rule(state, domain);
    }
    for (int i = 0; i < site_pin_count; i++) iptables_add_redirect(state, site_pins[i].ip);
    state->rules_installed = true;
}

static void iptables_remove(site_bypass_state_t *state) {
    if (getuid() != 0 || !state || !state->chain[0]) return;
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "iptables -t nat -D OUTPUT -j %s 2>/dev/null", state->chain);
    while (run_cmd(cmd) == 0) {}
    snprintf(cmd, sizeof(cmd), "iptables -t nat -F %s 2>/dev/null", state->chain);
    run_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "iptables -t nat -X %s 2>/dev/null", state->chain);
    run_cmd(cmd);
    state->rules_installed = false;
}

static int extract_qname(const unsigned char *pkt, int len, char *out, int out_size) {
    if (!pkt || len < 13 || !out || out_size < 2) return -1;
    int pos = 12, used = 0;
    while (pos < len && pkt[pos] != 0) {
        int label = pkt[pos++];
        if ((label & 0xc0) == 0xc0 || label == 0 || label > 63) return -1;
        if (pos + label > len || used + label + 2 >= out_size) return -1;
        if (used > 0) out[used++] = '.';
        memcpy(out + used, pkt + pos, (size_t)label);
        used += label;
        pos += label;
    }
    if (pos >= len || pkt[pos] != 0) return -1;
    out[used] = '\0';
    return used;
}

static int skip_qname(const unsigned char *pkt, int len) {
    if (!pkt || len < 13) return -1;
    int pos = 12;
    while (pos < len && pkt[pos] != 0) {
        int label = pkt[pos++];
        if ((label & 0xc0) == 0xc0) return pos + 1 < len ? pos + 1 : -1;
        if (label == 0 || label > 63 || pos + label > len) return -1;
        pos += label;
    }
    return pos < len ? pos + 1 : -1;
}

static int build_a_response(const unsigned char *query, int query_len,
                            unsigned char *response, int response_size,
                            const char *ip) {
    int qname_end = skip_qname(query, query_len);
    if (qname_end < 0 || qname_end + 4 > query_len || qname_end + 4 + 24 > response_size)
        return -1;
    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) != 1) return -1;
    memcpy(response, query, (size_t)(qname_end + 4));
    response[2] = 0x81;
    response[3] = 0x80;
    response[4] = 0;
    response[5] = 1;
    response[6] = 0;
    response[7] = 1;
    response[8] = 0;
    response[9] = 0;
    response[10] = 0;
    response[11] = 0;
    int out = qname_end + 4;
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
    memcpy(response + out, &addr, 4);
    return out + 4;
}

static int build_empty_response(const unsigned char *query, int query_len,
                                unsigned char *response, int response_size) {
    int qname_end = skip_qname(query, query_len);
    if (qname_end < 0 || qname_end + 4 > query_len || qname_end + 4 > response_size)
        return -1;
    memcpy(response, query, (size_t)(qname_end + 4));
    response[2] = 0x81;
    response[3] = 0x80;
    response[4] = 0;
    response[5] = 1;
    response[6] = 0;
    response[7] = 0;
    response[8] = 0;
    response[9] = 0;
    response[10] = 0;
    response[11] = 0;
    return qname_end + 4;
}

static int forward_query(const unsigned char *query, int query_len,
                         unsigned char *response, int response_size,
                         const site_bypass_state_t *state) {
    const char *servers[2] = {state->primary, state->fallback};
    for (int i = 0; i < 2; i++) {
        if (!servers[i] || !servers[i][0]) continue;
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) continue;
        unsigned int mark = state->mark;
        setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
        struct sockaddr_in destination = {0};
        destination.sin_family = AF_INET;
        destination.sin_port = htons(53);
        if (inet_pton(AF_INET, servers[i], &destination.sin_addr) != 1 ||
            sendto(fd, query, (size_t)query_len, 0,
                   (struct sockaddr *)&destination, sizeof(destination)) != query_len) {
            close(fd);
            continue;
        }
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int result = poll(&pfd, 1, 2000);
        int length = -1;
        if (result > 0 && (pfd.revents & POLLIN)) {
            ssize_t received = recvfrom(fd, response, (size_t)response_size, 0, NULL, NULL);
            if (received >= 12 && response[0] == query[0] && response[1] == query[1])
                length = (int)received;
        }
        close(fd);
        if (length > 0) return length;
    }
    return -1;
}

static void dns_child(site_bypass_state_t *state, int ready_fd) {
    prctl(PR_SET_PDEATHSIG, SIGTERM);
    if (getppid() == 1) _exit(0);
    setsid();
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, SIG_DFL);
    signal(SIGCHLD, SIG_DFL);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) _exit(1);
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons((uint16_t)state->dns_port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) != 0) _exit(2);
    if (ready_fd >= 0) {
        char ok = 1;
        if (write(ready_fd, &ok, 1) != 1) _exit(3);
        close(ready_fd);
    }

    unsigned char query[4096], response[4096];
    while (1) {
        struct sockaddr_in client;
        socklen_t client_len = sizeof(client);
        ssize_t received = recvfrom(fd, query, sizeof(query), 0,
                                    (struct sockaddr *)&client, &client_len);
        if (received < 13) continue;
        char domain[256];
        if (extract_qname(query, (int)received, domain, sizeof(domain)) < 0) continue;
        int qname_end = skip_qname(query, (int)received);
        if (qname_end < 0 || qname_end + 1 >= received) continue;
        int qtype = (query[qname_end] << 8) | query[qname_end + 1];
        const char *ip = lookup_pin(domain);
        int response_len = -1;
        if (ip && qtype == 1) {
            response_len = build_a_response(query, (int)received, response,
                                            sizeof(response), ip);
        } else if (ip) {
            response_len = build_empty_response(query, (int)received, response,
                                                sizeof(response));
        } else {
            response_len = forward_query(query, (int)received, response,
                                         sizeof(response), state);
        }
        if (response_len > 0)
            sendto(fd, response, (size_t)response_len, 0,
                   (struct sockaddr *)&client, client_len);
    }
}

static int dns_start(site_bypass_state_t *state) {
    int ready[2];
    if (pipe2(ready, O_CLOEXEC) < 0) return -1;
    pid_t pid = fork();
    if (pid < 0) {
        close(ready[0]);
        close(ready[1]);
        return -1;
    }
    if (pid == 0) {
        close(ready[0]);
        dns_child(state, ready[1]);
        _exit(0);
    }
    close(ready[1]);
    char ok = 0;
    struct pollfd pfd = { .fd = ready[0], .events = POLLIN };
    int result = poll(&pfd, 1, DNS_READY_TIMEOUT_MS);
    ssize_t got = result > 0 ? read(ready[0], &ok, 1) : 0;
    close(ready[0]);
    if (got != 1 || ok != 1) {
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
        return -1;
    }
    state->dns_pid = pid;
    return 0;
}

static void dns_stop(site_bypass_state_t *state) {
    if (!state || state->dns_pid <= 0) return;
    pid_t pid = state->dns_pid;
    state->dns_pid = 0;
    kill(pid, SIGTERM);
    for (int i = 0; i < 20; i++) {
        if (waitpid(pid, NULL, WNOHANG) == pid) return;
        usleep(50000);
    }
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
}

int site_bypass_start(site_bypass_state_t *state, const site_bypass_config_t *config) {
    if (!state || !config || !valid_token(config->chain) || !config->domains ||
        config->domain_count == 0 || config->domain_count > MAX_SITE_DOMAINS ||
        config->dns_port <= 1024 || config->dns_port > 65535 ||
        config->relay_port <= 1024 || config->relay_port > 65535 ||
        config->dns_port == config->relay_port) return -1;
    if (state->active || state->dns_pid > 0) site_bypass_stop(state);
    memset(state, 0, sizeof(*state));
    snprintf(state->primary, sizeof(state->primary), "%s",
             config->primary_dns && *config->primary_dns ? config->primary_dns : "1.1.1.1");
    snprintf(state->fallback, sizeof(state->fallback), "%s",
             config->fallback_dns && *config->fallback_dns ? config->fallback_dns : "8.8.8.8");
    snprintf(state->chain, sizeof(state->chain), "%s", config->chain);
    state->dns_port = config->dns_port;
    state->relay_port = config->relay_port;
    state->mark = config->mark;
    state->dns_fd = -1;
    site_pin_count = 0;
    site_ip_validator = config->validate_ip;
    site_fallback_count = config->fallback_count < 16 ? config->fallback_count : 16;
    for (size_t i = 0; i < site_fallback_count; i++)
        site_fallback_ips[i] = config->fallback_ips ? config->fallback_ips[i] : NULL;

    for (size_t i = 0; i < config->domain_count && site_pin_count < MAX_SITE_DOMAINS; i++) {
        if (!config->domains[i]) continue;
        char domain[256], ip[64] = {0};
        normalize_domain(config->domains[i], domain, sizeof(domain));
        if (!domain[0]) continue;
        int resolved = 0;
        if (doh_resolve_a(domain, ip, sizeof(ip)) == 0 && site_ip_allowed(ip))
            resolved = 1;
        if (!resolved && dns_resolve_udp(state->primary, domain, ip, sizeof(ip)) == 0 &&
            site_ip_allowed(ip))
            resolved = 1;
        if (!resolved && dns_resolve_udp(state->fallback, domain, ip, sizeof(ip)) == 0 &&
            site_ip_allowed(ip))
            resolved = 1;
        if (!resolved) ip[0] = '\0';
        for (size_t j = 0; !site_ip_allowed(ip) && j < site_fallback_count; j++) {
            if (site_fallback_ips[j] && strlen(site_fallback_ips[j]) < sizeof(ip))
                snprintf(ip, sizeof(ip), "%s", site_fallback_ips[j]);
        }
        if (!site_ip_allowed(ip)) continue;
        snprintf(site_pins[site_pin_count].domain,
                 sizeof(site_pins[site_pin_count].domain), "%s", domain);
        snprintf(site_pins[site_pin_count].ip,
                 sizeof(site_pins[site_pin_count].ip), "%s", ip);
        site_pin_count++;
    }
    if (site_pin_count == 0) return -1;
    if (dns_start(state) != 0) return -1;

    iptables_install(state, config);
    sni_relay_config_t relay = {
        .port = state->relay_port,
        .so_mark = state->mark,
        .frag_delay_ms = 30,
        .frag_first_seg = 20,
        .primary_dns = state->primary,
        .fallback_dns = state->fallback,
        .validate_ip = config->validate_ip,
        .fallback_ips = config->fallback_ips,
        .fallback_count = config->fallback_count,
    };
    if (sni_relay_start(&relay) != 0) {
        site_bypass_stop(state);
        return -1;
    }
    state->active = true;
    return 0;
}

void site_bypass_stop(site_bypass_state_t *state) {
    if (!state) return;
    if (state->rules_installed || state->chain[0]) iptables_remove(state);
    dns_stop(state);
    sni_relay_stop();
    state->active = false;
    state->rules_installed = false;
    state->dns_fd = -1;
    site_pin_count = 0;
    site_ip_validator = NULL;
    site_fallback_count = 0;
    memset(site_fallback_ips, 0, sizeof(site_fallback_ips));
}

int site_bypass_active(const site_bypass_state_t *state) {
    return state && state->active && state->dns_pid > 0 && sni_relay_running();
}
