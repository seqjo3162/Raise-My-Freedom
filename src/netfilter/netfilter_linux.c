// Linux-бэкенд слоя netfilter: iptables + SO_MARK.
//
// Это перенос текущего поведения проекта без изменений: те же правила, тот же
// mark 0x4d50/0xfff0, тот же порядок команд. Файл подключается к сборке на
// Linux; на Windows вместо него линкуется netfilter_win.c.

#define _GNU_SOURCE
#include "netfilter.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define NF_MARK            0x4d50u
#define NF_MARK_MASK       0xfff0u
#define NF_DNS_CHAIN_LOGICAL "RMF_DNS"
#define NF_RUNTIME_DIR     "/run/rmf"
#define NF_REGISTRY        "/run/rmf/chains"
#define NF_MAX_CHAINS      64

static char g_chains[NF_MAX_CHAINS][64];
static int  g_chain_count = 0;

const char *nf_backend_name(void) { return "iptables"; }

bool nf_available(void) { return geteuid() == 0; }

const char *nf_registry_path(void) { return NF_REGISTRY; }

// Имена цепочек и адреса приходят от модулей, поэтому копируем их в буфер
// заранее заданного размера: иначе длинная строка молча портит команду.
static void bounded(char *dst, size_t size, const char *src) {
    if (!dst || size == 0) return;
    size_t n = src ? strlen(src) : 0;
    if (n >= size) n = size - 1;
    if (n) memcpy(dst, src, n);
    dst[n] = '\0';
}

static void run_cmd(const char *cmd) {
    int rc = system(cmd);
    (void)rc;
}

static int run_cmd_checked(const char *cmd) {
    return system(cmd);
}

// Реестр созданных цепочек: переживает перезапуск процесса, поэтому
// nf_cleanup_all() знает, что удалять, даже если вызывающий процесс новый.
static void registry_add(const char *chain) {
    if (!chain || !*chain) return;
    for (int i = 0; i < g_chain_count; i++)
        if (strcmp(g_chains[i], chain) == 0) return;
    if (g_chain_count >= NF_MAX_CHAINS) return;
    snprintf(g_chains[g_chain_count], sizeof(g_chains[0]), "%s", chain);
    g_chain_count++;
    mkdir(NF_RUNTIME_DIR, 0755);
    FILE *f = fopen(NF_REGISTRY, "a");
    if (!f) return;
    fprintf(f, "%s\n", chain);
    fclose(f);
}

static void registry_load(void) {
    if (g_chain_count > 0) return;
    FILE *f = fopen(NF_REGISTRY, "r");
    if (!f) return;
    char line[128];
    while (fgets(line, sizeof(line), f) && g_chain_count < NF_MAX_CHAINS) {
        size_t n = strlen(line);
        while (n && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = '\0';
        if (!n) continue;
        snprintf(g_chains[g_chain_count], sizeof(g_chains[0]), "%s", line);
        g_chain_count++;
    }
    fclose(f);
}

static void registry_remove(const char *chain) {
    registry_load();
    for (int i = 0; i < g_chain_count; i++) {
        if (strcmp(g_chains[i], chain) != 0) continue;
        for (int j = i; j < g_chain_count - 1; j++)
            memcpy(g_chains[j], g_chains[j + 1], sizeof(g_chains[0]));
        g_chain_count--;
        i--;
    }
    FILE *f = fopen(NF_REGISTRY, "w");
    if (!f) return;
    for (int i = 0; i < g_chain_count; i++) fprintf(f, "%s\n", g_chains[i]);
    fclose(f);
}

// iptables ждёт hex-шаблон в вертикальных чертах: "|0C686F...|". Без них
// правило молча не добавляется.
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

int nf_init(void) {
    if (getuid() != 0) return -1;
    registry_load();
    return 0;
}

void nf_shutdown(void) {}

int nf_chain_create(const char *chain) {
    if (getuid() != 0 || !chain) return -1;
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "iptables -t nat -N %s 2>/dev/null || true", chain);
    run_cmd(cmd);
    registry_add(chain);
    return 0;
}

int nf_chain_flush(const char *chain) {
    if (getuid() != 0 || !chain) return -1;
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "iptables -t nat -F %s 2>/dev/null || true", chain);
    run_cmd(cmd);
    return 0;
}

int nf_chain_destroy(const char *chain) {
    if (getuid() != 0 || !chain) return -1;
    // Модули могли вставить точку входа несколько раз, поэтому снимаем все
    // копии, а не одну: иначе после рестарта остаются хвосты правил.
    char cmd[512];
    for (int i = 0; i < 64; i++) {
        snprintf(cmd, sizeof(cmd), "iptables -t nat -D OUTPUT -j %s 2>/dev/null", chain);
        if (run_cmd_checked(cmd) != 0) break;
    }
    for (int i = 0; i < 64; i++) {
        snprintf(cmd, sizeof(cmd), "iptables -t nat -D PREROUTING -j %s 2>/dev/null", chain);
        if (run_cmd_checked(cmd) != 0) break;
    }
    snprintf(cmd, sizeof(cmd), "iptables -t nat -F %s 2>/dev/null || true; "
                                "iptables -t nat -X %s 2>/dev/null || true", chain, chain);
    run_cmd(cmd);
    registry_remove(chain);
    return 0;
}

int nf_hook_output(const char *chain, int pos) {
    if (getuid() != 0 || !chain) return -1;
    char cmd[512];
    if (pos > 0) {
        snprintf(cmd, sizeof(cmd),
                 "iptables -t nat -D OUTPUT -j %s 2>/dev/null || true; "
                 "iptables -t nat -I OUTPUT %d -j %s", chain, pos, chain);
    } else {
        snprintf(cmd, sizeof(cmd),
                 "iptables -t nat -D OUTPUT -j %s 2>/dev/null || true; "
                 "iptables -t nat -I OUTPUT 1 -j %s", chain, chain);
    }
    return run_cmd_checked(cmd);
}

int nf_hook_prerouting(const char *chain) {
    if (getuid() != 0 || !chain) return -1;
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "iptables -t nat -C PREROUTING -j %s 2>/dev/null || "
             "iptables -t nat -A PREROUTING -j %s", chain, chain);
    return run_cmd_checked(cmd);
}

int nf_exempt_own_traffic(const char *chain) {
    if (getuid() != 0 || !chain) return -1;
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "iptables -t nat -C %s -m mark --mark 0x%x/0x%x -j RETURN 2>/dev/null || "
             "iptables -t nat -I %s 1 -m mark --mark 0x%x/0x%x -j RETURN",
             chain, NF_MARK, NF_MARK_MASK, chain, NF_MARK, NF_MARK_MASK);
    return run_cmd_checked(cmd);
}

int nf_mark_socket_as(int fd, unsigned int mark) {
    if (fd < 0) return -1;
    return setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
}

int nf_mark_socket(int fd) {
    return nf_mark_socket_as(fd, NF_MARK);
}

// dest: адрес или CIDR. Правило идемпотентно: -C проверяет, -A добавляет.
static int rule_port(const char *chain, const char *proto, const char *dest,
                     int dport, int to_port, const char *target, bool cidr_ok) {
    if (getuid() != 0 || !chain || !proto || !dest) return -1;
    char cmd[1400], ch[64], d[128];
    bounded(ch, sizeof(ch), chain);
    bounded(d, sizeof(d), dest);
    if (cidr_ok && strchr(dest, '/')) {
        snprintf(cmd, sizeof(cmd),
                 "iptables -t nat -C %s -p %s -d %s --dport %d -j %s 2>/dev/null || "
                 "iptables -t nat -A %s -p %s -d %s --dport %d -j %s",
                 ch, proto, d, dport, target, ch, proto, d, dport, target);
    } else if (to_port > 0) {
        snprintf(cmd, sizeof(cmd),
                 "iptables -t nat -C %s -p %s -d %s --dport %d -j REDIRECT --to-ports %d 2>/dev/null || "
                 "iptables -t nat -A %s -p %s -d %s --dport %d -j REDIRECT --to-ports %d",
                 ch, proto, d, dport, to_port, ch, proto, d, dport, to_port);
    } else {
        snprintf(cmd, sizeof(cmd),
                 "iptables -t nat -C %s -p %s -d %s --dport %d -j %s 2>/dev/null || "
                 "iptables -t nat -A %s -p %s -d %s --dport %d -j %s",
                 ch, proto, d, dport, target, ch, proto, d, dport, target);
    }
    return run_cmd_checked(cmd);
}

int nf_tcp_redirect(const char *chain, const char *dest, int dport, int to_port) {
    return rule_port(chain, "tcp", dest, dport, to_port, "REDIRECT", true);
}

int nf_udp_redirect(const char *chain, const char *dest, int dport, int to_port) {
    return rule_port(chain, "udp", dest, dport, to_port, "REDIRECT", true);
}

int nf_tcp_deny(const char *chain, const char *dest, int dport) {
    return rule_port(chain, "tcp", dest, dport, -1, "DROP", true);
}

int nf_udp_deny(const char *chain, const char *dest, int dport) {
    return rule_port(chain, "udp", dest, dport, -1, "DROP", true);
}

int nf_dns_redirect(const char *chain, const char *domain, int to_port) {
    if (getuid() != 0 || !chain || !domain || !*domain) return -1;
    char hex[1100], pat[1104], cmd[3072], ch[64];
    if (wire_hex_pattern(domain, hex, sizeof(hex)) < 0) return -1;
    bounded(ch, sizeof(ch), chain);
    bounded(pat, sizeof(pat), hex);
    char quoted[1112];
    snprintf(quoted, sizeof(quoted), "|%s|", pat);
    snprintf(cmd, sizeof(cmd),
             "iptables -t nat -C %s -p udp --dport 53 -m string --algo bm --hex-string \"%s\" "
             "-j DNAT --to-destination 127.0.0.1:%d 2>/dev/null || "
             "iptables -t nat -A %s -p udp --dport 53 -m string --algo bm --hex-string \"%s\" "
             "-j DNAT --to-destination 127.0.0.1:%d",
             ch, quoted, to_port, ch, quoted, to_port);
    return run_cmd_checked(cmd);
}

int nf_dns_redirect_all(const char *chain, int to_port) {
    if (getuid() != 0 || !chain) return -1;
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "iptables -t nat -C %s -p udp --dport 53 -j DNAT --to-destination 127.0.0.1:%d 2>/dev/null || "
             "iptables -t nat -A %s -p udp --dport 53 -j DNAT --to-destination 127.0.0.1:%d",
             chain, to_port, chain, to_port);
    return run_cmd_checked(cmd);
}

int nf_cleanup_all(void) {
    if (getuid() != 0) return -1;
    registry_load();
    for (int i = 0; i < g_chain_count; i++) {
        char cmd[512], ch[64];
        bounded(ch, sizeof(ch), g_chains[i]);
        snprintf(cmd, sizeof(cmd), "iptables -t nat -D OUTPUT -j %s 2>/dev/null || true; "
                                    "iptables -t nat -D PREROUTING -j %s 2>/dev/null || true; "
                                    "iptables -t nat -F %s 2>/dev/null || true; "
                                    "iptables -t nat -X %s 2>/dev/null || true",
                 ch, ch, ch, ch);
        run_cmd(cmd);
    }
    unlink(NF_REGISTRY);
    g_chain_count = 0;
    return 0;
}
