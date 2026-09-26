#include "src/dns/doh_resolve.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>

// Minimal DoH client: UDP DNS query -> base64url GET to https://1.1.1.1/dns-query
// Uses fork+exec of curl to avoid pulling OpenSSL into the core binary.

static const char b64url[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static void b64url_encode(const unsigned char *in, int inlen, char *out, int outcap) {
    int o = 0;
    for (int i = 0; i < inlen && o + 4 < outcap; i += 3) {
        unsigned v = in[i] << 16;
        if (i + 1 < inlen) v |= in[i + 1] << 8;
        if (i + 2 < inlen) v |= in[i + 2];
        out[o++] = b64url[(v >> 18) & 63];
        out[o++] = b64url[(v >> 12) & 63];
        if (i + 1 < inlen) out[o++] = b64url[(v >> 6) & 63];
        else break;
        if (i + 2 < inlen) out[o++] = b64url[v & 63];
        else break;
    }
    out[o] = '\0';
}

static int build_query(const char *domain, unsigned char *pkt, int cap) {
    if (cap < 32) return -1;
    memset(pkt, 0, (size_t)cap);
    pkt[0] = 0xAB; pkt[1] = 0xCD;
    pkt[2] = 0x01; pkt[3] = 0x00;
    pkt[4] = 0x00; pkt[5] = 0x01;
    unsigned char *p = pkt + 12;
    const char *s = domain;
    while (*s) {
        const char *dot = strchr(s, '.');
        int ll = dot ? (int)(dot - s) : (int)strlen(s);
        if (ll <= 0 || ll > 63 || (p - pkt) + ll + 6 >= cap) return -1;
        *p++ = (unsigned char)ll;
        memcpy(p, s, (size_t)ll);
        p += ll;
        s += ll + (dot ? 1 : 0);
        if (!dot) break;
    }
    *p++ = 0;
    *p++ = 0; *p++ = 1;
    *p++ = 0; *p++ = 1;
    return (int)(p - pkt);
}

// Собирает все A-записи ответа, а не только первую: у сайтов за Cloudflare и
// CloudFront их обычно несколько, и первая нередко оказывается недостижимой
// именно с этой сети.
static int parse_a_list(const unsigned char *resp, int n, char out[][64],
                        int max, int *count) {
    if (n < 12) return -1;
    int ancount = (resp[6] << 8) | resp[7];
    if (ancount <= 0) return -1;
    *count = 0;
    int off = 12;
    while (off < n && resp[off] != 0) {
        if ((resp[off] & 0xC0) == 0xC0) { off += 2; break; }
        off += resp[off] + 1;
    }
    if (off < n && resp[off] == 0) off++;
    off += 4;
    while (off + 10 < n && *count < max) {
        if ((resp[off] & 0xC0) == 0xC0) off += 2;
        else {
            while (off < n && resp[off] != 0 && (resp[off] & 0xC0) != 0xC0)
                off += resp[off] + 1;
            if (off < n && resp[off] == 0) off++;
            else if (off < n) off += 2;
        }
        if (off + 10 > n) break;
        int type = (resp[off] << 8) | resp[off + 1];
        int rdlen = (resp[off + 8] << 8) | resp[off + 9];
        off += 10;
        if (type == 1 && rdlen == 4 && off + 4 <= n) {
            int dup = 0;
            for (int i = 0; i < *count; i++) {
                char tmp[64];
                snprintf(tmp, sizeof(tmp), "%u.%u.%u.%u",
                         resp[off], resp[off + 1], resp[off + 2], resp[off + 3]);
                if (strcmp(out[i], tmp) == 0) dup = 1;
            }
            if (!dup)
                snprintf(out[(*count)++], 64, "%u.%u.%u.%u",
                         resp[off], resp[off + 1], resp[off + 2], resp[off + 3]);
        } else {
            off += rdlen;
        }
    }
    return (*count > 0) ? 0 : -1;
}

static int parse_a(const unsigned char *resp, int n, char *out_ip, int out_ip_len) {
    char list[8][64];
    int count = 0;
    if (parse_a_list(resp, n, list, 8, &count) != 0) return -1;
    snprintf(out_ip, (size_t)out_ip_len, "%s", list[0]);
    return 0;
}

// Запрашивает A-записи у DoH-резолверов и отдаёт до max адресов.
int doh_resolve_a_multi(const char *domain, char out[][64], int max, int *count) {
    *count = 0;
    if (!domain || !out || max <= 0) return -1;

    unsigned char q[512];
    int qlen = build_query(domain, q, sizeof(q));
    if (qlen < 0) return -1;

    char b64[768];
    b64url_encode(q, qlen, b64, sizeof(b64));

    char tmpl[] = "/tmp/mz-doh-XXXXXX";
    int tfd = mkstemp(tmpl);
    if (tfd < 0) return -1;
    close(tfd);

    static const struct {
        const char *url;
        const char *resolve;
    } hosts[] = {
        {"https://cloudflare-dns.com/dns-query?dns=", "cloudflare-dns.com:443:1.1.1.1"},
        {"https://dns.google/dns-query?dns=", "dns.google:443:8.8.8.8"},
        {NULL, NULL}
    };
    int result = -1;
    struct sigaction ign, oldc;
    sigemptyset(&ign.sa_mask);
    ign.sa_handler = SIG_DFL;
    ign.sa_flags = 0;
    sigaction(SIGCHLD, &ign, &oldc);
    for (int h = 0; hosts[h].url; h++) {
        char url[900];
        snprintf(url, sizeof(url), "%s%s", hosts[h].url, b64);
        char cmd[1200];
        snprintf(cmd, sizeof(cmd),
                 "curl -sS --fail --max-time 5 --resolve '%s' "
                 "-H 'accept: application/dns-message' "
                 "'%s' -o '%s' 2>/dev/null",
                 hosts[h].resolve, url, tmpl);
        if (system(cmd) != 0) continue;
        FILE *f = fopen(tmpl, "rb");
        if (!f) continue;
        unsigned char resp[2048];
        size_t n = fread(resp, 1, sizeof(resp), f);
        fclose(f);
        if (n >= 12 && resp[0] == 0xAB && resp[1] == 0xCD) {
            result = parse_a_list(resp, (int)n, out, max, count);
            if (result == 0) break;
        }
    }
    sigaction(SIGCHLD, &oldc, NULL);
    unlink(tmpl);
    return result;
}

int doh_resolve_a(const char *domain, char *out_ip, int out_ip_len) {
    if (!domain || !out_ip || out_ip_len < 16) return -1;

    unsigned char q[512];
    int qlen = build_query(domain, q, sizeof(q));
    if (qlen < 0) return -1;

    char b64[768];
    b64url_encode(q, qlen, b64, sizeof(b64));

    char tmpl[] = "/tmp/mz-doh-XXXXXX";
    int tfd = mkstemp(tmpl);
    if (tfd < 0) return -1;
    close(tfd);

    // Resolve both DoH hostnames without consulting the local DNS resolver.
    static const struct {
        const char *url;
        const char *resolve;
    } hosts[] = {
        {"https://cloudflare-dns.com/dns-query?dns=", "cloudflare-dns.com:443:1.1.1.1"},
        {"https://dns.google/dns-query?dns=", "dns.google:443:8.8.8.8"},
        {NULL, NULL}
    };
    int result = -1;
    // system() must not run with SIGCHLD=IGN (relay sets that): wait() would ECHILD.
    struct sigaction ign, oldc;
    sigemptyset(&ign.sa_mask);
    ign.sa_handler = SIG_DFL;
    ign.sa_flags = 0;
    sigaction(SIGCHLD, &ign, &oldc);
    for (int h = 0; hosts[h].url; h++) {
        char url[900];
        snprintf(url, sizeof(url), "%s%s", hosts[h].url, b64);
        char cmd[1200];
        snprintf(cmd, sizeof(cmd),
                 "curl -sS --fail --max-time 5 --resolve '%s' "
                 "-H 'accept: application/dns-message' "
                 "'%s' -o '%s' 2>/dev/null",
                 hosts[h].resolve, url, tmpl);
        if (system(cmd) != 0) continue;
        FILE *f = fopen(tmpl, "rb");
        if (!f) continue;
        unsigned char resp[2048];
        size_t n = fread(resp, 1, sizeof(resp), f);
        fclose(f);
        if (n >= 12 && resp[0] == 0xAB && resp[1] == 0xCD) {
            result = parse_a(resp, (int)n, out_ip, out_ip_len);
            if (result == 0) break;
        }
    }
    sigaction(SIGCHLD, &oldc, NULL);
    unlink(tmpl);
    return result;

}
