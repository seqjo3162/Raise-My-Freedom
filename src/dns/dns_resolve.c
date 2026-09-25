#include "src/dns/dns_resolve.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

int dns_resolve_udp(const char *dns_ip, const char *domain, char *out_ip, int out_ip_len) {
    if (!dns_ip || !domain || !out_ip || out_ip_len < 64) return -1;

    unsigned char pkt[512], resp[512];
    memset(pkt, 0, sizeof(pkt));

    pkt[0] = 0xAB; pkt[1] = 0xCD;
    pkt[2] = 0x01; pkt[3] = 0x00;
    pkt[4] = 0x00; pkt[5] = 0x01;

    unsigned char *p = pkt + 12;
    const char *s = domain;
    while (*s) {
        const char *dot = strchr(s, '.');
        int ll = dot ? (int)(dot - s) : (int)strlen(s);
        if (ll <= 0 || ll > 63 || (size_t)(p - pkt) + (size_t)ll + 6 >= sizeof(pkt))
            return -1;
        *p++ = (unsigned char)ll;
        memcpy(p, s, (size_t)ll);
        p += ll;
        s += ll + (dot ? 1 : 0);
        if (!dot) break;
    }
    *p++ = 0;
    *p++ = 0; *p++ = 1;
    *p++ = 0; *p++ = 1;
    int pkt_len = (int)(p - pkt);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    struct timeval tv = {3, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(53);
    if (inet_pton(AF_INET, dns_ip, &dst.sin_addr) != 1) { close(fd); return -1; }

    if (sendto(fd, pkt, (size_t)pkt_len, 0,
               (struct sockaddr *)&dst, sizeof(dst)) != pkt_len) { close(fd); return -1; }

    ssize_t n = recvfrom(fd, resp, sizeof(resp), 0, NULL, NULL);
    close(fd);

    if (n < 12 || resp[0] != 0xAB || resp[1] != 0xCD) return -1;
    int ancount = (resp[6] << 8) | resp[7];
    if (ancount <= 0) return -1;

    int off = 12;
    while (off < n && resp[off] != 0) {
        if ((resp[off] & 0xC0) == 0xC0) { off += 2; break; }
        off += resp[off] + 1;
    }
    if (off < n && resp[off] == 0) off++;
    off += 4;

    while (off + 10 < n) {
        if ((resp[off] & 0xC0) == 0xC0) { off += 2; }
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
            snprintf(out_ip, (size_t)out_ip_len, "%d.%d.%d.%d",
                     resp[off], resp[off + 1], resp[off + 2], resp[off + 3]);
            return 0;
        }
        off += rdlen;
    }
    return -1;
}

int dns_ip_is_cloudflare(const char *ip_str) {
    if (!ip_str || !*ip_str) return 0;
    struct in_addr a;
    if (inet_pton(AF_INET, ip_str, &a) != 1) return 0;
    uint32_t ip = ntohl(a.s_addr);
    static const struct { uint32_t net; uint32_t mask; } cf[] = {
        {0x68100000u, 0xFFF00000u}, // 104.16.0.0/12
        {0xAC400000u, 0xFFF80000u}, // 172.64.0.0/13
        {0xAC420000u, 0xFFFF0000u}, // 172.66.0.0/16
        {0xAC430000u, 0xFFFF0000u}, // 172.67.0.0/16
    };
    for (unsigned i = 0; i < sizeof(cf) / sizeof(cf[0]); i++) {
        if ((ip & cf[i].mask) == cf[i].net) return 1;
    }
    return 0;
}

int dns_ip_is_google(const char *ip_str) {
    if (!ip_str || !*ip_str) return 0;
    struct in_addr a;
    if (inet_pton(AF_INET, ip_str, &a) != 1) return 0;
    uint32_t ip = ntohl(a.s_addr);
    static const struct { uint32_t net; uint32_t mask; } g[] = {
        {0x08080000u, 0xFFFF0000u}, // 8.8.0.0/16
        {0x8EFA0000u, 0xFFFE0000u}, // 142.250.0.0/15
        {0xD8EF0000u, 0xFFFF0000u}, // 216.239.0.0/16
    };
    for (unsigned i = 0; i < sizeof(g) / sizeof(g[0]); i++) {
        if ((ip & g[i].mask) == g[i].net) return 1;
    }
    return 0;
}
