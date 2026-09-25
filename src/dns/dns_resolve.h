#ifndef DNS_RESOLVE_H
#define DNS_RESOLVE_H

#include <stdint.h>

// Resolve a domain name to IPv4 via raw UDP DNS query.
// Returns 0 on success, -1 on failure.
int dns_resolve_udp(const char *dns_ip, const char *domain, char *out_ip, int out_ip_len);

// Check if an IP belongs to known Cloudflare ranges.
int dns_ip_is_cloudflare(const char *ip_str);

// Check if an IP belongs to known Google ranges.
int dns_ip_is_google(const char *ip_str);

#endif // DNS_RESOLVE_H
