#ifndef DOH_RESOLVE_H
#define DOH_RESOLVE_H

// Resolve A record via Cloudflare DoH (bypasses ISP DNS poisoning).
// Returns 0 on success and fills out_ip (e.g. "142.251.154.4"), -1 on failure.
int doh_resolve_a(const char *domain, char *out_ip, int out_ip_len);

// То же, но отдаёт до max адресов сразу (out — массив строк по 64 байта).
// У сайтов за CDN адресов несколько, и первый нередко недостижим.
int doh_resolve_a_multi(const char *domain, char out[][64], int max, int *count);

#endif
