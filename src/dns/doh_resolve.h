#ifndef DOH_RESOLVE_H
#define DOH_RESOLVE_H

// Resolve A record via Cloudflare DoH (bypasses ISP DNS poisoning).
// Returns 0 on success and fills out_ip (e.g. "142.251.154.4"), -1 on failure.
int doh_resolve_a(const char *domain, char *out_ip, int out_ip_len);

#endif
