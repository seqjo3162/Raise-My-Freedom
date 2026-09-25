#ifndef SNi_RELAY_H
#define SNi_RELAY_H

// Generic SNI-split TCP relay (TLS record fragmentation of ClientHello).
// Shared by google / xcom / speedtestbyookla modules (and usable standalone).

#include <stddef.h>

typedef struct {
    int port;              // listen port on 127.0.0.1 (default set by caller)
    unsigned int so_mark;  // SO_MARK for upstream sockets (avoid REDIRECT loop)
    int frag_delay_ms;     // pause between TCP segments (default 30)
    int frag_first_seg;    // first segment size inside record1 (default 20)
    const char *primary_dns;   // for upstream candidate resolution
    const char *fallback_dns;
    int (*validate_ip)(const char *ip);
    const char *const *fallback_ips;
    size_t fallback_count;
} sni_relay_config_t;

// Start relay in a forked child. Returns 0 on success, -1 on error.
// Only one relay per process (static state).
int sni_relay_start(const sni_relay_config_t *cfg);
void sni_relay_stop(void);
int sni_relay_running(void);
int sni_relay_pid(void);

// Pure helpers (testable)
// Cut offset inside handshake message (mid SNI hostname) or -1.
int sni_find_split(const unsigned char *hs, int hs_len);
// Build 2-record fragmented CH into out. Returns length or -1.
int sni_build_fragmented_ch(const unsigned char *hs, int hs_len,
                            unsigned char *out, int out_cap, int *first_seg_out);
// Extract SNI hostname. Returns length written (0 if none).
int sni_extract_name(const unsigned char *hs, int hs_len, char *out, size_t out_sz);

#endif
