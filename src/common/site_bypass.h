#ifndef RMF_SITE_BYPASS_H
#define RMF_SITE_BYPASS_H

#include <stdbool.h>
#include <stddef.h>

typedef struct {
    const char *name;
    const char *chain;
    const char *const *domains;
    size_t domain_count;
    int dns_port;
    int relay_port;
    unsigned int mark;
    const char *primary_dns;
    const char *fallback_dns;
    int (*validate_ip)(const char *ip);
    const char *const *fallback_ips;
    size_t fallback_count;
} site_bypass_config_t;

typedef struct {
    int dns_pid;
    int dns_fd;
    int dns_port;
    int relay_port;
    unsigned int mark;
    bool active;
    bool rules_installed;
    char primary[32];
    char fallback[32];
    char chain[64];
} site_bypass_state_t;

int site_bypass_start(site_bypass_state_t *state, const site_bypass_config_t *config);
void site_bypass_stop(site_bypass_state_t *state);
int site_bypass_active(const site_bypass_state_t *state);

#endif
