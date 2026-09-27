#ifndef UNIVERSAL_H
#define UNIVERSAL_H

#include <stdint.h>
#include <stdbool.h>

#define MAX_REGISTERED_DOMAINS 256
#define MAX_DOMAIN_LEN 256
#define MAX_UPSTREAM_LEN 32

typedef struct {
    char domain[MAX_DOMAIN_LEN];
    char upstream[MAX_UPSTREAM_LEN]; // e.g. "1.1.1.1" or "8.8.8.8"
} universal_domain_entry_t;

typedef struct {
    int socket_fd;
    int listen_port;
    char default_upstream[MAX_UPSTREAM_LEN];
} universal_ctx_t;

typedef struct {
    bool primary_dns;
} universal_config_t;

void universal_module_init(universal_config_t *config);
void universal_module_cleanup(void);
int universal_process_dns(const unsigned char *buffer, uint16_t len);
uint32_t universal_get_packet_count(void);
const char *universal_get_status(void);

// Domain registry API — modules call these to register domains
int universal_register_domain(const char *domain, const char *upstream_dns);
int universal_unregister_domain(const char *domain);
int universal_get_domain_count(void);

#endif
