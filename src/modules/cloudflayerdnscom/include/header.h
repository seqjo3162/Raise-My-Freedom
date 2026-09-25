#ifndef CLOUDFLAYERDNS_MODULE_H
#define CLOUDFLAYERDNS_MODULE_H

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

// Cloudflare DNS Module Config
typedef struct {
    const char* primary_dns;       // Primary DNS (Cloudflare: 1.1.1.1)
    const char* fallback_dns;      // Fallback DNS (Google: 8.8.8.8)
    int buffer_size;               // Packet size limit (0=no limit!)
    int priority;                  // Injection priority
} cloudflayerdns_config_t;

// Cloudflare DNS Module Context
typedef struct {
    int socket_fd;                 // DNS Socket
    char primary[32];              // Primary DNS IP
    char fallback[32];             // Fallback DNS IP
    int mode;                      // 0=auto, 1=inject
} cloudflayerdns_ctx_t;

// Cloudflare DNS Module Interface (Clean C!)
extern void cloudflayerdns_module_init(cloudflayerdns_config_t* config);
extern void cloudflayerdns_module_cleanup(void);
extern void cloudflayerdns_module_inject(int fd);
extern void cloudflayerdns_module_remove(void);
extern const char* cloudflayerdns_get_status(void);

#endif // CLOUDFLAYERDNS_MODULE_H
