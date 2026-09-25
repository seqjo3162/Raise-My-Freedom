#ifndef BATTLNET_MODULE_H
#define BATTLNET_MODULE_H

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

// Battle.net Module Config
typedef struct {
    const char* primary_dns;       // Primary DNS (Cloudflare: 1.1.1.1)
    const char* fallback_dns;      // Fallback DNS (Google: 8.8.8.8)
    int buffer_size;               // Packet size limit (0=no limit!)
    int priority;                  // Injection priority
} battlenet_config_t;

// Battle.net Module Context
typedef struct {
    int socket_fd;                 // DNS Socket
    char primary[32];              // Primary DNS IP
    char fallback[32];             // Fallback DNS IP
    int mode;                      // 0=auto, 1=inject
} battlenet_ctx_t;

// Battle.net Module Interface (Clean C!)
extern void battlenet_module_init(battlenet_config_t* config);
extern void battlenet_module_cleanup(void);
extern void battlenet_module_inject(int fd);
extern void battlenet_module_remove(void);
extern const char* battlenet_get_status(void);

#endif // BATTLNET_MODULE_H
