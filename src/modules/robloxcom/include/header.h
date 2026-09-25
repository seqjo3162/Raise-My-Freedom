#ifndef ROBLOX_MODULE_H
#define ROBLOX_MODULE_H

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

// Roblox Module Config
typedef struct {
    const char* primary_dns;       // Primary DNS (Cloudflare: 1.1.1.1)
    const char* fallback_dns;      // Fallback DNS (Google: 8.8.8.8)
    int buffer_size;               // Packet size limit (0=no limit!)
    int priority;                  // Injection priority
} roblox_config_t;

// Roblox Module Context
typedef struct {
    int socket_fd;                 // DNS Socket
    char primary[32];              // Primary DNS IP
    char fallback[32];             // Fallback DNS IP
    int mode;                      // 0=auto, 1=inject
} roblox_ctx_t;

// Roblox Module Interface (Clean C!)
extern void roblox_module_init(roblox_config_t* config);
extern void roblox_module_cleanup(void);
extern void roblox_module_inject(int fd);
extern void roblox_module_remove(void);
extern const char* roblox_get_status(void);

#endif // ROBLOX_MODULE_H
