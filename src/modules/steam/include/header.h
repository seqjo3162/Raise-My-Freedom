#ifndef STEAM_MODULE_H
#define STEAM_MODULE_H

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

// Steam Module Config
typedef struct {
    const char* primary_dns;       // Primary DNS (Cloudflare: 1.1.1.1)
    const char* fallback_dns;      // Fallback DNS (Google: 8.8.8.8)
    int buffer_size;               // Packet size limit (0=no limit!)
    int priority;                  // Injection priority
} steam_config_t;

// Steam Module Context
typedef struct {
    int socket_fd;                 // DNS Socket
    char primary[32];              // Primary DNS IP
    char fallback[32];             // Fallback DNS IP
    int mode;                      // 0=auto, 1=inject
} steam_ctx_t;

// Steam Module Interface (Clean C!)
extern void steam_module_init(steam_config_t* config);
extern void steam_module_cleanup(void);
extern void steam_module_inject(int fd);
extern void steam_module_remove(void);
extern const char* steam_get_status(void);

#endif // STEAM_MODULE_H