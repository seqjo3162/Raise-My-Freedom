#ifndef EPICGAMES_MODULE_H
#define EPICGAMES_MODULE_H

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

// Epic Games Module Config
typedef struct {
    const char* primary_dns;       // Primary DNS (Cloudflare: 1.1.1.1)
    const char* fallback_dns;      // Fallback DNS (Google: 8.8.8.8)
    int buffer_size;               // Packet size limit (0=no limit!)
    int priority;                  // Injection priority
} epicgames_config_t;

// Epic Games Module Context
typedef struct {
    int socket_fd;                 // DNS Socket
    char primary[32];              // Primary DNS IP
    char fallback[32];             // Fallback DNS IP
    int mode;                      // 0=auto, 1=inject
} epicgames_ctx_t;

// Epic Games Module Interface (Clean C!)
extern void epicgames_module_init(epicgames_config_t* config);
extern void epicgames_module_cleanup(void);
extern void epicgames_module_inject(int fd);
extern void epicgames_module_remove(void);
extern const char* epicgames_get_status(void);

#endif // EPICGAMES_MODULE_H