#ifndef ACTIVISION_MODULE_H
#define ACTIVISION_MODULE_H

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

// Activision Module Config
typedef struct {
    const char* primary_dns;       // Primary DNS (Cloudflare: 1.1.1.1)
    const char* fallback_dns;      // Fallback DNS (Google: 8.8.8.8)
    int buffer_size;               // Packet size limit (0=no limit!)
    int priority;                  // Injection priority
} activision_config_t;

// Activision Module Context
typedef struct {
    int socket_fd;                 // DNS Socket
    char primary[32];              // Primary DNS IP
    char fallback[32];             // Fallback DNS IP
    int mode;                      // 0=auto, 1=inject
} activision_ctx_t;

// Activision Module Interface (Clean C!)
extern void activision_module_init(activision_config_t* config);
extern void activision_module_cleanup(void);
extern void activision_module_inject(int fd);
extern void activision_module_remove(void);
extern const char* activision_get_status(void);

#endif // ACTIVISION_MODULE_H