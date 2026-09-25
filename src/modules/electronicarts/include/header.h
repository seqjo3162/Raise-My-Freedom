#ifndef ELECTRONICARTS_MODULE_H
#define ELECTRONICARTS_MODULE_H

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

// Electronic Arts Module Config
typedef struct {
    const char* primary_dns;       // Primary DNS (Google: 8.8.8.8)
    const char* fallback_dns;      // Fallback DNS (Cloudflare: 1.1.1.1)
    int buffer_size;               // Packet size limit (0=no limit!)
    int priority;                  // Injection priority
} electronicarts_config_t;

// Electronic Arts Module Context
typedef struct {
    int socket_fd;                 // DNS Socket
    char primary[32];              // Primary DNS IP
    char fallback[32];             // Fallback DNS IP
    int mode;                      // 0=auto, 1=inject
} electronicarts_ctx_t;

// Electronic Arts Module Interface (Clean C!)
extern void electronicarts_module_init(electronicarts_config_t* config);
extern void electronicarts_module_cleanup(void);
extern void electronicarts_module_inject(int fd);
extern void electronicarts_module_remove(void);
extern const char* electronicarts_get_status(void);

#endif // ELECTRONICARTS_MODULE_H