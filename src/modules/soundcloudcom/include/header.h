#ifndef SOUNDCLOUD_MODULE_H
#define SOUNDCLOUD_MODULE_H

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

// SoundCloud Module Config
typedef struct {
    const char* primary_dns;       // Primary DNS (Cloudflare: 1.1.1.1)
    const char* fallback_dns;      // Fallback DNS (Google: 8.8.8.8)
    int buffer_size;               // Packet size limit (0=no limit!)
    int priority;                  // Injection priority
} soundcloud_config_t;

// SoundCloud Module Context
typedef struct {
    int socket_fd;                 // DNS Socket
    char primary[32];              // Primary DNS IP
    char fallback[32];             // Fallback DNS IP
    int mode;                      // 0=auto, 1=inject
} soundcloud_ctx_t;

// SoundCloud Module Interface (Clean C!)
extern void soundcloud_module_init(soundcloud_config_t* config);
extern void soundcloud_module_cleanup(void);
extern void soundcloud_module_inject(int fd);
extern void soundcloud_module_remove(void);
extern const char* soundcloud_get_status(void);

#endif // SOUNDCLOUD_MODULE_H
