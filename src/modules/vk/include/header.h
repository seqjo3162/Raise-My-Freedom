#ifndef VK_MODULE_H
#define VK_MODULE_H

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdbool.h>

// VK Module Config
typedef struct {
    const char* primary_dns;
    const char* fallback_dns;
    int buffer_size;
    int priority;
} vk_config_t;

// VK Module Context
typedef struct {
    int socket_fd;
    char primary[32];
    char fallback[32];
    int mode;
} vk_ctx_t;

// VK Module Interface (Clean C!)
extern void vk_module_init(vk_config_t* config);
extern void vk_module_cleanup(void);
extern void vk_module_inject(int fd);
extern void vk_module_remove(void);
extern const char* vk_get_status(void);

#endif