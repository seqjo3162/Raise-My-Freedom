#ifndef GAG_MODULE_H
#define GAG_MODULE_H

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdbool.h>

// 9GAG Module Config
typedef struct {
    const char* primary_dns;
    const char* fallback_dns;
    int buffer_size;
    int priority;
} ninegag_config_t;

// 9GAG Module Context
typedef struct {
    int socket_fd;
    char primary[32];
    char fallback[32];
    int mode;
} ninegag_ctx_t;

// 9GAG Module Interface (Clean C!)
extern void ninegag_module_init(ninegag_config_t* config);
extern void ninegag_module_cleanup(void);
extern void ninegag_module_inject(int fd);
extern void ninegag_module_remove(void);
extern const char* ninegag_get_status(void);

#endif