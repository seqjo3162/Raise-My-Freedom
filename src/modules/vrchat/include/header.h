#ifndef VRCHAT_MODULE_H
#define VRCHAT_MODULE_H

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

typedef struct {
    const char* primary_dns;
    const char* fallback_dns;
    int buffer_size;
    int priority;
} vrchat_config_t;

typedef struct {
    int socket_fd;
    char primary[32];
    char fallback[32];
    int mode;
} vrchat_ctx_t;

extern void vrchat_module_init(vrchat_config_t* config);
extern void vrchat_module_cleanup(void);
extern void vrchat_module_inject(int fd);
extern void vrchat_module_remove(void);
extern const char* vrchat_get_status(void);

#endif // VRCHAT_MODULE_H
