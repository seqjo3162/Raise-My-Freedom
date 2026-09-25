#ifndef GITHUB_MODULE_H
#define GITHUB_MODULE_H

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdbool.h>

// GitHub Module Config
typedef struct {
    const char* primary_dns;
    const char* fallback_dns;
    int buffer_size;
    int priority;
} github_config_t;

// GitHub Module Context
typedef struct {
    int socket_fd;
    char primary[32];
    char fallback[32];
    int mode;
} github_ctx_t;

// GitHub Module Interface (Clean C!)
extern void github_module_init(github_config_t* config);
extern void github_module_cleanup(void);
extern void github_module_inject(int fd);
extern void github_module_remove(void);
extern const char* github_get_status(void);

#endif
