#ifndef NETFLIX_MODULE_H
#define NETFLIX_MODULE_H

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdbool.h>

// Netflix Module Config
typedef struct {
    const char* primary_dns;
    const char* fallback_dns;
    int buffer_size;
    int priority;
} netflix_config_t;

// Netflix Module Context
typedef struct {
    int socket_fd;
    char primary[32];
    char fallback[32];
    int mode;
} netflix_ctx_t;

// Netflix Module Interface (Clean C!)
extern void netflix_module_init(netflix_config_t* config);
extern void netflix_module_cleanup(void);
extern void netflix_module_inject(int fd);
extern void netflix_module_remove(void);
extern const char* netflix_get_status(void);

#endif