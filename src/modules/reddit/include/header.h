#ifndef REDDIT_MODULE_H
#define REDDIT_MODULE_H

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdbool.h>

// Reddit Module Config
typedef struct {
    const char* primary_dns;
    const char* fallback_dns;
    int buffer_size;
    int priority;
} reddit_config_t;

// Reddit Module Context
typedef struct {
    int socket_fd;
    char primary[32];
    char fallback[32];
    int mode;
} reddit_ctx_t;

// Reddit Module Interface (Clean C!)
extern void reddit_module_init(reddit_config_t* config);
extern void reddit_module_cleanup(void);
extern void reddit_module_inject(int fd);
extern void reddit_module_remove(void);
extern const char* reddit_get_status(void);

#endif