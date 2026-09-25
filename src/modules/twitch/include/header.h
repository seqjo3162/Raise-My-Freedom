#ifndef TWITCH_MODULE_H
#define TWITCH_MODULE_H

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdbool.h>

// Twitch Module Config
typedef struct {
    const char* primary_dns;
    const char* fallback_dns;
    int buffer_size;
    int priority;
} twitch_config_t;

// Twitch Module Context
typedef struct {
    int socket_fd;
    char primary[32];
    char fallback[32];
    int mode;
} twitch_ctx_t;

// Twitch Module Interface (Clean C!)
extern void twitch_module_init(twitch_config_t* config);
extern void twitch_module_cleanup(void);
extern void twitch_module_inject(int fd);
extern void twitch_module_remove(void);
extern const char* twitch_get_status(void);

#endif