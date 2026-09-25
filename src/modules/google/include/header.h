#ifndef GOOGLE_MODULE_H
#define GOOGLE_MODULE_H

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

// Google/YouTube Module Config
typedef struct {
    const char* primary_dns;
    const char* fallback_dns;
    int buffer_size;
    int priority;
    int frag_delay_ms;
    int frag_first_seg;
    int relay_port;
} google_config_t;

// Google Module Context
typedef struct {
    int socket_fd;
    char primary[32];
    char fallback[32];
    int mode;
    int frag_delay_ms;
    int frag_first_seg;
    int relay_port;
    int relay_pid;
} google_ctx_t;

// Google Module Interface
extern void google_module_init(google_config_t* config);
extern void google_module_cleanup(void);
extern void google_module_inject(int fd);
extern void google_module_remove(void);
extern const char* google_get_status(void);

extern google_ctx_t* google_get_ctx(void);
extern int google_is_target(const char* domain);

#endif // GOOGLE_MODULE_H
