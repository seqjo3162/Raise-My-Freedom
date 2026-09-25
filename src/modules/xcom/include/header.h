#ifndef XCOM_MODULE_H
#define XCOM_MODULE_H

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

// X.com Module Config
typedef struct {
    const char* primary_dns;
    const char* fallback_dns;
    int buffer_size;
    int priority;
    int frag_delay_ms;
    int frag_first_seg;
    int relay_port;
} xcom_config_t;

// X.com Module Context
typedef struct {
    int socket_fd;
    char primary[32];
    char fallback[32];
    int mode;
    int frag_delay_ms;
    int frag_first_seg;
    int relay_port;
    int relay_pid;
} xcom_ctx_t;

// X.com Module Interface
extern void xcom_module_init(xcom_config_t* config);
extern void xcom_module_cleanup(void);
extern void xcom_module_inject(int fd);
extern void xcom_module_remove(void);
extern const char* xcom_get_status(void);

extern xcom_ctx_t* xcom_get_ctx(void);
extern int xcom_is_target(const char* domain);

#endif // XCOM_MODULE_H
