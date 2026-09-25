#ifndef SPEEDTESTBYOOKLA_MODULE_H
#define SPEEDTESTBYOOKLA_MODULE_H

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

// Speedtest by Ookla Module Config
typedef struct {
    const char* primary_dns;
    const char* fallback_dns;
    int buffer_size;
    int priority;
    int frag_delay_ms;
    int frag_first_seg;
    int relay_port;
} speedtestbyookla_config_t;

// Speedtest by Ookla Module Context
typedef struct {
    int socket_fd;
    char primary[32];
    char fallback[32];
    int mode;
    int frag_delay_ms;
    int frag_first_seg;
    int relay_port;
    int relay_pid;
} speedtestbyookla_ctx_t;

// Speedtest by Ookla Module Interface
extern void speedtestbyookla_module_init(speedtestbyookla_config_t* config);
extern void speedtestbyookla_module_cleanup(void);
extern void speedtestbyookla_module_inject(int fd);
extern void speedtestbyookla_module_remove(void);
extern float speedtestbyookla_speed_test(const char* domain);
extern const char* speedtestbyookla_get_status(void);

extern speedtestbyookla_ctx_t* speedtestbyookla_get_ctx(void);
extern int speedtestbyookla_is_target(const char* domain);

#endif // SPEEDTESTBYOOKLA_MODULE_H
