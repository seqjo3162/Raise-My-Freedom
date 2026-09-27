#ifndef HF_MODULE_H
#define HF_MODULE_H

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdbool.h>

// Hugging Face Module Config
typedef struct {
    const char* primary_dns;
    const char* fallback_dns;
    int buffer_size;
    int priority;
} hf_config_t;

// Hugging Face Module Context
typedef struct {
    int socket_fd;
    char primary[32];
    char fallback[32];
    int mode;
} hf_ctx_t;

// Hugging Face Module Interface
extern void hf_module_init(hf_config_t* config);
extern void hf_module_cleanup(void);
extern void hf_module_inject(int fd);
extern void hf_module_remove(void);
extern const char* hf_get_status(void);

#endif
