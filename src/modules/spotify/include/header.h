#ifndef SPOTIFY_MODULE_H
#define SPOTIFY_MODULE_H

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdbool.h>

// Spotify Module Config
typedef struct {
    const char* primary_dns;
    const char* fallback_dns;
    int buffer_size;
    int priority;
} spotify_config_t;

// Spotify Module Context
typedef struct {
    int socket_fd;
    char primary[32];
    char fallback[32];
    int mode;
} spotify_ctx_t;

// Spotify Module Interface (Clean C!)
extern void spotify_module_init(spotify_config_t* config);
extern void spotify_module_cleanup(void);
extern void spotify_module_inject(int fd);
extern void spotify_module_remove(void);
extern const char* spotify_get_status(void);

#endif