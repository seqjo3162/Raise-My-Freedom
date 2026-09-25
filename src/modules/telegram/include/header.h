#ifndef TELEGRAM_MODULE_H
#define TELEGRAM_MODULE_H

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdbool.h>

#define TG_PROXY_PORT      1443
#define TG_CONF_FILE       "webui/telegram.conf"
#define TG_PROTO_SALT      0xefefefefefefefefULL
#define TG_TAG             0xdeadbeefU
#define TG_HANDSHAKE_LEN   64
#define TG_NONCE_LEN       32
#define TG_AUTHKEY_LEN     40
#define TG_CHUNK           4096

// Локальный Telegram proxy: SOCKS5 CONNECT и экспериментальный MTProto путь.
typedef struct {
    const char *primary_dns;    // Cloudflare: 1.1.1.1
    const char *fallback_dns;   // Cloudflare: 1.0.0.1
    int buffer_size;
    int priority;
    int proxy_port;             // локальный порт proxy, по умолчанию 1443
    int prefer_ipv6;            // 1 = x6 first, затем x4 (пул x6-x4)
    int use_fake_tls;           // 1 = intermediate-режим с поддельным TLS
} telegram_config_t;

typedef struct {
    int socket_fd;
    char primary[32];
    char fallback[32];
    int mode;
    int proxy_port;
    int prefer_ipv6;
    int use_fake_tls;
    int listen_fd;
    pid_t relay_pid;
    int relay_running;
} telegram_ctx_t;

// Модуль
extern void telegram_module_init(telegram_config_t *config);
extern void telegram_module_cleanup(void);
extern void telegram_module_inject(int fd);
extern void telegram_module_remove(void);
extern const char *telegram_get_status(void);
extern telegram_ctx_t *telegram_get_ctx(void);

// MTProxy
extern void telegram_proxy_set_secret(const char *hex);
extern int  telegram_proxy_start(int port);
extern void telegram_proxy_stop(void);
extern int  telegram_proxy_running(void);

#endif
