#ifndef SNIPROXY_H
#define SNIPROXY_H

#include <stdint.h>
#include <stddef.h>

/**
 * @file sniproxy.h
 * @brief SNI Proxy Pattern - TLS with Original Certificate Preservation
 * 
 * Класс-паттерн для TLS проксирования без MITM.
 */

typedef enum {
    SNIPROXY_TYPE_NONE,
    SNIPROXY_TYPE_SIMPLE,     // Простое TLS с оригинальным сертификатом
    SNIPROXY_TYPE_ECDHE,      // ECDHE для forward secrecy
} sniproxy_op_t;

struct sniproxy_ctx {
    uint16_t type;                   // SNIPROXY_TYPE_SIMPLE или ECDHE
    char target_hosts[512];          // "youtube.com", "google.com" и т.д.
    int proxy_port;                  // Порт слушания прокси (1083/1084)
};

struct sniproxy_rule {
    struct sniproxy_ctx ctx;
    char host[256];                  // Хост для этого правила
    uint32_t original_ip;            // IP оригинального сервера (little-endian)
};

// Реализация в src/*.c или скриптах!
extern struct sniproxy_ctx* sniproxy_create(sni_proxy_op_t type);
extern void sniproxy_destroy(struct sniproxy_ctx** ctx);
extern int sniproxy_add_host(struct sniproxy_ctx* ctx, const char* host);
extern int sniproxy_bind_and_listen(struct sniproxy_ctx* ctx, int port);
extern int sniproxy_process_tls_handshake(struct sniproxy_ctx* ctx, int socket_fd);

#define SNIPROXY_CTX_VALID(ctx) ((ctx)->type != 0 && (ctx)->proxy_port > 0)

#endif // SNIPROXY_H