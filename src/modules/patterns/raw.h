#ifndef RAW_H
#define RAW_H

#include <stdint.h>

/**
 * @file raw.h
 * @brief Raw Socks Pattern - Direct Tunnel via iptables REDIRECT
 * 
 * Класс-паттерн для прямого туннелирования через iptables REDIRECT.
 */

typedef enum {
    RAW_TYPE_NONE,
    RAW_TYPE_REDIRECT,   // Через iptables REDIRECT
    RAW_TYPE_TUNNEL,     // Прямой туннель без прокси
} raw_op_t;

struct raw_ctx {
    uint16_t type;
    int src_port;        // Исходный порт (443)
    int dest_port;       // Порт minizapret (1083/1084)
};

extern struct raw_ctx* raw_create(raw_op_t type, int src_port, int dest_port);
extern void raw_destroy(struct raw_ctx** ctx);
extern int raw_apply_redirect(struct raw_ctx* ctx);

#define RAW_CTX_VALID(ctx) ((ctx)->type != 0)

#endif // RAW_H