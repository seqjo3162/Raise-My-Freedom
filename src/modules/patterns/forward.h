#ifndef FORWARD_H
#define FORWARD_H

#include <stdint.h>
#include <stddef.h>

/**
 * @file forward.h
 * @brief Port Forwarding Pattern - iptables DNAT/REDIRECT
 * 
 * Класс-паттерн для перенаправления портов через iptables.
 */

typedef enum {
    FORWARD_TYPE_NONE,
    FORWARD_TYPE_IPTABLES,   // Через iptables REDIRECT/DNAT
    FORWARD_TYPE_NFTABLES,  // Через nftables (альтернатива)
} forward_op_t;

struct forward_ctx {
    uint16_t type;           // FORWARD_TYPE_IPTABLES или др.
    int src_port;            // Исходный порт (443)
    int dest_port;           // Порт rmf (1083/1084)
    char chain[32];          // "PREROUTING" или "OUTPUT"
};

struct forward_rule {
    struct forward_ctx ctx;
    uint32_t target_host;    // Хэш целевого домена (little-endian)
    char protocol[16];       // "tcp" или "udp"
};

// Реализация в src/iptables_manager.c или скриптах!
extern struct forward_ctx* forward_create(forward_op_t type, int src_port, int dest_port);
extern void forward_destroy(struct forward_ctx** ctx);
extern int forward_apply_iptables_rule(struct forward_ctx* ctx, const char* rule_file);
extern int forward_cleanup_rules(void);

#define FORWARD_CTX_VALID(ctx) ((ctx)->type != 0 && (ctx)->src_port > 0)

#endif // FORWARD_H