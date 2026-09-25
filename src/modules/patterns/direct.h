#ifndef DIRECT_H
#define DIRECT_H

#include <stdint.h>
#include <stddef.h>

/**
 * @file direct.h
 * @brief Direct Tunnel Pattern - Tun/Tap Interface Routing
 * 
 * Класс-паттерн для туннелирования через tun/tap устройство.
 */

typedef enum {
    DIRECT_TYPE_NONE,
    DIRECT_TYPE_TUN,       // IP уровень (layer 3)
    DIRECT_TYPE_TAP,      // Ethernet уровень (layer 2)
} direct_op_t;

struct direct_ctx {
    uint16_t type;           // DIRECT_TYPE_TUN или DIRECT_TYPE_TAP
    char interface_name[64]; // "tun0" или "tap0"
    struct {
        uint32_t network;    // Сеть (little-endian)
        uint8_t mask;        // Маска (например 24 для /24)
    } network_range;         // "192.168.100.0/24"
};

struct direct_setup_ctx {
    struct direct_ctx ctx;
    uint32_t gateway_ip;     // Шлюз через tun/tap
    uint16_t gateway_port;   // Порт шлюза (если требуется)
};

// Функции будут реализованы в src/*.c или скриптах!
extern struct direct_ctx* direct_create(direct_op_t type, const char* iface);
extern void direct_destroy(struct direct_ctx** ctx);
extern int direct_setup_interface(struct direct_ctx* ctx);
extern int direct_route_traffic(struct direct_ctx* ctx, uint32_t dest_ip);

#define DIRECT_CTX_VALID(ctx) ((ctx)->type != 0 && (ctx)->interface_name[0])

#endif // DIRECT_H