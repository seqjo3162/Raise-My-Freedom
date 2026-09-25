#ifndef SNI_H
#define SNI_H

#include <stdint.h>

/**
 * @file sni.h
 * @brief SNI Hijacker Pattern - TLS Handshake Interception
 * 
 * Класс-паттерн для перехвата TLS handshake на уровне SNI.
 * 
 * Использование:
 *   struct { uint16_t type; char target_host[256]; } ctx = {...};
 *   process_sni_handshake(&ctx);  // Твоя реализация в скриптах!
 */

// ============ ENUMERATIONS ============
typedef enum {
    SNI_TYPE_NONE,
    SNI_TYPE_CHECKER,     // Проверка сертификата цели
    SNI_TYPE_BYPASS,      // Прозрачный bypass (прямая пересылка)
} sni_op_t;

// ============ STRUCTURES ============
struct sni_ctx {
    uint16_t type;              // Тип операции
    char target_host[256];      // Хост цели
    int proxy_port;             // Порт прокси (обычно 1083/1084)
};

struct sni_checker_ctx {
    struct sni_ctx ctx;
    int cert_verified;          // 1 если сертификат подтверждён
};

struct sni_bypass_ctx {
    struct sni_ctx ctx;
    uint32_t dest_ip;           // IP цели (в сетевых байтах)
};

// ============ FUNCTION DECLARATIONS ============
/* 
 * Эти функции не реализованы в этом файле.
 * Их нужно реализовать в commands/*.sh или src/*.c!
 */
extern struct sni_ctx* sni_create(sni_op_t type, const char* host);
extern void sni_destroy(struct sni_ctx** ctx);
extern int sni_process_handshake(struct sni_ctx* ctx);

// ============ MACROS ============
#define SNI_CTX_VALID(ctx) ((ctx)->type != 0)

#endif // SNI_H