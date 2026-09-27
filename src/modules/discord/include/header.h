#ifndef DISCORD_MODULE_H
#define DISCORD_MODULE_H

#include <stdint.h>

// Discord Module Config
typedef struct {
    const char* primary_dns;       // Primary DNS IP (Cloudflare: 1.1.1.1)
    const char* fallback_dns;      // Fallback DNS IP (Google: 8.8.8.8)
    int buffer_size;               // Packet size limit (0=no limit!)
    int priority;                  // Injection priority
    int frag_delay_ms;             // Пауза между TCP-сегментами CH (default 30)
    int frag_first_seg;            // Размер первого сегмента внутри record1 (default 20)
    int relay_port;                // Порт локального SNI-split relay (default 18443)
} discord_config_t;

// Discord Module Context
typedef struct {
    int socket_fd;                 // DNS Socket
    char primary[32];              // Primary DNS IP
    char fallback[32];             // Fallback DNS IP
    int mode;                      // 0=auto, 1=inject
    int frag_delay_ms;             // Пауза между сегментами ClientHello
    int frag_first_seg;            // Первый TCP-сегмент (обрыв внутри record1)
    int relay_port;                // Порт relay
    int relay_pid;                 // PID relay-процесса (-1 = не запущен)
} discord_ctx_t;

// Discord Module Interface
extern void discord_module_init(discord_config_t* config);
extern void discord_module_cleanup(void);
extern void discord_module_inject(int fd);
extern void discord_module_remove(void);
extern const char* discord_get_status(void);

// Доступ к контексту (для relay и тестов)
extern discord_ctx_t* discord_get_ctx(void);

// Разрезание SNI и сборка фрагментированного ClientHello живут в
// src/common/sni_relay.c (sni_find_split, sni_build_fragmented_ch) — там же,
// где ими реально пользуется рель. Копии в модуле были мертвым кодом:
// вызывались только из несуществующего теста.

// Хук реля: 1 = адрес в инфраструктуре Discord и годится в качестве
// апстрим-кандидата. Без сети — вызывается на каждое соединение.
// Живая проверка достижимости живёт в collect_own_ips, один раз при старте.
extern int discord_validate_ip(const char* ip);

// Свой релей (SNI-split) удалён: модуль использует общий
// src/common/plain_relay.c, который не меняет TLS. Раньше здесь был
// fork-релей с разрывом SNI — он рвал крупные ответы Cloudflare.

#endif // DISCORD_MODULE_H
