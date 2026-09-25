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

// Хелперы (чистые, тестируемые)
extern int discord_is_target(const char* domain);
extern int discord_find_sni_split(const unsigned char* hs, int hs_len);
extern int discord_build_fragmented_ch(const unsigned char* hs, int hs_len,
                                       unsigned char* out, int out_cap,
                                       int* first_seg_out);

// Прозрачный relay с SNI-split (fork-процесс)
extern int  discord_relay_start(int port);
extern void discord_relay_stop(void);
extern int  discord_relay_running(void);

#endif // DISCORD_MODULE_H
