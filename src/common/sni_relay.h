#ifndef SNi_RELAY_H
#define SNi_RELAY_H

// Generic SNI-split TCP relay (TLS record fragmentation of ClientHello).
// Shared by the google module and usable standalone (and usable standalone).

#include <stddef.h>

typedef struct {
    int port;              // listen port on 127.0.0.1 (default set by caller)
    unsigned int so_mark;  // SO_MARK for upstream sockets (avoid REDIRECT loop)
    int frag_delay_ms;     // pause between TCP segments (default 30)
    int frag_first_seg;    // first segment size inside record1 (default 20)
    const char *primary_dns;   // for upstream candidate resolution
    const char *fallback_dns;
    int (*validate_ip)(const char *ip);
    const char *const *fallback_ips;
    size_t fallback_count;
    int split_data_records;     // 1 = дробить и записи с данными (0x17), не только handshake
    int split_record_size;      // размер одной части data-записи в байтах
    int split_record_delay_ms;  // пауза между частями
    // Внимание: поля ниже инвертированы или имеют 0 = «прежнее поведение».
    // Незаданное поле в designated initializer обнуляется, поэтому 0 обязан
    // означать исходные значения, иначе модули, которые эти поля не задают,
    // молча поменяют своё поведение.
    int no_split_client_hello;  // 1 = отправить ClientHello как есть, без разрыва SNI
    int data_chunk;             // размер порции при пересылке данных, 0 = 4096
    int data_pause_ms;          // пауза между порциями, 0 = 1 мс, отрицательное = без паузы
    // 1 = не резать ответные handshake-записи (0x16) пополам. Проверено: при
    // разрезе клиент получал ответ и отвечал алертом (ERR_SSL_PROTOCOL_ERROR).
    // Поле по умолчанию 0, то есть прежнее поведение.
    int no_split_handshake_records;
} sni_relay_config_t;

// Start relay in a forked child. Returns 0 on success, -1 on error.
// Only one relay per process (static state).
int sni_relay_start(const sni_relay_config_t *cfg);
void sni_relay_stop(void);
int sni_relay_running(void);
int sni_relay_pid(void);

// Pure helpers (testable)
// Cut offset inside handshake message (mid SNI hostname) or -1.
int sni_find_split(const unsigned char *hs, int hs_len);



// Build 2-record fragmented CH into out. Returns length or -1.
int sni_build_fragmented_ch(const unsigned char *hs, int hs_len,
                            unsigned char *out, int out_cap, int *first_seg_out);
// Extract SNI hostname. Returns length written (0 if none).
int sni_extract_name(const unsigned char *hs, int hs_len, char *out, size_t out_sz);

#endif
