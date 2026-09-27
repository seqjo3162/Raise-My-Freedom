#ifndef DESYNC_H
#define DESYNC_H

#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stddef.h>
#include <stdint.h>

// Пакетный слой десинхронизации.
//
// Зачем он нужен. Разрыв SNI на потоке (sni_relay, multisplit) не сработал:
// провайдерский DPI склеивает поток обратно и обрывает его. Ломать сборку
// надо на уровне пакета — так, чтобы ДВА получателя видели РАЗНОЕ:
//
//   DPI      — видит поддельную запись с чужим именем, блокировать нечего;
//   сервер   — подделку не видит вовсе.
//
// Разница между ними в том, что DPI стоит ближе к нам, чем сервер. Пакет с
// маленьким TTL переживает первый хоп провайдера (DPI его прочитал) и
// умирает до сервера. Это приём zapret --dpi-desync-ttl, здесь он сделан на
// сырых сокетах, чтобы не тянуть NFQUEUE и не трогать ядро.
//
// Слой полностью отдельный: модуль подключает его сам и только для своих
// адресов. Без подключения ничего не меняется.

typedef enum {
    DESYNC_MODE_OFF = 0,
    DESYNC_MODE_FAKE,     // поддельная запись перед настоящей, с малым TTL
    DESYNC_MODE_FAKE_TAIL // то же, но подделка уходит после настоящей
} desync_mode_t;

typedef struct {
    const char *iface;        // сетевой интерфейс, например enp42s0
    const char *cidr;         // один адрес или диапазон: 162.159.128.0/18
    int         dport;        // порт назначения, обычно 443; 0 = любой
    const char *fake_sni;     // имя в подделке; по умолчанию vk.ru —
                                 // российское намеренно, см. FAKE_SNI
    unsigned char fake_ttl;   // TTL подделки. 2-4 обычно достаточно
    desync_mode_t mode;
    unsigned int so_mark;     // пометить свои пакеты, чтобы не попасть в iptables
    char        chain[64];    // цепочка модуля-владельца, только для логов
} desync_config_t;

// Счётчики для диагностики: без них слой работает вслепую.
typedef struct {
    uint64_t seen;       // просмотрено исходящих TCP-пакетов
    uint64_t matched;    // подошли под адрес/порт
    uint64_t hellos;     // распознан ClientHello
    uint64_t injected;   // подделок отправлено
    uint64_t no_fake;    // ClientHello без SNI — подделывать нечего
    uint64_t skipped;    // уже наша подделка (защита от рекурсии)
} desync_stats_t;

int  desync_start(const desync_config_t *cfg);
void desync_stop(void);
bool desync_running(void);
const char *desync_last_error(void);
void desync_get_stats(desync_stats_t *out);

// Диагностика: сколько пакетов ушло в каждый диапазон /16. Нужна, чтобы
// отличить «трафика к цели нет» от «цель задана неверно» — по молчанию
// это неразличимо, а стоит один запуск.
#define DESYNC_TOP_N 8

// Проверка пути инъекции без прав root: подменяем отправку на захват байтов
// и прогоняем настоящий обработчик.
typedef ssize_t (*desync_send_fn)(const void *buf, size_t len,
                                  struct sockaddr *sa, socklen_t sl);
int  desync_test_setup(const char *cidr, int dport, const char *fake_sni, unsigned ttl);
int  desync_test_handle(const unsigned char *pkt, int len);
int  desync_test_frame(const unsigned char *frame, int len, int halen);
void desync_set_injector(desync_send_fn fn);
void desync_reset_for_test(void);
int  desync_test_in_target(uint32_t addr);
int  desync_sniffer_kind(void);
int  desync_ip_offset(const unsigned char *p, int len);
void desync_test_note_peer(uint32_t addr);
void desync_test_reset_peers(void);

// Разбор по протоколам: куда деваются пакеты, которые не дошли до разбора TCP.
typedef struct {
    unsigned long long tcp, udp, icmp, other, not_v4, long_hdr, short_pkt;
    unsigned long long to_us, to_other, outgoing, no_sni;
} desync_proto_stats_t;
void desync_get_proto_stats(desync_proto_stats_t *out);
void desync_test_target(uint32_t *net, uint32_t *mask, int *dport);

typedef struct { char net[20]; unsigned long long pkts; } desync_top_peer_t;
void desync_top_peers(desync_top_peer_t *out, int max, int *count);
const char *desync_mode_name(desync_mode_t m);

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#endif
