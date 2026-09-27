#ifndef VRCHAT_DISCOVERY_H
#define VRCHAT_DISCOVERY_H

// Фоновая разведка адресов VRChat. См. vrchat_discovery.c за подробностями:
// почему сессионные и контентные хосты обрабатываются по-разному.

#include <stdbool.h>
#include <stdint.h>

#define VRCHAT_DISC_MAX_HOSTS 16
#define VRCHAT_DISC_MAX_ADDRS 6

typedef struct {
    const char *host;
    bool        session_critical;  // один адрес на весь сессионный набор
    const char *fallback_ip;       // зашитый адрес, если свежие не годятся
} vrchat_discovery_host_t;

typedef struct {
    int  interval_sec;
    vrchat_discovery_host_t *hosts;   // массив, NULL-слоты пропускаются
} vrchat_discovery_cfg_t;

typedef struct {
    char     host[96];
    bool     session_critical;
    char     pinned[64];                                   // для сессионных
    char     addrs[VRCHAT_DISC_MAX_ADDRS][64];             // все живые
    int      count;
    int      alive;      // сколько ответило
    int      tried;      // сколько пробовали
    int      best_ms;    // задержка выбранного адреса
    char     note[72];
} vrchat_discovery_host_out_t;

typedef struct {
    long generation;   // растёт на каждом обходе
    vrchat_discovery_host_out_t hosts[VRCHAT_DISC_MAX_HOSTS];
} vrchat_discovery_report_t;

int  vrchat_discovery_start(const vrchat_discovery_cfg_t *cfg);
void vrchat_discovery_stop(void);
int  vrchat_discovery_copy_report(vrchat_discovery_report_t *out);
long vrchat_discovery_generation(void);

#endif
