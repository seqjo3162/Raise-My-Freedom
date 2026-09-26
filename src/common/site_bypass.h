#ifndef RMF_SITE_BYPASS_H
#define RMF_SITE_BYPASS_H

#include <stdbool.h>
#include <stddef.h>

typedef struct {
    const char *domain;
    const char *ip;
} site_preset_pin_t;

typedef struct {
    const char *name;
    const char *chain;
    const char *const *domains;
    size_t domain_count;
    int dns_port;
    int relay_port;
    unsigned int mark;
    const char *primary_dns;
    const char *fallback_dns;
    int (*validate_ip)(const char *ip);
    const char *const *fallback_ips;
    size_t fallback_count;
    // -1 = решить самому (по умолчанию), 0 = только DNS, 1 = с релем.
    // Решает site_probe: если хотя бы один адрес молчит на ClientHello,
    // домен режут по имени и рель необходим; если все отвечают — рель
    // не нужен и только мешает.
    int use_relay;
    // Точечные прибивки «домен -> адрес». Нужны там, где у одного доменного
    // имени разные хосты требуют разных адресов (spotify: веб отдаётся с
    // 151.101.x, а API — с 35.186.224.24) либо где разрешение нестабильно.
    // Проверка: адрес должен быть разрешён validate_ip, иначе игнорируется.
    const site_preset_pin_t *preset_pins;
    size_t preset_count;
} site_bypass_config_t;

typedef struct {
    int dns_pid;
    int dns_fd;
    int dns_port;
    int relay_port;
    unsigned int mark;
    bool active;
    bool rules_installed;
    char primary[32];
    char fallback[32];
    char chain[64];
    bool relay_on;
} site_bypass_state_t;

int site_bypass_start(site_bypass_state_t *state, const site_bypass_config_t *config);
void site_bypass_stop(site_bypass_state_t *state);
int site_bypass_active(const site_bypass_state_t *state);

#endif
