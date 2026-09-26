#include "src/common/site_bypass.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#ifndef SITE_MODULE_PREFIX
#error SITE_MODULE_PREFIX is required
#endif
#ifndef SITE_MODULE_CONFIG
#error SITE_MODULE_CONFIG is required
#endif
#ifndef SITE_MODULE_CTX
#error SITE_MODULE_CTX is required
#endif
#ifndef SITE_MODULE_CHAIN
#error SITE_MODULE_CHAIN is required
#endif
#ifndef SITE_DNS_PORT
#error SITE_DNS_PORT is required
#endif
#ifndef SITE_RELAY_PORT
#error SITE_RELAY_PORT is required
#endif
#ifndef SITE_MARK
#error SITE_MARK is required
#endif
#ifndef SITE_LABEL
#error SITE_LABEL is required
#endif

// Необязательные переопределения. По умолчанию поведение прежнее: обычный
// список доменов, без проверки адресов и без запасных. Модуль, которому нужны
// закреплённые заранее проверенные адреса, задаёт свои списки — тогда адреса
// от DoH, не прошедшие проверку, отбрасываются, и подставляется запасной.
#ifndef SITE_EXTRA_DOMAINS
#define SITE_EXTRA_DOMAINS site_domains
#endif
#ifndef SITE_EXTRA_FALLBACK_IPS
#define SITE_EXTRA_FALLBACK_IPS NULL
#define SITE_EXTRA_FALLBACK_COUNT 0
#endif
#ifndef SITE_EXTRA_PRESET_PINS
#define SITE_EXTRA_PRESET_PINS NULL
#define SITE_EXTRA_PRESET_COUNT 0
#endif

#ifndef SITE_EXTRA_VALIDATE_IP
#define SITE_EXTRA_VALIDATE_IP NULL
#endif
// -1 (по умолчанию) = решить пробой: домен режут по имени → рель, иначе только
// закрепление DNS. 0 — принудительно без реля, 1 — принудительно с релем.
#ifndef SITE_USE_RELAY
#define SITE_USE_RELAY (-1)
#endif

#define SITE_JOIN_INNER(a, b) a##_##b
#define SITE_JOIN(a, b) SITE_JOIN_INNER(a, b)
#define SITE_VAR(name) SITE_JOIN(SITE_MODULE_PREFIX, name)
#define SITE_FN(name) SITE_JOIN3(SITE_MODULE_PREFIX, module, name)
#define SITE_JOIN3_INNER(a, b, c) a##_##b##_##c
#define SITE_JOIN3(a, b, c) SITE_JOIN3_INNER(a, b, c)

static SITE_MODULE_CTX SITE_VAR(ctx) = {0};
static bool SITE_VAR(initialized) = false;
static site_bypass_state_t SITE_VAR(bypass);

static void SITE_FN(copy_dns)(char *dst, size_t size, const char *value,
                               const char *fallback) {
    snprintf(dst, size, "%s", value && *value ? value : fallback);
}

void SITE_FN(init)(SITE_MODULE_CONFIG *config) {
    if (SITE_VAR(initialized)) return;
    memset(&SITE_VAR(ctx), 0, sizeof(SITE_VAR(ctx)));
    SITE_VAR(ctx).socket_fd = -1;
    SITE_FN(copy_dns)(SITE_VAR(ctx).primary, sizeof(SITE_VAR(ctx).primary),
                      config ? config->primary_dns : NULL, "1.1.1.1");
    SITE_FN(copy_dns)(SITE_VAR(ctx).fallback, sizeof(SITE_VAR(ctx).fallback),
                      config ? config->fallback_dns : NULL, "8.8.8.8");
    SITE_VAR(initialized) = true;
    fprintf(stderr, "[%s] initialized\n", SITE_LABEL);
}

void SITE_FN(cleanup)(void) {
    if (!SITE_VAR(initialized)) return;
    SITE_FN(remove)();
    SITE_VAR(initialized) = false;
    fprintf(stderr, "[%s] cleaned up\n", SITE_LABEL);
}

void SITE_FN(inject)(int fd) {
    (void)fd;
    if (!SITE_VAR(initialized)) return;
    site_bypass_config_t config = {
        .name = SITE_LABEL,
        .chain = SITE_MODULE_CHAIN,
        .domains = SITE_EXTRA_DOMAINS,
        .domain_count = sizeof(SITE_EXTRA_DOMAINS) / sizeof(SITE_EXTRA_DOMAINS[0]) - 1,
        .dns_port = SITE_DNS_PORT,
        .relay_port = SITE_RELAY_PORT,
        .mark = SITE_MARK,
        .primary_dns = SITE_VAR(ctx).primary,
        .fallback_dns = SITE_VAR(ctx).fallback,
        .validate_ip = SITE_EXTRA_VALIDATE_IP,
        .preset_pins = SITE_EXTRA_PRESET_PINS,
        .preset_count = SITE_EXTRA_PRESET_COUNT,
        .fallback_ips = SITE_EXTRA_FALLBACK_IPS,
        .fallback_count = SITE_EXTRA_FALLBACK_COUNT,
        .use_relay = SITE_USE_RELAY,
    };
    if (site_bypass_start(&SITE_VAR(bypass), &config) == 0) {
        SITE_VAR(ctx).mode = 1;
        fprintf(stderr, "[%s] active\n", SITE_LABEL);
    } else {
        SITE_VAR(ctx).mode = 0;
        fprintf(stderr, "[%s] start failed\n", SITE_LABEL);
    }
}

void SITE_FN(remove)(void) {
    if (!SITE_VAR(initialized)) return;
    site_bypass_stop(&SITE_VAR(bypass));
    SITE_VAR(ctx).mode = 0;
    fprintf(stderr, "[%s] removed\n", SITE_LABEL);
}

const char *SITE_FN(get_status)(void) {
    if (!SITE_VAR(initialized)) return "Not loaded";
    return site_bypass_active(&SITE_VAR(bypass)) ? "Active" : "Inactive";
}

const char *SITE_JOIN(SITE_MODULE_PREFIX, get_status)(void) {
    return SITE_FN(get_status)();
}
