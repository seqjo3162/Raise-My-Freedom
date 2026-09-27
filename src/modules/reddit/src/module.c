#include "src/modules/reddit/include/header.h"
#include "src/common/site_bypass.h"
#include <stddef.h>
#include <string.h>
#include <strings.h>

// Reddit. Модуль закрепляет домены за проверенными адресами: прямой DNS по UDP
// с этой машины не доходит (проверено 2026-09-26: запросы к 8.8.8.8 и 1.1.1.1
// по UDP не отвечают), поэтому без закреплений ответчик обязан пересылать
// запрос вверх и на этом молчит — сайт становится недоступен целиком.
// Адреса проверены 2026-09-26: TLS и сертификат сходятся под именем домена.
// redditstatic.com в списке не было: A-записи у него больше нет.
static const char *const reddit_domains[] = {
    "reddit.com",
    "redd.it",
    "redditmedia.com",
    NULL
};

static const char *const reddit_good_ips[] = {
    "151.101.193.140",
    "151.101.1.140",
    "151.101.65.140",
    NULL
};

// Точечные прибивки: адреса reddit проверены и не меняются, а разрешение
// для них нестабильно, поэтому заданы явно.
static const site_preset_pin_t reddit_preset_pins[] = {
    { "reddit.com",       "151.101.193.140" },
    { "redd.it",          "151.101.193.140" },
    { "redditmedia.com",  "151.101.193.140" },
};

static int reddit_ip_allowed(const char *ip) {
    if (!ip) return 0;
    for (int i = 0; reddit_good_ips[i]; i++)
        if (strcasecmp(ip, reddit_good_ips[i]) == 0) return 1;
    return 0;
}

#define SITE_MODULE_PREFIX reddit
#define SITE_MODULE_CONFIG reddit_config_t
#define SITE_MODULE_CTX reddit_ctx_t
#define SITE_MODULE_CHAIN "REDDIT_BYPASS"
#define SITE_DNS_PORT 18555
#define SITE_RELAY_PORT 18455
#define SITE_MARK 0x4d65
#define SITE_LABEL "REDDIT"
#define SITE_EXTRA_DOMAINS reddit_domains
#define SITE_EXTRA_FALLBACK_IPS reddit_good_ips
#define SITE_EXTRA_FALLBACK_COUNT 3
#define SITE_EXTRA_VALIDATE_IP reddit_ip_allowed
#define SITE_EXTRA_PRESET_PINS reddit_preset_pins
#define SITE_EXTRA_PRESET_COUNT 3
#include "src/common/site_module_impl.h"
