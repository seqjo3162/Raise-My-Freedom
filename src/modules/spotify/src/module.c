#include "src/modules/spotify/include/header.h"
#include "src/common/site_bypass.h"
#include <stddef.h>
#include <string.h>
#include <strings.h>

// Spotify. Модуль закрепляет домены за проверенными адресами: прямой DNS по UDP
// с этой машины не доходит (8.8.8.8 и 1.1.1.1 по UDP молчат, проверено
// 2026-09-26), а без закреплений ответчик пересылает запрос вверх и не отвечает
// — домен не резолвится вовсе.
//
// Важно: хосты требуют РАЗНЫХ адресов, проверено 2026-09-26:
//   open.spotify.com   -> 151.101.x, страница отдаётся целиком (163848 байт);
//                        на 35.186.224.24 тот же хост отвечает 403 с пустым телом
//   api.spotify.com    -> 35.186.224.24 (301), на 151.101.x не отвечает
//   spclient.wg.spotify.com -> 35.186.224.24
// Поэтому домены перечислены поимённо и раньше apex: поддомен находит своё
// закрепление первым. Домены scdn.co и spotifycdn.com убраны — A-записей у них
// больше нет.
static const char *const spotify_domains[] = {
    "open.spotify.com",
    "spclient.wg.spotify.com",
    "api.spotify.com",
    "spotify.com",
    NULL
};

static const char *const spotify_good_ips[] = {
    "35.186.224.24",
    "151.101.195.42",
    "151.101.3.42",
    "151.101.67.42",
    NULL
};

// Точечные прибивки: у одного домена разные хоты требуют разных адресов,
// и разрешение для них нестабильно, поэтому адреса заданы явно.
static const site_preset_pin_t spotify_preset_pins[] = {
    { "open.spotify.com",       "151.101.195.42" },
    { "api.spotify.com",        "35.186.224.24"  },
    { "spclient.wg.spotify.com","35.186.224.24"  },
};

static int spotify_ip_allowed(const char *ip) {
    if (!ip) return 0;
    for (int i = 0; spotify_good_ips[i]; i++)
        if (strcasecmp(ip, spotify_good_ips[i]) == 0) return 1;
    return 0;
}

#define SITE_MODULE_PREFIX spotify
#define SITE_MODULE_CONFIG spotify_config_t
#define SITE_MODULE_CTX spotify_ctx_t
#define SITE_MODULE_CHAIN "SPOTIFY_BYPASS"
#define SITE_DNS_PORT 18556
#define SITE_RELAY_PORT 18456
#define SITE_MARK 0x4d66
#define SITE_LABEL "SPOTIFY"
#define SITE_EXTRA_DOMAINS spotify_domains
#define SITE_EXTRA_FALLBACK_IPS spotify_good_ips
#define SITE_EXTRA_FALLBACK_COUNT 4
#define SITE_EXTRA_VALIDATE_IP spotify_ip_allowed
#define SITE_EXTRA_PRESET_PINS spotify_preset_pins
#define SITE_EXTRA_PRESET_COUNT 3
#include "src/common/site_module_impl.h"
