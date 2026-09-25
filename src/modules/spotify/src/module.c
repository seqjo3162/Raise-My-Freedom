#include "src/modules/spotify/include/header.h"
#include <stddef.h>

static const char *const site_domains[] = {
    "spotify.com",
    "scdn.co",
    "spotifycdn.com",
    NULL
};

#define SITE_MODULE_PREFIX spotify
#define SITE_MODULE_CONFIG spotify_config_t
#define SITE_MODULE_CTX spotify_ctx_t
#define SITE_MODULE_CHAIN "SPOTIFY_BYPASS"
#define SITE_DNS_PORT 18556
#define SITE_RELAY_PORT 18456
#define SITE_MARK 0x4d66
#define SITE_LABEL "SPOTIFY"
#include "src/common/site_module_impl.h"
