#include "src/modules/twitch/include/header.h"
#include <stddef.h>

static const char *const site_domains[] = {
    "twitch.tv",
    "ttvnw.net",
    "jtvnw.net",
    NULL
};

#define SITE_MODULE_PREFIX twitch
#define SITE_MODULE_CONFIG twitch_config_t
#define SITE_MODULE_CTX twitch_ctx_t
#define SITE_MODULE_CHAIN "TWITCH_BYPASS"
#define SITE_DNS_PORT 18558
#define SITE_RELAY_PORT 18458
#define SITE_MARK 0x4d68
#define SITE_LABEL "TWITCH"
#include "src/common/site_module_impl.h"
