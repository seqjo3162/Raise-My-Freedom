#include "src/modules/steam/include/header.h"
#include <stddef.h>

static const char *const site_domains[] = {
    "steampowered.com",
    "steamcommunity.com",
    "steamstatic.com",
    NULL
};

#define SITE_MODULE_PREFIX steam
#define SITE_MODULE_CONFIG steam_config_t
#define SITE_MODULE_CTX steam_ctx_t
#define SITE_MODULE_CHAIN "STEAM_BYPASS"
#define SITE_DNS_PORT 18568
#define SITE_RELAY_PORT 18468
#define SITE_MARK 0x4d72
#define SITE_LABEL "STEAM"
#include "src/common/site_module_impl.h"
