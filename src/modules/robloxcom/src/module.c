#include "src/modules/robloxcom/include/header.h"
#include <stddef.h>

static const char *const site_domains[] = {
    "roblox.com",
    "robloxgames.com",
    "api.roblox.com",
    "assetdelivery.roblox.com",
    "avatar.roblox.com",
    "economy.roblox.com",
    "cdn.roblox.com",
    NULL
};

#define SITE_MODULE_PREFIX roblox
#define SITE_MODULE_CONFIG roblox_config_t
#define SITE_MODULE_CTX roblox_ctx_t
#define SITE_MODULE_CHAIN "ROBLOX_BYPASS"
#define SITE_DNS_PORT 18566
#define SITE_RELAY_PORT 18466
#define SITE_MARK 0x4d70
#define SITE_LABEL "ROBLOX"
#include "src/common/site_module_impl.h"
