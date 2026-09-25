#include "src/modules/epicgames/include/header.h"
#include <stddef.h>

static const char *const site_domains[] = {
    "epicgames.com",
    "epicgames.dev",
    "store.epicgames.com",
    "launcher.epicgames.com",
    "accounts.epicgames.com",
    "unrealengine.com",
    "cdn.unrealengine.com",
    "download.epicgames.com",
    NULL
};

#define SITE_MODULE_PREFIX epicgames
#define SITE_MODULE_CONFIG epicgames_config_t
#define SITE_MODULE_CTX epicgames_ctx_t
#define SITE_MODULE_CHAIN "EPICGAMES_BYPASS"
#define SITE_DNS_PORT 18565
#define SITE_RELAY_PORT 18465
#define SITE_MARK 0x4d6f
#define SITE_LABEL "EPICGAMES"
#include "src/common/site_module_impl.h"
