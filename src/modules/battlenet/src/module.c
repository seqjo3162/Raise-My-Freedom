#include "src/modules/battlenet/include/header.h"
#include <stddef.h>

static const char *const site_domains[] = {
    "battle.net",
    "blizzard.com",
    "shop.blizzard.com",
    "account.blizzard.com",
    NULL
};

#define SITE_MODULE_PREFIX battlenet
#define SITE_MODULE_CONFIG battlenet_config_t
#define SITE_MODULE_CTX battlenet_ctx_t
#define SITE_MODULE_CHAIN "BATTLENET_BYPASS"
#define SITE_DNS_PORT 18563
#define SITE_RELAY_PORT 18463
#define SITE_MARK 0x4d6d
#define SITE_LABEL "BATTLENET"
#include "src/common/site_module_impl.h"
