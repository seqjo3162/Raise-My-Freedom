#include "src/modules/9gag/include/header.h"
#include <stddef.h>

static const char *const site_domains[] = {
    "9gag.com",
    NULL
};

#define SITE_MODULE_PREFIX ninegag
#define SITE_MODULE_CONFIG ninegag_config_t
#define SITE_MODULE_CTX ninegag_ctx_t
#define SITE_MODULE_CHAIN "NINEGAG_BYPASS"
#define SITE_DNS_PORT 18552
#define SITE_RELAY_PORT 18452
#define SITE_MARK 0x4d62
#define SITE_LABEL "9GAG"
#include "src/common/site_module_impl.h"
