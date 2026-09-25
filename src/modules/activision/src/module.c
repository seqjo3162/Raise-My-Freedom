#include "src/modules/activision/include/header.h"
#include <stddef.h>

static const char *const site_domains[] = {
    "activision.com",
    "callofduty.com",
    "profile.callofduty.com",
    "support.activision.com",
    NULL
};

#define SITE_MODULE_PREFIX activision
#define SITE_MODULE_CONFIG activision_config_t
#define SITE_MODULE_CTX activision_ctx_t
#define SITE_MODULE_CHAIN "ACTIVISION_BYPASS"
#define SITE_DNS_PORT 18562
#define SITE_RELAY_PORT 18462
#define SITE_MARK 0x4d6c
#define SITE_LABEL "ACTIVISION"
#include "src/common/site_module_impl.h"
