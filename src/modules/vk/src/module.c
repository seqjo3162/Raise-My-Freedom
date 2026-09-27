#include "src/modules/vk/include/header.h"
#include <stddef.h>

static const char *const site_domains[] = {
    "vk.com",
    "vk.ru",
    "vkuser.net",
    "vk-cdn.net",
    "userapi.com",
    NULL
};

#define SITE_MODULE_PREFIX vk
#define SITE_MODULE_CONFIG vk_config_t
#define SITE_MODULE_CTX vk_ctx_t
#define SITE_MODULE_CHAIN "VK_BYPASS"
#define SITE_DNS_PORT 18559
#define SITE_RELAY_PORT 18459
#define SITE_MARK 0x4d69
#define SITE_LABEL "VK"
#include "src/common/site_module_impl.h"
