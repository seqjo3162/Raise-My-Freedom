#include "src/modules/soundcloudcom/include/header.h"
#include <stddef.h>

static const char *const site_domains[] = {
    "soundcloud.com",
    "api.soundcloud.com",
    "scdn.co",
    "sndcdn.com",
    NULL
};

#define SITE_MODULE_PREFIX soundcloud
#define SITE_MODULE_CONFIG soundcloud_config_t
#define SITE_MODULE_CTX soundcloud_ctx_t
#define SITE_MODULE_CHAIN "SOUNDCLOUD_BYPASS"
#define SITE_DNS_PORT 18567
#define SITE_RELAY_PORT 18467
#define SITE_MARK 0x4d71
#define SITE_LABEL "SOUNDCLOUD"
#include "src/common/site_module_impl.h"
