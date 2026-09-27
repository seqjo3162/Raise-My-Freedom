#include "src/modules/netflix/include/header.h"
#include <stddef.h>

static const char *const site_domains[] = {
    "netflix.com",
    "fast.com",
    "nflx.net",
    "nflximg.com",
    "nflxso.com",
    "nflxvideo.net",
    NULL
};

#define SITE_MODULE_PREFIX netflix
#define SITE_MODULE_CONFIG netflix_config_t
#define SITE_MODULE_CTX netflix_ctx_t
#define SITE_MODULE_CHAIN "NETFLIX_BYPASS"
#define SITE_DNS_PORT 18554
#define SITE_RELAY_PORT 18454
#define SITE_MARK 0x4d64
#define SITE_LABEL "NETFLIX"
#include "src/common/site_module_impl.h"
