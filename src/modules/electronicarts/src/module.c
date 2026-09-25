#include "src/modules/electronicarts/include/header.h"
#include <stddef.h>

static const char *const site_domains[] = {
    "ea.com",
    "origin.com",
    "eaassets-a.akamaihd.net",
    "answers.ea.com",
    "help.ea.com",
    "signin.ea.com",
    "store.ea.com",
    NULL
};

#define SITE_MODULE_PREFIX electronicarts
#define SITE_MODULE_CONFIG electronicarts_config_t
#define SITE_MODULE_CTX electronicarts_ctx_t
#define SITE_MODULE_CHAIN "ELECTRONICARTS_BYPASS"
#define SITE_DNS_PORT 18564
#define SITE_RELAY_PORT 18464
#define SITE_MARK 0x4d6e
#define SITE_LABEL "ELECTRONICARTS"
#include "src/common/site_module_impl.h"
