#include "src/modules/github/include/header.h"
#include <stddef.h>

static const char *const site_domains[] = {
    "github.com",
    // Без этого ш��ла по суффиксу от github.com, и ssh.github.com уезжал на
    // адрес обычного сайта: 4.225.11.194 вместо 4.225.11.200. Соединение
    // закрывалось на handshake, и git push по ssh не проходил.
    "ssh.github.com",
    "gist.github.com",
    "codeload.github.com",
    "api.github.com",
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
    NULL
};

#define SITE_MODULE_PREFIX github
#define SITE_MODULE_CONFIG github_config_t
#define SITE_MODULE_CTX github_ctx_t
#define SITE_MODULE_CHAIN "GITHUB_BYPASS"
#define SITE_DNS_PORT 18590
#define SITE_RELAY_PORT 18490
#define SITE_MARK 0x4d5a
#define SITE_LABEL "GITHUB"
#include "src/common/site_module_impl.h"
