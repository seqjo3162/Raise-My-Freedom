#include "src/modules/hf/include/header.h"
#include <stddef.h>
#include <string.h>
#include <strings.h>

// Hugging Face. Провайдер отбрасывает часть адресов CloudFront, на которые
// указывает DNS. Раньше здесь был белый список из двух адресов, и всё
// остальное отбрасывалось проверкой hf_ip_allowed.
//
// Это сломало модуль. Проверено на живых данных: оба адреса из списка
// переназначены Amazon'у и больше не обслуживают huggingface.
//   3.161.105.31  отдаёт CN=dp-contacts-opf.amazon.com
//   99.84.108.22  отдаёт CN=r.amazon.com
// Настоящие адреса в список не попадали, hf_ip_allowed отвергал их все, и в
// DNS уходил 3.161.105.31. Следствие: hf.co, cdn-lfs.huggingface.co и
// cdn-oauth.huggingface.co отдавали TLS-ошибку, HTTP 000.
//
// Списка адресов здесь теперь нет намеренно. CloudFront обслуживает на одном
// адресе много доменов и по SNI отдаёт сертификат того, который попался
// первым, поэтому адрес, годный для hf.co, проходил проверку и тут же
// закреплялся за huggingface.co и cdn-lfs — те получали чужой сертификат.
// Отбор адреса теперь сверяет имя в сертификате (site_probe_cert_ok в
// site_bypass), а зарезанные провайдером адреса и так отсекаются пробой TCP.
//
// Два имени убраны как мёртвые: cdn-lfs.huggingface.co и
// cdn-oauth.huggingface.co не имеют A-записей в публичном DNS (проверено
// 2026-09-27 через DoH Cloudflare). Пока они были в списке, домен без
// A-записей уходил в запасные адреса и закреплялся за чужим сертификатом.
// Оставлены реальные адреса: hf.co — 18.213.84.241, 3.210.66.237,
// 34.198.14.237, 34.202.8.246, 34.204.155.59, 44.212.132.255.
static const char *const hf_domains[] = {
    "huggingface.co",
    "hf.co",
    "cdn-lfs-us-1.hf.co",
    "cdn-lfs-eu-1.hf.co",
    "datasets-server.huggingface.co",
    "cas-bridge.xethub.hf.co",
    "transfer.xethub.hf.co",
    NULL
};

// Запасных адресов нет. Список для всех доменов сразу создавал ровно ту
// поломку, которую чинили: hf.co-адрес подставлялся к cdn-lfs, тот получал
// чужой сертификат и не грузился. Если DoH не ответил, лучше оставить домен
// без закрепления, чем закрепить его за чужим сертификатом.
#define SITE_MODULE_PREFIX hf
#define SITE_MODULE_CONFIG hf_config_t
#define SITE_MODULE_CTX hf_ctx_t
#define SITE_MODULE_CHAIN "HF_BYPASS"
#define SITE_DNS_PORT 18595
#define SITE_RELAY_PORT 18495
#define SITE_MARK 0x4d95
#define SITE_LABEL "HF"
#define SITE_EXTRA_DOMAINS hf_domains
#include "src/common/site_module_impl.h"
