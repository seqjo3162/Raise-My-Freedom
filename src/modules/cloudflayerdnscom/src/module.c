#include "src/modules/cloudflayerdnscom/include/header.h"
#include "src/dns/dns_resolve.h"
#include "src/dns/doh_resolve.h"

#include <stdio.h>
#include <string.h>

static cloudflayerdns_ctx_t ctx = {0};
static int cloudflayerdns_initialized;

static void copy_dns(char *dst, size_t size, const char *value, const char *fallback) {
    snprintf(dst, size, "%s", value && *value ? value : fallback);
}

void cloudflayerdns_module_init(cloudflayerdns_config_t *config) {
    if (cloudflayerdns_initialized) return;
    memset(&ctx, 0, sizeof(ctx));
    ctx.socket_fd = -1;
    copy_dns(ctx.primary, sizeof(ctx.primary), config ? config->primary_dns : NULL, "1.1.1.1");
    copy_dns(ctx.fallback, sizeof(ctx.fallback), config ? config->fallback_dns : NULL, "1.0.0.1");
    char *port = strchr(ctx.primary, ':');
    if (port) *port = '\0';
    port = strchr(ctx.fallback, ':');
    if (port) *port = '\0';
    cloudflayerdns_initialized = 1;
    fprintf(stderr, "[CLOUDFLAREDNS] initialized\n");
}

void cloudflayerdns_module_cleanup(void) {
    if (!cloudflayerdns_initialized) return;
    cloudflayerdns_module_remove();
    cloudflayerdns_initialized = 0;
    fprintf(stderr, "[CLOUDFLAREDNS] cleaned up\n");
}

void cloudflayerdns_module_inject(int fd) {
    (void)fd;
    if (!cloudflayerdns_initialized) return;
    char ip[64] = {0};
    int primary_ok = doh_resolve_a("cloudflare.com", ip, sizeof(ip)) == 0;
    if (!primary_ok)
        primary_ok = dns_resolve_udp(ctx.primary, "cloudflare.com", ip, sizeof(ip)) == 0;
    int fallback_ok = dns_resolve_udp(ctx.fallback, "cloudflare.com", ip, sizeof(ip)) == 0;
    ctx.mode = primary_ok || fallback_ok;
    fprintf(stderr, "[CLOUDFLAREDNS] primary=%s fallback=%s\n",
            primary_ok ? "ok" : "failed", fallback_ok ? "ok" : "failed");
}

void cloudflayerdns_module_remove(void) {
    if (!cloudflayerdns_initialized) return;
    ctx.mode = 0;
    fprintf(stderr, "[CLOUDFLAREDNS] removed\n");
}

const char *cloudflayerdns_get_status(void) {
    if (!cloudflayerdns_initialized) return "Off";
    return ctx.mode ? "Active (DNS reachable)" : "Unavailable";
}
