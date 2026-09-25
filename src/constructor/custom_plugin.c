// Универсальный раннер для модулей, созданных в конструкторе.
//
// Сам по себе ничего не знает о доменах: читает спецификацию
// webui/custom/active.json и передаёт её движку site_bypass.
// Один бинарник обслуживает любой модуль из конструктора.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

#include "src/constructor/custom_plugin.h"
#include "src/common/site_bypass.h"

#define MAX_DOMAINS 64
#define SPEC_PATH_ENV "RMF_SPEC"
#define SPEC_PATH_ENV_LEGACY "MINIZAPRET_SPEC"
#define SPEC_DEFAULT "webui/custom/active.json"

static char g_name[64] = "custom";
static char g_chain[64] = "CUSTOM";
static char g_domains[MAX_DOMAINS][128];
static int  g_domain_count = 0;
static char g_primary[64] = "1.1.1.1";
static char g_fallback[64] = "8.8.8.8";
static int  g_dns_port = 1053;
static int  g_relay_port = 18443;
static unsigned int g_mark = 20100;

static site_bypass_state_t g_bypass;
static bool g_loaded = false;
static bool g_active = false;
static char g_status[128] = "Not loaded";

// ── мини-разбор JSON ──
static const char *jfind(const char *json, const char *key) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return NULL;
    p = strchr(p + strlen(pat), ':');
    if (!p) return NULL;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

static void jstr(const char *json, const char *key, char *out, size_t cap) {
    const char *p = jfind(json, key);
    if (!p || *p != '"') return;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i < cap - 1) out[i++] = *p++;
    out[i] = '\0';
}

static int jint(const char *json, const char *key, int dflt) {
    const char *p = jfind(json, key);
    if (!p) return dflt;
    if (*p == '"') p++;
    return atoi(p);
}

static void jdomains(const char *json) {
    const char *p = jfind(json, "domains");
    if (!p || *p != '[') return;
    p++;
    while (*p && *p != ']' && g_domain_count < MAX_DOMAINS) {
        while (*p == ' ' || *p == ',') p++;
        if (*p != '"') break;
        p++;
        size_t i = 0;
        while (*p && *p != '"' && i < 127) g_domains[g_domain_count][i++] = *p++;
        g_domains[g_domain_count][i] = '\0';
        if (*p == '"') p++;
        if (i) g_domain_count++;
    }
}

static bool load_spec(void) {
    const char *path = getenv(SPEC_PATH_ENV);
    if (!path || !*path) path = getenv(SPEC_PATH_ENV_LEGACY);
    if (!path || !*path) path = SPEC_DEFAULT;
    FILE *f = fopen(path, "r");
    if (!f) {
        snprintf(g_status, sizeof(g_status), "нет спецификации: %s", path);
        fprintf(stderr, "[custom] %s\n", g_status);
        return false;
    }
    static char json[65536];
    size_t got = fread(json, 1, sizeof(json) - 1, f);
    fclose(f);
    json[got] = '\0';
    if (got == 0) {
        snprintf(g_status, sizeof(g_status), "спецификация пуста");
        return false;
    }

    jstr(json, "name", g_name, sizeof(g_name));
    jstr(json, "chain", g_chain, sizeof(g_chain));
    jstr(json, "primary_dns", g_primary, sizeof(g_primary));
    jstr(json, "fallback_dns", g_fallback, sizeof(g_fallback));
    g_dns_port   = jint(json, "dns_port", g_dns_port);
    g_relay_port = jint(json, "relay_port", g_relay_port);
    g_mark       = (unsigned)jint(json, "mark", (int)g_mark);
    jdomains(json);

    if (g_domain_count == 0) {
        snprintf(g_status, sizeof(g_status), "в спецификации нет доменов");
        fprintf(stderr, "[custom] %s\n", g_status);
        return false;
    }
    snprintf(g_status, sizeof(g_status), "загружено: %s (%d доменов)", g_name, g_domain_count);
    return true;
}

void custom_init(void *config) {
    (void)config;
    if (g_loaded) return;
    g_loaded = load_spec();
    fprintf(stderr, "[custom] %s\n", g_status);
}

void custom_inject(int fd) {
    (void)fd;
    if (!g_loaded) return;
    if (g_active) return;
    if (g_dns_port == g_relay_port) {
        snprintf(g_status, sizeof(g_status), "dns_port и relay_port совпадают (%d)", g_dns_port);
        fprintf(stderr, "[custom] %s\n", g_status);
        return;
    }
    const char *domains[MAX_DOMAINS];
    for (int i = 0; i < g_domain_count; i++) domains[i] = g_domains[i];

    site_bypass_config_t config = {
        .name = g_name,
        .chain = g_chain,
        .domains = domains,
        .domain_count = g_domain_count,
        .dns_port = g_dns_port,
        .relay_port = g_relay_port,
        .mark = g_mark,
        .primary_dns = g_primary,
        .fallback_dns = g_fallback,
    };
    if (site_bypass_start(&g_bypass, &config) == 0) {
        g_active = true;
        snprintf(g_status, sizeof(g_status), "активен: %s, dns:%d relay:%d", g_name, g_dns_port, g_relay_port);
        fprintf(stderr, "[custom] %s\n", g_status);
    } else {
        g_active = false;
        snprintf(g_status, sizeof(g_status), "движок отклонил спецификацию — проверьте цепочку и порты");
        fprintf(stderr, "[custom] %s\n", g_status);
    }
}

void custom_remove(void) {
    if (!g_active) return;
    site_bypass_stop(&g_bypass);
    g_active = false;
    fprintf(stderr, "[custom] снят\n");
}

void custom_cleanup(void) {
    if (!g_loaded) return;
    custom_remove();
    g_loaded = false;
    snprintf(g_status, sizeof(g_status), "Not loaded");
    fprintf(stderr, "[custom] выгружен\n");
}

const char *custom_get_status(void) {
    return g_status;
}
