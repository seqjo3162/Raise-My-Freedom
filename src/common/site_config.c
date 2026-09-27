// Разбор и запись файла параметров модуля (module.conf).
//
// Формат намеренно плоский: key = value, без вложенности и кавычек.
// Такой файл одинаково удобно писать руками, читать глазами и генерировать
// из веба, а разбирается он без внешних библиотек — в проекте ничего, кроме
// C, и не должно появиться.

#include "site_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

static const char *const METHOD_NAMES[] = { "sni", "relay", "pin", "drop" };

const char *site_method_name(site_method_t m) {
    if (m < SITE_METHOD_SNI || m > SITE_METHOD_DROP) return "sni";
    return METHOD_NAMES[m];
}

site_method_t site_method_from_name(const char *name) {
    if (!name) return SITE_METHOD_SNI;
    for (int i = 0; i <= SITE_METHOD_DROP; i++)
        if (strcasecmp(name, METHOD_NAMES[i]) == 0) return (site_method_t)i;
    return SITE_METHOD_SNI;
}

void site_config_defaults(site_config_t *cfg) {
    if (!cfg) return;
    memset(cfg, 0, sizeof(*cfg));
    cfg->method = SITE_METHOD_SNI;
    cfg->mark = 0x4d50;
    snprintf(cfg->primary_dns, sizeof(cfg->primary_dns), "1.1.1.1");
    snprintf(cfg->fallback_dns, sizeof(cfg->fallback_dns), "8.8.8.8");
}

static char *trim(char *s) {
    while (*s == ' ' || *s == '\t') s++;
    char *e = s + strlen(s);
    while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' || e[-1] == '\n')) *--e = '\0';
    return s;
}

// Комментарий с # до конца строки, но не внутри значения: в значении
// решётки быть не может, так что сноска прямо на месте.
static void strip_comment(char *s) {
    char *h = strchr(s, '#');
    if (h) *h = '\0';
}

static int parse_int(const char *v, int *out) {
    char *end = NULL;
    errno = 0;
    long n = strtol(v, &end, 0);          // 0x понимается сам
    if (errno || end == v || *end) return -1;
    *out = (int)n;
    return 0;
}

static int parse_uint(const char *v, unsigned int *out) {
    char *end = NULL;
    errno = 0;
    unsigned long n = strtoul(v, &end, 0);
    if (errno || end == v || *end) return -1;
    *out = (unsigned int)n;
    return 0;
}

static int add_domain(site_config_t *c, const char *v) {
    if (c->domain_count >= SITE_CONF_MAX_DOMAINS) return -1;
    snprintf(c->domains[c->domain_count], SITE_CONF_MAX_HOST, "%s", v);
    c->domain_count++;
    return 0;
}

static int add_cidr(site_config_t *c, const char *v) {
    if (c->cidr_count >= SITE_CONF_MAX_CIDR) return -1;
    snprintf(c->cidrs[c->cidr_count], SITE_CONF_MAX_HOST, "%s", v);
    c->cidr_count++;
    return 0;
}

static int add_fallback(site_config_t *c, const char *v) {
    if (c->fallback_count >= SITE_CONF_MAX_FALLBACK) return -1;
    snprintf(c->fallback_ips[c->fallback_count], SITE_CONF_MAX_HOST, "%s", v);
    c->fallback_count++;
    return 0;
}

int site_config_load(const char *path, site_config_t *cfg, char *err, size_t errsz) {
    if (!path || !cfg) return -1;
    FILE *f = fopen(path, "r");
    if (!f) {
        // Файла нет — это штатный случай, модуль остаётся на #define.
        if (err && errsz) snprintf(err, errsz, "нет файла %s", path);
        return -1;
    }
    site_config_defaults(cfg);
    char line[SITE_CONF_MAX_LINE];
    int lineno = 0;
    while (fgets(line, sizeof(line), f)) {
        lineno++;
        strip_comment(line);
        char *s = trim(line);
        if (!*s) continue;
        char *eq = strchr(s, '=');
        if (!eq) {
            snprintf(err, errsz, "строка %d: нет '='", lineno);
            fclose(f);
            return -2;
        }
        *eq = '\0';
        char *key = trim(s);
        char *val = trim(eq + 1);
        if (!*val) {
            snprintf(err, errsz, "строка %d: у '%s' пустое значение", lineno, key);
            fclose(f);
            return -2;
        }
        if (!strcmp(key, "label"))
            snprintf(cfg->label, sizeof(cfg->label), "%s", val);
        else if (!strcmp(key, "chain"))
            snprintf(cfg->chain, sizeof(cfg->chain), "%s", val);
        else if (!strcmp(key, "primary_dns"))
            snprintf(cfg->primary_dns, sizeof(cfg->primary_dns), "%s", val);
        else if (!strcmp(key, "fallback_dns"))
            snprintf(cfg->fallback_dns, sizeof(cfg->fallback_dns), "%s", val);
        else if (!strcmp(key, "method")) {
            char low[32];
            snprintf(low, sizeof(low), "%s", val);
            for (size_t i = 0; low[i]; i++) low[i] = (char)tolower((unsigned char)low[i]);
            int found = -1;
            for (int i = 0; i <= SITE_METHOD_DROP; i++)
                if (!strcmp(low, METHOD_NAMES[i])) found = i;
            if (found < 0) {
                snprintf(err, errsz, "строка %d: метод '%s' неизвестен", lineno, val);
                fclose(f);
                return -2;
            }
            cfg->method = (site_method_t)found;
        } else if (!strcmp(key, "dns_port")) {
            if (parse_int(val, &cfg->dns_port)) {
                snprintf(err, errsz, "строка %d: dns_port '%s' не число", lineno, val);
                fclose(f);
                return -2;
            }
        } else if (!strcmp(key, "relay_port")) {
            if (parse_int(val, &cfg->relay_port)) {
                snprintf(err, errsz, "строка %d: relay_port '%s' не число", lineno, val);
                fclose(f);
                return -2;
            }
        } else if (!strcmp(key, "mark")) {
            if (parse_uint(val, &cfg->mark)) {
                snprintf(err, errsz, "строка %d: mark '%s' не число", lineno, val);
                fclose(f);
                return -2;
            }
        } else if (!strcmp(key, "domain")) {
            if (add_domain(cfg, val)) {
                snprintf(err, errsz, "строка %d: больше %d доменов", lineno, SITE_CONF_MAX_DOMAINS);
                fclose(f);
                return -2;
            }
        } else if (!strcmp(key, "cidr")) {
            if (add_cidr(cfg, val)) {
                snprintf(err, errsz, "строка %d: больше %d диапазонов", lineno, SITE_CONF_MAX_CIDR);
                fclose(f);
                return -2;
            }
        } else if (!strcmp(key, "fallback_ip")) {
            if (add_fallback(cfg, val)) {
                snprintf(err, errsz, "строка %d: больше %d запасных адресов", lineno, SITE_CONF_MAX_FALLBACK);
                fclose(f);
                return -2;
            }
        } else {
            // Неизвестный ключ — повод смотреть файл, а не молчалить.
            snprintf(err, errsz, "строка %d: неизвестный ключ '%s'", lineno, key);
            fclose(f);
            return -2;
        }
    }
    fclose(f);
    return 0;
}

static int valid_chain(const char *s) {
    if (!s || !*s) return 0;
    for (const char *p = s; *p; p++)
        if (!isalnum((unsigned char)*p) && *p != '_') return 0;
    return 1;
}

static int valid_host(const char *s) {
    if (!s || !*s) return 0;
    for (const char *p = s; *p; p++) {
        if (isalnum((unsigned char)*p) || *p == '.' || *p == '-' || *p == '_') continue;
        return 0;   // пробел, слэш, двоеточие, точка с запятой
    }
    return 1;
}

static int valid_ipv4(const char *s, int allow_prefix) {
    // Свой разбор ниже строже любой проверки символов: он принимает только
    // цифры, точки и, при allow_prefix, один слэш с числом после. Проверка
    // через valid_host тут стояла и ломала всё: тот / не пропускает, и до
    // разбора префикса дело не доходило.
    if (!s || !*s) return 0;
    int parts = 0;
    const char *p = s;
    int val = -1;
    for (;;) {
        if (!isdigit((unsigned char)*p)) return 0;
        val = 0;
        int digits = 0;
        while (isdigit((unsigned char)*p)) {
            val = val * 10 + (*p - '0');
            p++;
            if (++digits > 3 || val > 255) return 0;
        }
        parts++;
        if (*p == '.') { p++; continue; }
        if (*p == '\0') break;
        if (*p == '/') {
            if (!allow_prefix) return 0;
            p++;
            if (!isdigit((unsigned char)*p)) return 0;
            int bits = 0;
            while (isdigit((unsigned char)*p)) { bits = bits * 10 + (*p - '0'); p++; }
            if (*p || bits < 0 || bits > 32) return 0;
            return parts == 4;
        }
        return 0;
    }
    return parts == 4;
}

int site_config_validate(const site_config_t *cfg, char *err, size_t errsz) {
    if (!cfg) return -1;
#define FAIL(...) do { if (err && errsz) snprintf(err, errsz, __VA_ARGS__); return -1; } while (0)

    if (cfg->label[0] && !valid_host(cfg->label)) FAIL("метка «%s»: только буквы, цифры, дефис, точка", cfg->label);
    if (cfg->chain[0] && !valid_chain(cfg->chain)) FAIL("цепочка «%s»: только буквы, цифры, подчёркивание", cfg->chain);
    if (cfg->dns_port < 0 || cfg->dns_port > 65535) FAIL("dns_port %d вне 1..65535", cfg->dns_port);
    if (cfg->relay_port < 0 || cfg->relay_port > 65535) FAIL("relay_port %d вне 1..65535", cfg->relay_port);
    if (cfg->dns_port == cfg->relay_port && cfg->dns_port != 0)
        FAIL("dns_port и relay_port совпадают (%d) — перехват зациклится", cfg->dns_port);
    if (cfg->mark < 0x4d50u || cfg->mark > 0x4d5fu)
        FAIL("метка 0x%x вне 0x4d50..0x4d5f: правило исключения собственного трафика её не пропустит",
             cfg->mark);
    if (cfg->primary_dns[0] && !valid_ipv4(cfg->primary_dns, 0)) FAIL("primary_dns «%s» не адрес", cfg->primary_dns);
    if (cfg->fallback_dns[0] && !valid_ipv4(cfg->fallback_dns, 0)) FAIL("fallback_dns «%s» не адрес", cfg->fallback_dns);
    for (size_t i = 0; i < cfg->domain_count; i++)
        if (!valid_host(cfg->domains[i])) FAIL("домен «%s»: только буквы, цифры, дефис и точка", cfg->domains[i]);
    for (size_t i = 0; i < cfg->cidr_count; i++)
        if (!valid_ipv4(cfg->cidrs[i], 1)) FAIL("диапазон «%s»: нужен адрес или a.b.c.d/nn", cfg->cidrs[i]);
    for (size_t i = 0; i < cfg->fallback_count; i++)
        if (!valid_ipv4(cfg->fallback_ips[i], 0)) FAIL("запасной адрес «%s» не адрес", cfg->fallback_ips[i]);
#undef FAIL
    return 0;
}

int site_config_save(const char *path, const site_config_t *cfg, char *err, size_t errsz) {
    if (!path || !cfg) return -1;
    if (site_config_validate(cfg, err, errsz) != 0) return -1;

    // Пишем во временный файл и переименовываем: если обрыв на середине,
    // старый файл останется целым.
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f) {
        if (err && errsz) snprintf(err, errsz, "не открыть для записи: %s", strerror(errno));
        return -1;
    }
    fprintf(f, "# Параметры модуля. Правь руками или через веб — файл\n"
               "# перекрывает значения, собранные из макросов.\n");
    if (cfg->label[0])       fprintf(f, "label        = %s\n", cfg->label);
    if (cfg->chain[0])       fprintf(f, "chain        = %s\n", cfg->chain);
    fprintf(f, "method       = %s\n", site_method_name(cfg->method));
    fprintf(f, "dns_port     = %d\n", cfg->dns_port);
    fprintf(f, "relay_port   = %d\n", cfg->relay_port);
    fprintf(f, "mark         = 0x%02x\n", cfg->mark);
    fprintf(f, "primary_dns  = %s\n", cfg->primary_dns);
    fprintf(f, "fallback_dns = %s\n", cfg->fallback_dns);
    for (size_t i = 0; i < cfg->domain_count; i++)     fprintf(f, "domain       = %s\n", cfg->domains[i]);
    for (size_t i = 0; i < cfg->cidr_count; i++)       fprintf(f, "cidr         = %s\n", cfg->cidrs[i]);
    for (size_t i = 0; i < cfg->fallback_count; i++)   fprintf(f, "fallback_ip  = %s\n", cfg->fallback_ips[i]);
    if (fclose(f) != 0) {
        if (err && errsz) snprintf(err, errsz, "ошибка записи: %s", strerror(errno));
        remove(tmp);
        return -1;
    }
    if (rename(tmp, path) != 0) {
        if (err && errsz) snprintf(err, errsz, "переименование не удалось: %s", strerror(errno));
        remove(tmp);
        return -1;
    }
    return 0;
}
