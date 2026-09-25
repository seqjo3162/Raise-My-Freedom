#include "src/modules/telegram/include/header.h"

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static telegram_ctx_t ctx = {0};
static bool telegram_initialized = false;

// домены Telegram: клиент обращается напрямую, трафик заворачиваем на релей
static const char *tg_domains[] = {
    "telegram.org", "www.telegram.org", "web.telegram.org", "k telegram.org",
    "t.me", "core.telegram.org", NULL
};

telegram_ctx_t *telegram_get_ctx(void) { return &ctx; }

static int is_root(void) { return getuid() == 0; }

static void sh(const char *cmd) {
    int rc = system(cmd);
    (void)rc;
}

static void sh_check(const char *cmd) {
    int rc = system(cmd);
    if (rc == -1) fprintf(stderr, "[TG] iptables: не удалось выполнить: %s\n", cmd);
    else if (WIFEXITED(rc) && WEXITSTATUS(rc) != 0)
        fprintf(stderr, "[TG] iptables: ошибка %d: %s\n", WEXITSTATUS(rc), cmd);
}

// Читает webui/telegram.conf. main.c вызывает plugin.init(NULL), поэтому
// без этого все настройки из веб-интерфейса оставались бы незамеченными.
static void load_conf(char *secret, size_t secret_size, int *port, int *v6, int *tls) {
    FILE *f = fopen(TG_CONF_FILE, "r");
    if (!f) return;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char *v = eq + 1;
        char *nl = strpbrk(v, "\r\n");
        if (nl) *nl = '\0';
        if (!strcmp(line, "secret") && strlen(v) >= 32)
            snprintf(secret, secret_size, "%.32s", v);
        else if (!strcmp(line, "port") && atoi(v) > 0)
            *port = atoi(v);
        else if (!strcmp(line, "prefer_ipv6"))
            *v6 = atoi(v) ? 1 : 0;
        else if (!strcmp(line, "fake_tls"))
            *tls = atoi(v) ? 1 : 0;
    }
    fclose(f);
}

void telegram_module_init(telegram_config_t *config) {
    if (telegram_initialized) return;

    // 1) значения из файла — база
    char secret[64] = {0};
    int fport = TG_PROXY_PORT, fv6 = 1, ftls = 1;
    load_conf(secret, sizeof(secret), &fport, &fv6, &ftls);

    // 2) явный конфиг от вызывающего кода важнее файла
    if (config) {
        if (config->proxy_port > 0)    fport = config->proxy_port;
        if (config->prefer_ipv6 >= 0)  fv6 = config->prefer_ipv6 ? 1 : 0;
        if (config->use_fake_tls >= 0) ftls = config->use_fake_tls ? 1 : 0;
    }
    if (secret[0]) telegram_proxy_set_secret(secret);

    // DNS — Cloudflare, как и требуется для обхода
    strncpy(ctx.primary,  "1.1.1.1", sizeof(ctx.primary) - 1);
    strncpy(ctx.fallback, "1.0.0.1", sizeof(ctx.fallback) - 1);
    if (config && config->primary_dns)  strncpy(ctx.primary,  config->primary_dns,  sizeof(ctx.primary) - 1);
    if (config && config->fallback_dns) strncpy(ctx.fallback, config->fallback_dns, sizeof(ctx.fallback) - 1);
    ctx.primary[sizeof(ctx.primary) - 1]  = '\0';
    ctx.fallback[sizeof(ctx.fallback) - 1] = '\0';

    ctx.proxy_port   = fport;
    ctx.prefer_ipv6  = fv6;
    ctx.use_fake_tls = ftls;
    ctx.mode = 0;
    ctx.socket_fd = -1;
    ctx.listen_fd = -1;
    ctx.relay_pid = -1;
    ctx.relay_running = 0;

    telegram_initialized = true;
    // секрет показываем маской: он должен совпадать с тем, что введён в Telegram
    printf("[telegram] init: DNS %s / %s, MTProxy :%d (x6=%d x4=%d), mode=%s, secret=%s\n",
           ctx.primary, ctx.fallback, ctx.proxy_port, 6, 4,
           ctx.use_fake_tls ? "fake-TLS" : "classic",
           secret[0] ? secret : "(встроенный)");
}

void telegram_module_inject(int fd) {
    (void)fd;
    if (!telegram_initialized) return;
    if (telegram_proxy_running()) {
        ctx.mode = 1;
        return;
    }

    if (telegram_proxy_start(ctx.proxy_port) == 0) {
        ctx.mode = 1;
        printf("[telegram]   MTProxy слушает 127.0.0.1:%d (pid %d)\n", ctx.proxy_port, ctx.relay_pid);
    } else {
        fprintf(stderr, "[telegram]   MTProxy не запустился: %s\n", strerror(errno));
    }
}

void telegram_module_remove(void) {
    if (!telegram_initialized) return;
    telegram_proxy_stop();
    ctx.mode = 0;
    printf("[telegram] remove done\n");
}

void telegram_module_cleanup(void) {
    if (!telegram_initialized) return;
    telegram_module_remove();
    ctx.socket_fd = -1;
    telegram_initialized = false;
    printf("[telegram] cleanup done\n");
}

const char *telegram_get_status(void) {
    if (!telegram_initialized) return "Off";
    if (!ctx.mode) return "Idle";
    return telegram_proxy_running() ? "Active (MTProxy)" : "Active (MTProxy down!)";
}
