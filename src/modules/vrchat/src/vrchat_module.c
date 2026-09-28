#include "src/modules/vrchat/include/header.h"
#include "src/dns/doh_resolve.h"
#include <pthread.h>
#include "src/modules/vrchat/src/vrchat_discovery.h"
#include "src/common/site_probe.h"
#include "src/common/plain_relay.h"

#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <signal.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

// VRChat module: DNS pinning via module-owned responder + SNI-split relay.
//
// Diagnosis (login/registration was broken):
//   - plain DNS for vrchat.com / vrchat.cloud is poisoned on this network:
//     api.vrchat.cloud -> 8.47.69.0 sinkhole instead of 104.18.26.36 (DoH);
//   - old iptables rules matched ASCII "auth.vrchat.cloud", but a DNS wire
//     packet stores labels length-prefixed (\x07vrchat\x05cloud...) — the rule
//     could never match, so nothing was ever redirected;
//   - the core proxy has no pin for auth/api and would forward vrchat queries
//     into the poisoned upstream anyway;
//   - TLS to the real IPs works (SNI is not cut), so the module pins DNS and
//     additionally runs the shared SNI-split relay like google/xcom/discord.
//
// All pins below were verified against DoH (cloudflare-dns.com). Перепроверено
// 2026-09-26: у assets.vrchat.com адрес сменился, старый протух.

#define VRCHAT_DNS_PORT   15353   // module-owned DNS responder (not the core :53 proxy)
#define VRCHAT_RELAY_PORT 18444   // free: discord 18443, google 18445, xcom 18446, speedtest 18447
#define VRCHAT_SO_MARK    0x4d5b  // sni_relay default mark, reserved for vrchat

static vrchat_ctx_t ctx = {0};
static bool vrchat_initialized = false;

typedef struct {
    const char *domain;
    const char *ip;
} vrchat_pin_t;

// Exact matches first (checked before suffix pins).
static const vrchat_pin_t vrchat_pins[] = {
    {"api.vrchat.cloud",     "104.18.26.36"},   // Cloudflare
    {"pipeline.vrchat.cloud","104.18.26.36"},   // Cloudflare
    // Тот же Cloudflare-адрес, что у api: исходящий адрес зависит от адреса
    // назначения, и при двух разных фронт-эндах сессия VRChat рвётся мгновенно
    // (вход проходит, и сразу выкидывает — как с WARP).
    {"www.vrchat.com",       "104.18.26.36"},   // Cloudflare, единый фронт-энд
    {"vrchat.com",           "104.18.26.36"},   // Cloudflare, единый фронт-энд
    {"docs.vrchat.com",      "104.16.241.118"}, // ReadMe (CF)
      {"assets.vrchat.com",    "143.204.238.8"}, // CloudFront; старый 65.9.106.85 протух
    {"files.vrchat.cloud",   "108.157.229.62"}, // CloudFront d2jw20of4mijnb; старый 3.174.18.93 протух
      {"help.vrchat.com",      "216.198.53.6"},   // Zendesk
      // Без точных пинов суффиксное правило уводит эти имена на адрес
      // api, и Cloudflare отвечает 421 Misdirected Request.
      {"status.vrchat.com",     "108.157.229.63"}, // Statuspage; 421 без пина
      {"feedback.vrchat.com",   "100.56.186.228"}, // canny.io; 421 без пина
      {NULL, NULL}
  };

  // Разведка обновляет эти адреса сама. session_critical означает, что хост
  // держит логин VRChat: для таких держим РОВНО ОДИН адрес, общий на весь
  // набор. Причина не в прихоти: исходящий адрес зависит от адреса
  // назначения, и при двух разных фронт-эндах видимый адрес скачет, а
  // VRChat мгновенно рвёт сессию — выкидывает из аккаунта сразу после входа.
  static vrchat_discovery_host_t vrchat_disc_hosts[VRCHAT_DISC_MAX_HOSTS] = {
      { "api.vrchat.cloud",      true,  "104.18.26.36" },
      { "pipeline.vrchat.cloud", true,  "104.18.26.36" },
      { "vrchat.com",            true,  "104.18.26.36" },
      { "www.vrchat.com",        true,  "104.18.26.36" },
      { "files.vrchat.cloud",    false, "108.157.229.62" },
      { "assets.vrchat.com",     false, "143.204.238.8" },
      { "docs.vrchat.com",       false, "104.16.241.118" },
  };

  // Контент VRChat живёт на CloudFront, а тот отдаёт сразу несколько адресов и
  // меняет их по мере роста нагрузки. Проверено 2026-09-27 через DoH:
  //   assets.vrchat.com  (аватары) -> 143.204.238.8 .54 .91 .127
  //   files.vrchat.cloud (миры)     -> 108.157.229.62 .115 .98 .48
  // Модуль знал ровно по одному адресу на хост, поэтому три четверти запросов
  // аватаров и миров уходили мимо перехвата и не грузились. DNS мы задаём
  // сами, но адреса CloudFront всё равно забирать целиком: перехватываем
  // диапазон, а не отдельные адреса — иначе следующая ротация снова ломает
  // загрузку, как уже ломала раньше, со старыми адресами.
  static const char *const vrchat_content_ranges[] = {
      "143.204.238.0/24",   // CloudFront: аватары
      "108.157.229.0/24",   // CloudFront: миры и файлы
      NULL
  };

// Suffix fallbacks: every other *.vrchat.cloud / *.vrchat.com name
// (auth, worlds, avatars, groups, status, unknown future subdomains...).
static const vrchat_pin_t vrchat_suffix_pins[] = {
    {"vrchat.cloud", "104.18.26.36"},
    {"vrchat.com",   "104.18.26.36"},
    {NULL, NULL}
};

// iptables string-match zones: one wire-pattern rule per zone covers the zone
// and all of its subdomains (labels are length-prefixed, so "\x07vrchat\x03com"
// is a true label-anchored suffix match).
static const char *vrchat_zones[] = {
    "vrchat.com",
    "vrchat.cloud",
    NULL
};

// Known-good names, printed at inject to show what the responder will answer.
static const char *vrchat_notable[] = {
    "api.vrchat.cloud",
    "pipeline.vrchat.cloud",
    "www.vrchat.com",
    "vrchat.com",
    "docs.vrchat.com",
    "assets.vrchat.com",
    "files.vrchat.cloud",
    "help.vrchat.com",
    "status.vrchat.com",
    NULL
};

static pid_t responder_pid = -1;

// Настройки релея. Читаются из webui/vrchat.conf при каждом inject, поэтому
// перебор вариантов не требует пересборки. Файл опционален.
#define VRCHAT_CONF "webui/vrchat.conf"

// По умолчанию релей выключен: измерено 2026-09-25, что прямые соединения на
// пинованные адреса VRChat проходят целиком, а пропуск трафика через
// релей рвал поток примерно на 20 КБ. Обход на этом провайдере делает
// DNS-пиннинг (модуль отвечает сам, минуя подменённый провайдерский ответ).
// Релей включается только если без него не обойтись: use_relay=1.
static int opt_use_relay = 0;
static int opt_relay_chunk = 0;        // 0 = пересылать как есть
static int opt_relay_pause_ms = 0;     // 0 = без пауз
static int opt_relay_idle_sec = 0;     // 0 = не обрывать по простою

static int conf_int(const char *path, const char *key, int def) {
    FILE *f = fopen(path, "r");
    if (!f) return def;
    char line[256];
    int val = def;
    size_t klen = strlen(key);
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\0') continue;
        if (strncmp(p, key, klen) != 0 || p[klen] != '=') continue;
        val = atoi(p + klen + 1);
        break;
    }
    fclose(f);
    return val;
}

static void load_strategy(void) {
    opt_use_relay       = conf_int(VRCHAT_CONF, "use_relay", 0);
    opt_relay_chunk     = conf_int(VRCHAT_CONF, "relay_chunk", 0);
    opt_relay_pause_ms  = conf_int(VRCHAT_CONF, "relay_pause_ms", 0);
    opt_relay_idle_sec  = conf_int(VRCHAT_CONF, "relay_idle_sec", 0);
    if (conf_int(VRCHAT_CONF, "split_ch", 0) != 0)
        fprintf(stderr, "[VRCHAT] split_ch=1 в конфиге игнорируется: релей модуля "
                        "не изменяет ClientHello\n");
    if (opt_relay_chunk < 0) opt_relay_chunk = 0;
    if (opt_relay_pause_ms < 0) opt_relay_pause_ms = 0;
    if (opt_relay_idle_sec < 0) opt_relay_idle_sec = 0;
}

static int is_root(void) { return getuid() == 0; }

static void sh(const char *cmd) {
    int rc = system(cmd);
    (void)rc;
}

// ── DNS wire encoding for iptables -m string ─────────────────────────────
static void wire_pattern(const char *domain, char *out, size_t out_sz) {
    size_t o = 0;
    const char *s = domain;
    while (*s && o + 64 < out_sz) {
        const char *dot = strchr(s, '.');
        int ll = dot ? (int)(dot - s) : (int)strlen(s);
        if (ll <= 0 || ll > 63) break;
        out[o++] = (char)ll;
        memcpy(out + o, s, (size_t)ll); o += (size_t)ll;
        if (!dot) break;
        s = dot + 1;
    }
    out[o] = '\0';
}

// ── iptables ─────────────────────────────────────────────────────────────
static void iptables_base(void) {
    if (!is_root()) return;
    sh("iptables -t nat -N VRCHAT_BYPASS 2>/dev/null || true");
    // Не трогаем помеченные пакеты ЛЮБОГО модуля (0x4d5a discord, 0x4d5b vrchat,
    // 0x4d5c google, 0x4d5e speedtest -> маска 0xfff0 = 0x4d50/0xfff0).
    sh("iptables -t nat -C VRCHAT_BYPASS -m mark --mark 0x4d50/0xfff0 -j RETURN "
       "2>/dev/null || iptables -t nat -I VRCHAT_BYPASS 1 -m mark --mark 0x4d50/0xfff0 -j RETURN");
    sh("iptables -t nat -C VRCHAT_BYPASS -m mark --mark 0x4d5b -j RETURN "
       "2>/dev/null || iptables -t nat -I VRCHAT_BYPASS 2 -m mark --mark 0x4d5b -j RETURN");
    // Прыжок обязан быть ПЕРВЫМ в OUTPUT: у discord есть широкие CIDR
    // (104.16.0.0/12, 104.18.0.0/16 -> REDIRECT 18443), которые перехватывают
    // наши IP (104.18.26.36, 104.18.6.156, 104.16.241.118), если он стоит выше.
    // Поэтому пересоздаём прыжок на позиции 1 при каждом inject.
    sh("iptables -t nat -D OUTPUT -j VRCHAT_BYPASS 2>/dev/null");
    sh("iptables -t nat -I OUTPUT 1 -j VRCHAT_BYPASS");
}

static void iptables_add_dns_rule(const char *zone) {
    if (!is_root()) return;
    char wire[128], cmd[1024];
    wire_pattern(zone, wire, sizeof(wire));
    // -C перед -A: при повторном inject правило не задваивается
    snprintf(cmd, sizeof(cmd),
        "iptables -t nat -C VRCHAT_BYPASS -p udp --dport 53 "
        "-m string --algo bm --string \"%s\" "
        "-j DNAT --to-destination 127.0.0.1:%d 2>/dev/null || "
        "iptables -t nat -A VRCHAT_BYPASS -p udp --dport 53 "
        "-m string --algo bm --string \"%s\" "
        "-j DNAT --to-destination 127.0.0.1:%d",
        wire, VRCHAT_DNS_PORT, wire, VRCHAT_DNS_PORT);
    sh(cmd);
}

static void iptables_add_redirect(const char *ip) {
    if (!is_root()) return;
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "iptables -t nat -C VRCHAT_BYPASS -p tcp -d %.64s --dport 443 "
        "-j REDIRECT --to-ports %d 2>/dev/null || "
        "iptables -t nat -A VRCHAT_BYPASS -p tcp -d %.64s --dport 443 "
        "-j REDIRECT --to-ports %d",
        ip, VRCHAT_RELAY_PORT, ip, VRCHAT_RELAY_PORT);
    sh(cmd);
}

// ── DoH: клиент уходит в обход перехвата DNS ──────────────────────────────
// Наблюдение с живого клиента. VRChat под Proton/Wine резолвит имена через
// DNS-over-HTTPS на 1.1.1.1:443 и 8.8.8.8:443, а не через порт 53. Наш
// перехват DNS живёт на порте 53, поэтому он не видел ни одного запроса
// клиента: в трафике не было ни одного пакета на udp/53, зато были
// 517-байтные запросы на 1.1.1.1:443.
//
// Чем это вредно. Клиент получал настоящие адреса Cloudflare мимо наших
// пинов: 104.18.125.108, 104.17.208.5, 104.18.52.172, 104.18.48.115, тогда
// как наш пин один — 104.18.26.36. Выход в интернет зависит от адреса
// назначения, поэтому один и тот же клиент посылал запросы с разных
// адресов. Для VRChat это ломает сессию, а для аватаров даёт «Error».
//
// Почему REJECT, а не тишина. REJECT с icmp-port-unreachable отбивает
// соединение мгновенно, и клиент сразу откатывается на обычный порт 53,
// где сработает наш перехват. Молчаливый DROP заставил бы ждать таймаут.
//
// Почему отдельная цепочка в filter. REJECT — цель для таблицы filter, в
// nat её отвергает ядро («Invalid argument»). Поэтому своя цепочка RMF_DOH
// в filter, чтобы её можно было снять целиком при остановке модуля.
static const char *doh_resolvers[] = {
    "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2",          // Cloudflare
    "8.8.8.8", "8.8.4.4",                                  // Google
    "9.9.9.9", "9.9.9.10",                                 // Quad9
    "149.112.112.112", "149.112.113.112",                  // Quad9
    "208.67.222.222", "208.67.220.220",                    // OpenDNS
    "94.140.14.14", "94.140.15.15",                        // AdGuard
    "185.228.168.9", "185.228.169.9",                      // CleanBrowsing
    NULL
};

static void iptables_block_doh(void) {
    if (!is_root()) return;
    sh("iptables -N RMF_DOH 2>/dev/null || true");
    sh("iptables -C OUTPUT -j RMF_DOH 2>/dev/null || iptables -I OUTPUT 1 -j RMF_DOH");
    // Собственные резолверы модулей — под root, их блокировать нельзя.
    //
    // Модули резолвят имена через DoH и идут ровно на заблокированные адреса:
    //   doh_resolve.c: https://cloudflare-dns.com/dns-query  через 1.1.1.1:443
    //                   https://dns.google/dns-query        через 8.8.8.8:443
    // Когда запрет применялся ко всем, он глушил и их. Тогда домен без
    // готового закрепления уезжал на обычный DNS, а тот для github.com
    // отдаёт 140.82.121.3, который у провайдера режется. Сайт висел на
    // таймауте, хотя рабочий адрес 4.225.11.194 был рядом и отвечал.
    //
    // Клиент, ради которого запрет и нужен, работает от обычного пользователя,
    // поэтому exempt для root точно оставляет нужное поведение: модули
    // резолвят как хотят, клиент через DoH уйти не может.
    sh("iptables -C RMF_DOH -m owner --uid-owner 0 -j RETURN 2>/dev/null || "
       "iptables -I RMF_DOH 1 -m owner --uid-owner 0 -j RETURN");
    for (int i = 0; doh_resolvers[i]; i++) {
        char cmd[512];
        snprintf(cmd, sizeof(cmd),
            "iptables -C RMF_DOH -p tcp -d %.32s --dport 443 -j REJECT "
            "--reject-with icmp-port-unreachable 2>/dev/null || "
            "iptables -A RMF_DOH -p tcp -d %.32s --dport 443 -j REJECT "
            "--reject-with icmp-port-unreachable",
            doh_resolvers[i], doh_resolvers[i]);
        sh(cmd);
        snprintf(cmd, sizeof(cmd),
            "iptables -C RMF_DOH -p udp -d %.32s --dport 853 -j REJECT "
            "--reject-with icmp-port-unreachable 2>/dev/null || "
            "iptables -A RMF_DOH -p udp -d %.32s --dport 853 -j REJECT "
            "--reject-with icmp-port-unreachable",
            doh_resolvers[i], doh_resolvers[i]);
        sh(cmd);
    }
}

static void iptables_unblock_doh(void) {
    if (!is_root()) return;
    sh("iptables -D OUTPUT -j RMF_DOH 2>/dev/null");
    sh("iptables -F RMF_DOH 2>/dev/null");
    sh("iptables -X RMF_DOH 2>/dev/null");
}

static void iptables_del_rules(void) {
    if (!is_root()) return;
    iptables_unblock_doh();
    sh("iptables -t nat -D OUTPUT -j VRCHAT_BYPASS 2>/dev/null");
    sh("iptables -t nat -D OUTPUT -p udp --dport 53 -j VRCHAT_BYPASS 2>/dev/null");
    sh("iptables -t nat -F VRCHAT_BYPASS 2>/dev/null");
    sh("iptables -t nat -X VRCHAT_BYPASS 2>/dev/null");
}

// ── pin lookup (exact, then zone suffix) ─────────────────────────────────
// Форвард: кеш пинов описан ниже, а проверка уже им пользуется.
#define VC_CACHE_MAX 128
static char vc_dom[VC_CACHE_MAX][256];
static char vc_ip[VC_CACHE_MAX][64];
static int  vc_cache_n;
static void vc_cache_put(const char *domain, const char *ip);
static void vc_cache_del(const char *domain);
static void vc_cache_path(char *out, size_t cap);
static void vc_cache_load(void);
static void vc_cache_prune_dead(void);
static const char *vc_cache_get(const char *domain);
static int is_session_host(const char *domain);

// ── самовосстановление пинов ───────────────────────────────────────────────
//
// Зашитый адрес протухает, когда CDN проворачивает сеть. Раньше это означало
// молчаливую поломку: модуль отдавал прежний адрес, страница или миры не
// грузились, и понять, где дело, можно было только вручную.
//
// Здесь адрес сверяется с DoH, и меняется он только когда старого в ответе
// действительно нет. Пока адрес в списке — не трогаем ничего, поэтому набор
// серверов у VRChat не меняется без причины. Никаких перезапусков: ответчик
// читает /run/rmf/pins/VRCHAT.pin, и новое значение подхватывается само.
static int probe_why(const char *ip, char *why, size_t cap) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { snprintf(why, cap, "socket(): %s", strerror(errno)); return 0; }
    // Метка обязательна, иначе проба измеряет собственный рель модуля.
    //
    // Без метки соединение попадает в REDIRECT правила модуля и уходит на
    // локальный рель. Проверка кэша идёт до старта реля, так что там никто не
    // слушает, и проба получала отказ на живых адресах: в журнале это выглядело
    // как «104.18.26.36 больше не отвечает (Connection refused)», хотя адрес
    // отвечает. Все закрепления объявлялись мёртвыми и выбрасывались.
    //
    // Раньше это не всплывало только потому, что файл закреплений и так
    // удалялся при каждом запуске.
    if (VRCHAT_SO_MARK) {
        unsigned int mark = VRCHAT_SO_MARK;
        setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
    }
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET; a.sin_port = htons(443);
    if (inet_pton(AF_INET, ip, &a.sin_addr) != 1) {
        snprintf(why, cap, "inet_pton"); close(fd); return 0;
    }
    int rc = connect(fd, (struct sockaddr *)&a, sizeof(a));
    if (rc != 0 && errno != EINPROGRESS) {
        snprintf(why, cap, "connect(): %s", strerror(errno)); close(fd); return 0;
    }
    if (rc != 0) {
        struct pollfd p = { .fd = fd, .events = POLLOUT };
        int pr = poll(&p, 1, 2000);
        if (pr == 0) { snprintf(why, cap, "таймаут 2 с"); close(fd); return 0; }
        if (pr < 0) { snprintf(why, cap, "poll(): %s", strerror(errno)); close(fd); return 0; }
        int err = 0; socklen_t el = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) < 0 || err) {
            snprintf(why, cap, "SO_ERROR: %s", strerror(err ? err : errno)); close(fd); return 0;
        }
    }
    snprintf(why, cap, "соединено");
    close(fd);
    return 1;
}

static void pins_verify_self(void) {
    // Контрольная проба. Проверка идёт непомеченным сокетом, а активные
    // модули перехватывают широкие диапазоны: если проба сама идёт в чужой
    // рель, она вернёт «не отвечает» про всё сразу. Тогда верить нельзя
    // ничему, и безопаснее не менять ни одного адреса.
    if (site_probe_tcp("1.1.1.1", 443, 3000) != 1) {
        printf("[VRCHAT]   проверка пинов отключена: контрольная проба не прошла\n");
        return;
    }

    for (int i = 0; vrchat_pins[i].domain; i++) {
        const char *domain = vrchat_pins[i].domain;
        const char *pinned = vrchat_pins[i].ip;

        // Сессионные хосты обслуживает разведка (vrchat_discovery), и только
        // она одна. Если разрешить этой проверке менять им адреса, получатся
        // две механики управления одними и теми же записями: разведка
        // назначает всем хостам ОДИН общий адрес, а эта — свой каждому.
        // Спор выигрывал кэш, и pipeline уезжал на 104.18.27.36 при общих
        // 104.18.26.36 у остальных. Видимый адрес скакал между фронт-эндами,
        // и VRChat мгновенно рвал сессию — выкидывало из аккаунта на входе.
        if (is_session_host(domain)) continue;

        // Главное правило: пока пин отвечает, его не трогаем. Сравнивать пин
        // со списком из DoH нельзя — там отдаётся одна из краевых точек сети,
        // и она меняется от запроса к запросу, так что «пина нет в ответе»
        // получается почти всегда. Меряем сам адрес.
        char why[128] = {0};
        if (probe_why(pinned, why, sizeof(why)) == 1) continue;
        printf("[VRCHAT]   проба %s (%s): %s\n", domain, pinned, why);

        // Адрес не отвечает. Ищем замену и тоже проверяем её, прежде чем
        // принять: в наборе DoH попадаются узлы, которые не обслуживают
        // запросы, и такой адрес в пине просто ломает сайт.
        char addrs[6][64];
        int n = 0;
        if (doh_resolve_a_multi(domain, addrs, 6, &n) != 0 || n <= 0) {
            printf("[VRCHAT]   %s: пин %s не отвечает, DoH не дал замены\n",
                   domain, pinned);
            continue;
        }
        const char *chosen = NULL;
        for (int k = 0; k < n; k++) {
            if (strcmp(addrs[k], pinned) == 0) continue;
            if (site_probe_tcp(addrs[k], 443, 2000) == 1) { chosen = addrs[k]; break; }
        }
        if (!chosen) {
            printf("[VRCHAT]   %s: пин %s не отвечает, замены среди %d адр. нет\n",
                   domain, pinned, n);
            continue;
        }
        vc_cache_put(domain, chosen);
        printf("[VRCHAT]   пин обновлён: %s %s -> %s (старый не отвечал)\n",
               domain, pinned, chosen);
    }

    // Кеш живёт в процессе ответчика, а проверка идёт в отдельном, поэтому
    // файл читается здесь явно: иначе цикл ниже не увидит ни одной записи.
    // Мёртвые адреса уходят из кэша сразу, а не после перезапуска модуля.
    vc_cache_prune_dead();
    vc_cache_load();

    // Записи в /run/rmf/pins тоже проверяются. Кеш перекрывает зашитую
    // таблицу, поэтому оставленная в нём мёртвая запись ломает сайт так же,
    // как протухший пин. Не проверенные записи не хранятся.
    for (int i = 0; i < vc_cache_n; i++) {
        char dom[256];
        snprintf(dom, sizeof(dom), "%s", vc_dom[i]);
          // Сессионные хосты — исключение, и здесь оно обязательно.
          //
          // Выше по этой же функции стоит прямой запрет трогать их: ими
          // управляет только разведка, иначе адреса разъезжаются и VRChat
          // рвёт сессию. Чистка кэша этот запрет не повторяла и удаляла их
          // записи. Проверено: блокировка одного адреса выбивала из кеша сразу
          // четыре записи — api, pipeline, vrchat.com и www.vrchat.com, — и до
          // следующего прохода разведки (900 с) они остались без закрепления.
          if (is_session_host(dom)) continue;
        if (site_probe_tcp(vc_ip[i], 443, 2000) == 1) continue;
        printf("[VRCHAT]   запись кеша не отвечает, удаляю: %s %s\n", dom, vc_ip[i]);
        vc_cache_del(dom);
        i--;
    }
}

// Проверка идёт в отдельном процессе и не тормозит запуск модуля: DoH-запрос
// на каждый пин — это fork и curl, и на старте это заметная пауза.

// Периодическая сверка закреплений.
//
// Сама сверка (pins_verify_self) умеет всё нужное: помеченной пробой отсеивает
// мёртвые адреса, находит замену через DoH и пишет её в файл, а ответчик
// подхватывает файл по mtime. Проблема была не в логике, а в том, что её
// звали один раз при старте — после смены сети модуль держал протухший адрес
// до перезапуска.
//
// Нить ничего не считает сама: она только будит сверку, а сверка работает в
// форкнутом процессе. Так сохраняется исходная идея — не делить кэш с
// процессом ответчика.
#define PINS_RECHECK_SEC 300

// Опережающее объявление: сверка описана ниже, а нить будит её раньше.
static void pins_verify_async(void);

static volatile int g_recheck_stop;
static volatile int g_recheck_running;
static pthread_t g_recheck_th;

static void *pins_recheck_thread(void *arg) {
    (void)arg;
    for (int t = 0; t < PINS_RECHECK_SEC && !g_recheck_stop; t++) sleep(1);
    while (!g_recheck_stop) {
        pins_verify_async();
        for (int t = 0; t < PINS_RECHECK_SEC && !g_recheck_stop; t++) sleep(1);
    }
    return NULL;
}

static void pins_recheck_start(void) {
    if (g_recheck_running) return;
    g_recheck_stop = 0;
    if (pthread_create(&g_recheck_th, NULL, pins_recheck_thread, NULL) == 0)
        g_recheck_running = 1;
}

static void pins_recheck_stop(void) {
    if (!g_recheck_running) return;
    g_recheck_stop = 1;
    // join обязателен: поток исполняет код этой библиотеки, и после dlclose
    // любое его пробуждение — падение.
    pthread_join(g_recheck_th, NULL);
    g_recheck_running = 0;
}

static void pins_verify_async(void) {
    pid_t p = fork();
    if (p != 0) { if (p < 0) fprintf(stderr, "[VRCHAT] fork для проверки пинов не удался\n"); return; }
    pins_verify_self();
    _exit(0);
}

// Адрес для сессионного хоста: сначала то, что нашла разведка, и только
// потом зашитое значение. Разведка обновляет отчёт целиком, поэтому здесь
// всегда согласованный снимок.
// Сессионный ли это хост. Таких адресами управляет только разведка, и
// вторая механика для них запрещена: иначе она перебивает общий адрес
// своими пообъектными, видимый адрес скачет между фронт-эндами, и VRChat
// мгновенно рвёт сессию — выкидывает из аккаунта сразу после входа.
// Отдельный буфер: результат живёт до следующего вызова, как и прежний.
static char g_content_ip[64] = {0};

static int is_session_host(const char *domain) {
    if (!domain) return 0;
    for (int k = 0; k < VRCHAT_DISC_MAX_HOSTS; k++)
        if (vrchat_disc_hosts[k].host && vrchat_disc_hosts[k].session_critical &&
            strcasecmp(vrchat_disc_hosts[k].host, domain) == 0)
            return 1;
    return 0;
}

static const char *discovery_pinned(const char *domain) {
    static char out[64];
    vrchat_discovery_report_t rep;
    if (vrchat_discovery_copy_report(&rep) != 0) return NULL;
    for (int i = 0; i < VRCHAT_DISC_MAX_HOSTS; i++) {
        if (rep.hosts[i].host[0] && strcasecmp(rep.hosts[i].host, domain) == 0) {
            if (rep.hosts[i].pinned[0]) {
                snprintf(out, sizeof(out), "%s", rep.hosts[i].pinned);
                return out;
            }
        }
    }
    return NULL;
}

static const char *lookup_ip(const char *domain) {
    const char *from_disc = discovery_pinned(domain);
    if (from_disc && *from_disc) return from_disc;
    // Контентные хосты. Разведка находит для них ВСЕ живые адреса, но
    // pinned у них пуст — там сессии нет, и держать один адрес незачем.
    // Раньше эти адреса вычислялись и молча выбрасывались, а клиенту
    // доставался единственный зашитый. Теперь берём первый живой.
    if (domain && !is_session_host(domain)) {
        vrchat_discovery_report_t rep;
        if (vrchat_discovery_copy_report(&rep) == 0) {
            for (int i = 0; i < VRCHAT_DISC_MAX_HOSTS; i++) {
                if (!rep.hosts[i].host[0] ||
                    strcasecmp(rep.hosts[i].host, domain) != 0) continue;
                if (rep.hosts[i].count > 0 && rep.hosts[i].addrs[0][0]) {
                    snprintf(g_content_ip, sizeof(g_content_ip), "%.63s",
                             rep.hosts[i].addrs[0]);
                    return g_content_ip;
                }
            }
        }
    }
    if (!domain || !*domain) return NULL;
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s", domain);
    size_t l = strlen(tmp);
    while (l > 0 && tmp[l - 1] == '.') tmp[--l] = '\0';

      // Кеш важнее таблицы: туда попадают адреса, проверенные пробой, в том
      // числе обновлённые после смены сети. Таблица — запасной вариант.
      const char *cached = vc_cache_get(tmp);
      if (cached) return cached;

      for (int i = 0; vrchat_pins[i].domain; i++) {
          if (strcasecmp(tmp, vrchat_pins[i].domain) == 0)
              return vrchat_pins[i].ip;
      }
    for (int i = 0; vrchat_suffix_pins[i].domain; i++) {
        const char *base = vrchat_suffix_pins[i].domain;
        size_t bl = strlen(base), tl = strlen(tmp);
        if (tl == bl && strcasecmp(tmp, base) == 0)
            return vrchat_suffix_pins[i].ip;
        if (tl > bl && tmp[tl - bl - 1] == '.' &&
            strcasecmp(tmp + tl - bl, base) == 0)
            return vrchat_suffix_pins[i].ip;
    }
    return NULL;
}

// ── кеш адресов для доменов vrchat, которых нет в статической таблице ──
//
// Раньше такие домены уходили в апстрим, где им отдавали новый адрес на каждый
// запрос. Клиент VRChat видел постоянно меняющийся набор серверов и считал это
// подменой трафика. Поэтому адрес запоминается и переиспользуется, пока
// отвечает; переспрашивается только когда прежний не отвечает.
static char vc_dom[VC_CACHE_MAX][256];
static char vc_ip[VC_CACHE_MAX][64];
static int vc_cache_n;
static int vc_cache_loaded;

static void vc_cache_path(char *out, size_t cap) {
    snprintf(out, cap, "/run/rmf/pins/VRCHAT.pin");
}

static time_t vc_cache_mtime = 0;

// Выбросить из кэша адреса, которые не отвечают. Проба помечена, поэтому
// идёт мимо собственного реля и меряет настоящий путь до адреса.
//
// Зачем: кэш жил в двух местах — на диске и в памяти. Удаление файла не
// помогало, потому что карта в памяти оставалась прежней, и модуль продолжал
// отдавать заблокованный адрес, пока его не перезапустили. Именно так аватары
// VRChat показывали Error: в кэше лежал 143.204.238.54, который провайдер режет.
static void vc_cache_prune_dead(void) {
    int n = vc_cache_n;
    for (int i = 0; i < n; i++) {
        char dom_copy[64], ip_copy[64];
        snprintf(dom_copy, sizeof(dom_copy), "%.63s", vc_dom[i]);
        snprintf(ip_copy, sizeof(ip_copy), "%.63s", vc_ip[i]);
        char why[128] = {0};
        if (probe_why(ip_copy, why, sizeof(why)) == 1) continue;
        printf("[VRCHAT] кэш: %s %s больше не отвечает (%s) — убираю\n",
               dom_copy, ip_copy, why);
        vc_cache_del(dom_copy);
    }
    vc_cache_mtime = 0;
    vc_cache_loaded = 0;
    vc_cache_load();
}

static void vc_cache_load(void) {
    vc_cache_n = 0;
    vc_cache_loaded = 1;
    char path[512];
    struct stat st;
    vc_cache_path(path, sizeof(path));
    if (stat(path, &st) == 0) vc_cache_mtime = st.st_mtime;
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[400];
    while (vc_cache_n < VC_CACHE_MAX && fgets(line, sizeof(line), f)) {
        char d[256], ip[64];
        if (sscanf(line, "%255s %63s", d, ip) != 2) continue;
        snprintf(vc_dom[vc_cache_n], sizeof(vc_dom[0]), "%s", d);
        snprintf(vc_ip[vc_cache_n], sizeof(vc_ip[0]), "%s", ip);
        vc_cache_n++;
    }
    fclose(f);
}

// Файл пинов могут править два процесса: сам модуль (vc_cache_put) и
// проверка самовосстановления, которая переписывает протухшие адреса. Поэтому
// кеш перечитывается, когда файл изменился, а не только один раз при старте.
static void vc_cache_maybe_reload(void) {
    char path[512];
    struct stat st;
    vc_cache_path(path, sizeof(path));
    if (stat(path, &st) != 0) { if (vc_cache_n) { vc_cache_n = 0; vc_cache_loaded = 1; } return; }
    if (!vc_cache_loaded || st.st_mtime != vc_cache_mtime) {
        vc_cache_mtime = st.st_mtime;
        vc_cache_n = 0;
        vc_cache_loaded = 1;
        vc_cache_load();
    }
}

static const char *vc_cache_get(const char *domain) {
    if (!vc_cache_loaded) vc_cache_load();
    else vc_cache_maybe_reload();
    for (int i = 0; i < vc_cache_n; i++)
        if (strcasecmp(vc_dom[i], domain) == 0) return vc_ip[i];
    return NULL;
}

// Удаление записи из кеша. Нужна, чтобы кеш сам очищался: адрес, который
// перестал отвечать, не должен навсегда перекрывать зашитый.
static void vc_cache_del(const char *domain) {
    if (!vc_cache_loaded) vc_cache_load();
    for (int i = 0; i < vc_cache_n; i++) {
        if (strcasecmp(vc_dom[i], domain) != 0) continue;
        for (int j = i; j < vc_cache_n - 1; j++) {
            memcpy(vc_dom[j], vc_dom[j + 1], sizeof(vc_dom[0]));
            memcpy(vc_ip[j], vc_ip[j + 1], sizeof(vc_ip[0]));
        }
        vc_cache_n--;
        char path[512], tmp[560];
        mkdir("/run/rmf", 0755);
        mkdir("/run/rmf/pins", 0755);
        vc_cache_path(path, sizeof(path));
        snprintf(tmp, sizeof(tmp), "%s.tmp", path);
        FILE *f = fopen(tmp, "w");
        if (f) {
            for (int k = 0; k < vc_cache_n; k++)
                fprintf(f, "%s %s\n", vc_dom[k], vc_ip[k]);
            fclose(f);
            rename(tmp, path);
        }
        return;
    }
}

static void vc_cache_put(const char *domain, const char *ip) {
    if (!vc_cache_loaded) vc_cache_load();
    for (int i = 0; i < vc_cache_n; i++) {
        if (strcasecmp(vc_dom[i], domain) != 0) continue;
        if (strcmp(vc_ip[i], ip) == 0) return;
        snprintf(vc_ip[i], sizeof(vc_ip[0]), "%s", ip);   // адрес сменился
        goto save;
    }
    if (vc_cache_n >= VC_CACHE_MAX) return;
    snprintf(vc_dom[vc_cache_n], sizeof(vc_dom[0]), "%s", domain);
    snprintf(vc_ip[vc_cache_n], sizeof(vc_ip[0]), "%s", ip);
    vc_cache_n++;
save:
    mkdir("/run/rmf", 0755);
    mkdir("/run/rmf/pins", 0755);
    char path[512], tmp[560];
    vc_cache_path(path, sizeof(path));
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f) return;
    for (int i = 0; i < vc_cache_n; i++)
        fprintf(f, "%s %s\n", vc_dom[i], vc_ip[i]);
    fclose(f);
    rename(tmp, path);
}

// Домен в зоне vrchat? Только такие имеет смысл закреплять.
static int in_vrchat_zone(const char *domain) {
    static const char *zones[] = { "vrchat.com", "vrchat.cloud", NULL };
    size_t dl = strlen(domain);
    for (int i = 0; zones[i]; i++) {
        size_t zl = strlen(zones[i]);
        if (dl == zl && strcasecmp(domain, zones[i]) == 0) return 1;
        if (dl > zl && domain[dl - zl - 1] == '.' &&
            strcasecmp(domain + dl - zl, zones[i]) == 0) return 1;
    }
    return 0;
}

// Адрес для домена: статическая таблица, затем кеш, затем разовое разрешение.
static const char *resolve_vrchat(const char *domain, char *out, size_t out_len) {
    const char *ip = lookup_ip(domain);
    if (ip) return ip;
    ip = vc_cache_get(domain);
    if (ip) return ip;
    out[0] = '\0';
    if (!in_vrchat_zone(domain)) return NULL;
    if (doh_resolve_a(domain, out, (int)out_len) != 0) { out[0] = '\0'; return NULL; }
    if (out[0]) vc_cache_put(domain, out);
    return out;
}

// ── minimal DNS message helpers (same shape as core proxy) ───────────────
static void get_qname(const unsigned char *pkt, int len, char *out, int outlen) {
    int pos = 12, o = 0;
    while (pos < len && pkt[pos] != 0 && o < outlen - 1) {
        int ll = pkt[pos++];
        if ((ll & 0xC0) == 0xC0) break;
        if (o > 0) out[o++] = '.';
        for (int i = 0; i < ll && pos < len && o < outlen - 1; i++)
            out[o++] = (char)pkt[pos++];
    }
    out[o] = 0;
}

static int skip_qname(const unsigned char *pkt, int len) {
    int pos = 12;
    while (pos < len && pkt[pos] != 0) {
        int ll = pkt[pos++];
        if ((ll & 0xC0) == 0xC0) { pos += 1; break; }
        pos += ll;
    }
    if (pos < len) pos++;
    return pos;
}

static int build_a_resp(const unsigned char *q, int ql, unsigned char *buf,
                        int buflen, const char *ip) {
    int qpos = skip_qname(q, ql);
    int qsection_len = qpos + 4;
    if (qsection_len > ql || buflen < qsection_len + 24) return -1;
    memset(buf, 0, buflen);
    memcpy(buf, q, qsection_len);
    unsigned char *r = buf;
    r[2] = 0x81; r[3] = 0x80;
    r[4] = 0; r[5] = 1;   // QDCOUNT
    r[6] = 0; r[7] = 1;   // ANCOUNT
    r[8] = 0; r[9] = 0;   // NSCOUNT
    int o = qsection_len;
    r[o++] = 0xC0; r[o++] = 0x0C;
    r[o++] = 0x00; r[o++] = 0x01;   // A
    r[o++] = 0x00; r[o++] = 0x01;   // IN
    r[o++] = 0x00; r[o++] = 0x00; r[o++] = 0x00; r[o++] = 0x78;
    r[o++] = 0x00; r[o++] = 0x04;
    struct in_addr a;
    if (inet_pton(AF_INET, ip, &a) != 1) return -1;
    memcpy(r + o, &a, 4);
    o += 4;
    r[10] = 0; r[11] = 0;
    return o;
}

// NOERROR with empty answer (AAAA/SVCB/TXT on a pinned name: "no such record").
static int build_empty_resp(const unsigned char *q, int ql,
                            unsigned char *buf, int buflen) {
    int qpos = skip_qname(q, ql);
    int qsection_len = qpos + 4;
    if (qsection_len > ql || buflen < qsection_len) return -1;
    memset(buf, 0, buflen);
    memcpy(buf, q, qsection_len);
    unsigned char *r = buf;
    r[2] = 0x81; r[3] = 0x80;
    r[4] = 0; r[5] = 1;   // QDCOUNT
    r[6] = 0; r[7] = 0;   // ANCOUNT (empty)
    r[8] = 0; r[9] = 0;   // NSCOUNT
    r[10] = 0; r[11] = 0; // ARCOUNT
    return qsection_len;
}

// Forward a non-vrchat query upstream (marked so our own DNAT rules skip it).
static int forward_query(const unsigned char *q, int ql,
                         unsigned char *ans, int anslen) {
    const char *servers[3];
    int ns = 0;
    if (ctx.primary[0]) servers[ns++] = ctx.primary;
    if (ctx.fallback[0]) servers[ns++] = ctx.fallback;
    servers[ns++] = NULL;

    for (int i = 0; servers[i]; i++) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) return -1;
        unsigned int mark = VRCHAT_SO_MARK;
        setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)); // ok if it fails (no root)
        struct timeval tv = {2, 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        struct sockaddr_in dst = {0};
        dst.sin_family = AF_INET;
        dst.sin_port = htons(53);
        if (inet_pton(AF_INET, servers[i], &dst.sin_addr) != 1) { close(fd); continue; }
        ssize_t sent = sendto(fd, q, (size_t)ql, 0,
                              (struct sockaddr *)&dst, sizeof(dst));
        if (sent == ql) {
            ssize_t n = recvfrom(fd, ans, (size_t)anslen, 0, NULL, NULL);
            close(fd);
            if (n >= 12 && ans[0] == q[0] && ans[1] == q[1]) return (int)n;
        } else {
            close(fd);
        }
    }
    return -1;
}

// ── DNS responder (forked child, answers from the pin table) ─────────────
static void responder_loop(int ready_fd) {
    prctl(PR_SET_PDEATHSIG, SIGTERM);
    if (getppid() == 1) _exit(0);   // parent died before prctl
    setsid();
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGTERM, SIG_DFL);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) _exit(1);
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons(VRCHAT_DNS_PORT);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0) _exit(2);

    if (ready_fd >= 0) {
        char ok = 1;
        if (write(ready_fd, &ok, 1) != 1) _exit(5);
        close(ready_fd);
    }

    unsigned char q[4096], r[4096];
    for (;;) {
        struct sockaddr_in cli;
        socklen_t cl = sizeof(cli);
        ssize_t n = recvfrom(fd, q, sizeof(q), 0, (struct sockaddr *)&cli, &cl);
        if (n < 12) continue;

        char dom[256];
        get_qname(q, (int)n, dom, sizeof(dom));
        int qpos = skip_qname(q, (int)n);
        int qtype = (qpos + 1 < n) ? (q[qpos] << 8) | q[qpos + 1] : 0;

        char fresh[64] = {0};
        const char *ip = resolve_vrchat(dom, fresh, sizeof(fresh));
        int rl;
        if (ip) {
            rl = (qtype == 1) ? build_a_resp(q, (int)n, r, sizeof(r), ip)
                              : build_empty_resp(q, (int)n, r, sizeof(r));
        } else {
            rl = forward_query(q, (int)n, r, sizeof(r));
        }
        if (rl > 0)
            sendto(fd, r, (size_t)rl, 0, (struct sockaddr *)&cli, cl);
    }
}

static void responder_stop(void) {
    if (responder_pid <= 0) return;
    kill(responder_pid, SIGTERM);
    for (int i = 0; i < 20; i++) {
        if (waitpid(responder_pid, NULL, WNOHANG) == responder_pid) {
            responder_pid = -1;
            return;
        }
        usleep(50000);
    }
    kill(responder_pid, SIGKILL);
    waitpid(responder_pid, NULL, 0);
    responder_pid = -1;
}

static int responder_start(void) {
    if (responder_pid > 0 && kill(responder_pid, 0) == 0) return 0;

    int pfd[2];
    if (pipe(pfd) != 0) return -1;
    pid_t p = fork();
    if (p < 0) { close(pfd[0]); close(pfd[1]); return -1; }
    if (p == 0) {
        close(pfd[0]);
        responder_loop(pfd[1]);
        _exit(0);
    }
    close(pfd[1]);
    responder_pid = p;

    char ok = 0;
    struct pollfd pfd_ev = { .fd = pfd[0], .events = POLLIN };
    int pr = poll(&pfd_ev, 1, 2000);
    int got = (pr > 0) ? (int)read(pfd[0], &ok, 1) : 0;
    close(pfd[0]);
    if (got != 1 || !ok) { responder_stop(); return -1; }
    return 0;
}

// ── lifecycle ────────────────────────────────────────────────────────────
void vrchat_module_init(vrchat_config_t *config) {
    if (vrchat_initialized) return;

    strncpy(ctx.primary, "1.1.1.1", 31);
    strncpy(ctx.fallback, "8.8.8.8", 31);
    if (config && config->primary_dns) strncpy(ctx.primary, config->primary_dns, 31);
    if (config && config->fallback_dns) strncpy(ctx.fallback, config->fallback_dns, 31);
    ctx.primary[31] = '\0';
    ctx.fallback[31] = '\0';
    char *c;
    if ((c = strchr(ctx.primary, ':'))) *c = '\0';
    if ((c = strchr(ctx.fallback, ':'))) *c = '\0';

    ctx.socket_fd = -1;
    ctx.socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctx.socket_fd < 0) {
        fprintf(stderr, "[VRCHAT] socket: %s\n", strerror(errno));
        return;
    }

    vrchat_initialized = true;
    printf("[VRCHAT] init: DNS %s / %s, responder:%d relay:%d\n",
           ctx.primary, ctx.fallback, VRCHAT_DNS_PORT, VRCHAT_RELAY_PORT);
}

void vrchat_module_cleanup(void) {
    if (!vrchat_initialized) return;
    vrchat_module_remove();
    if (ctx.socket_fd >= 0) {
        close(ctx.socket_fd);
        ctx.socket_fd = -1;
    }
    vrchat_initialized = false;
    printf("[VRCHAT] cleanup done\n");
}

void vrchat_module_inject(int fd) {
    (void)fd;
    if (!vrchat_initialized) {
        fprintf(stderr, "[VRCHAT] not initialized\n");
        return;
    }

    if (responder_start() != 0) {
        fprintf(stderr, "[VRCHAT] responder start failed: %s\n", strerror(errno));
        ctx.mode = 0;
        return;
    }

    // Пробы обязаны быть помечены, иначе их перехватит собственный
    // рель модуля и заблокированный адрес покажется живым.
    //
    // Стоит сделать это ДО чтения пинов, иначе сверка пойдёт немеченной пробой
    // и решит, что адрес живой, хотя на самом деле его режет провайдер.
    site_probe_set_mark(VRCHAT_SO_MARK);

    // Закрепления с диска НЕ удаляются.
    //
    // Раньше здесь стояло remove(pin_path), и это было правильно: пробы шли
    // без метки, мерили собственный рель вместо провайдера и записывали в файл
    // адрес, который на самом деле зарезан. Раз запуск сносил файл целиком,
    // мусор не накапливался.
    //
    // Теперь пробы помечены, и сносить файл незачем: удачные адреса, найденные
    // в прошлый запуск, должны пережить перезапуск. Без этого модуль на каждом
    // старте заново рисует картину с нуля, а это и есть лишняя работа и
    // лишняя смена адреса на живых сессиях.
    //
    // Что попало в файл раньше и не проверено, тем и плохо: поэтому файл
    // читается и сверяется помеченной пробой, а не берётся на веру. Не
    // ответил — выбрасывается, ответил — остаётся и им же будет записан
    // проверенный.
    {
        char pin_path[512];
        vc_cache_path(pin_path, sizeof(pin_path));
        if (access(pin_path, F_OK) == 0) {
            vc_cache_mtime = 0;
            vc_cache_loaded = 0;
            vc_cache_load();
            printf("[VRCHAT] закреплений с диска: %d, сверяю помеченной пробой\n",
                   vc_cache_n);
            fflush(stdout);
        }
    }

    // Сверка пинов асинхронная: модуль поднимается сразу, протухшие адреса
    // выбрасываются в фоне помеченной пробой.
    pins_verify_async();
    pins_recheck_start();

    // Фоновая разведка: сама подтягивает свежие адреса, проверяет их
    // соединением и раскладывает по правилам. Старую проверку пин��в
    // оставляем как страховку на случай, если разведка не справилась.
    {
        vrchat_discovery_cfg_t dc = {
            .interval_sec = 900,
            .hosts = vrchat_disc_hosts,
        };
        if (vrchat_discovery_start(&dc) == 0)
            printf("[VRCHAT] разведка адресов запущена, интервал %d с\n", dc.interval_sec);
        else
            printf("[VRCHAT] разведка не запустилась, работаем на зашитых адресах\n");
    }

    load_strategy();
    iptables_base();
    iptables_block_doh();
    for (int i = 0; vrchat_zones[i]; i++)
        iptables_add_dns_rule(vrchat_zones[i]);

    printf("[VRCHAT] inject: зоны vrchat.com/vrchat.cloud -> 127.0.0.1:%d\n",
           VRCHAT_DNS_PORT);
    printf("[VRCHAT]   DoH 1.1.1.1/8.8.8.8:443 заблокирован — клиент пойдёт через порт 53\n");
    printf("[VRCHAT]   relay=%s\n", opt_use_relay ? "on" : "off");
    for (int i = 0; vrchat_notable[i]; i++) {
        const char *ip = lookup_ip(vrchat_notable[i]);
        printf("[VRCHAT]   %s -> %s\n", vrchat_notable[i], ip ? ip : "?");
        // Удачный адрес сразу закрепляем на диске.
        //
        // Раньше vc_cache_put вызывался только при замене неработающего пина,
        // поэтому удачный набор никуда не попадал: файл оставался пустым, а на
        // следующем запуске всё определялось заново. Записать здесь — значит
        // дать следующему запуску начать с проверки удачных адресов, а не с
        // нуля.
        if (ip) vc_cache_put(vrchat_notable[i], ip);
    }

    ctx.mode = 1;
    if (opt_use_relay) {
        // Редиректим 443 пинованных адресов в собственный релей модуля.
        char seen[32][64];
        int nseen = 0;
        for (int i = 0; vrchat_pins[i].domain; i++) {
            const char *ip = vrchat_pins[i].ip;
            int dup = 0;
            for (int j = 0; j < nseen; j++) dup |= (strcmp(seen[j], ip) == 0);
            if (!dup && nseen < 32) {
                snprintf(seen[nseen], sizeof(seen[0]), "%s", ip);
                nseen++;
            }
        }
        for (int i = 0; i < nseen; i++)
            iptables_add_redirect(seen[i]);
        // CloudFront отдаёт контент с многих адресов; берём диапазоном целиком.
        for (int i = 0; vrchat_content_ranges[i]; i++)
            iptables_add_redirect(vrchat_content_ranges[i]);

        plain_relay_config_t rc = {
            .port = VRCHAT_RELAY_PORT,
            .so_mark = VRCHAT_SO_MARK,
            .chunk = opt_relay_chunk,
            .pause_ms = opt_relay_pause_ms,
            .idle_sec = opt_relay_idle_sec,
        };
        if (plain_relay_start(&rc) != 0) {
            fprintf(stderr, "[VRCHAT] relay start failed: %s\n", strerror(errno));
            iptables_del_rules();
            responder_stop();
            ctx.mode = 0;
            return;
        }
        printf("[VRCHAT]   relay: 127.0.0.1:%d (pid %d, chunk=%d pause=%dms idle=%ds)\n",
               VRCHAT_RELAY_PORT, plain_relay_pid(),
               opt_relay_chunk, opt_relay_pause_ms, opt_relay_idle_sec);
    } else {
        printf("[VRCHAT]   relay off: трафик идёт напрямую на пинованные адреса\n");
    }

    printf("[VRCHAT] inject done (responder pid %d, %s)\n",
           (int)responder_pid,
           is_root() ? "iptables active" : "no root — iptables skipped");
}

void vrchat_module_remove(void) {
    if (!vrchat_initialized) return;
    // Поток разведки обязан умереть ДО выгрузки библиотеки. Иначе он
    // просыпается после dlclose и исполняет код размапленного .so — это
    // падение. Раньше vrchat_discovery_stop() не вызывался вообще.
    vrchat_discovery_stop();
    pins_recheck_stop();
    iptables_del_rules();
    responder_stop();
    plain_relay_stop();
    ctx.mode = 0;
    printf("[VRCHAT] remove done\n");
}

const char *vrchat_get_status(void) {
    if (!vrchat_initialized) return "Off";
    if (!ctx.mode) return "Idle";
    if (responder_pid <= 0) return "Active (responder down!)";
    if (!opt_use_relay) return "Active (DNS pinning)";
    if (!plain_relay_running()) return "Active (relay down!)";
    return "Active (relay)";
}
