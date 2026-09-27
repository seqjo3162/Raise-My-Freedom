#include "src/modules/discord/include/header.h"
#include "src/dns/dns_resolve.h"
#include "src/dns/doh_resolve.h"
#include "src/common/sni_relay.h"
#include "src/common/claims.h"
#include "src/common/site_probe.h"
#include "src/netfilter/netfilter.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/time.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/stat.h>

static discord_ctx_t ctx = {0};
static bool discord_initialized = false;

typedef struct {
    const char *domain;
    const char *pinned_ip;
} discord_pin_t;

static const discord_pin_t discord_pins[] = {
    {"discord.com",                     "162.159.128.233"},
    {"discord.gg",                      "162.159.135.234"},
    {"cdn.discordapp.com",              "162.159.130.233"},
    {"media.discordapp.net",            "162.159.130.232"},
    {"status.discord.com",              "162.159.136.232"},
    {"gateway.discord.gg",              "162.159.133.234"},
    {"remote-auth-gateway.discord.gg",  "162.159.135.234"},
    {"discordapp.com",                  "162.159.134.233"},
    {"discord.media",                   "162.159.137.234"},
    {"dl.discordapp.net",               "104.18.48.115"},
    {"dl2.discordapp.net",              "34.126.226.51"},
    {"updates.discordapp.com",          "162.159.136.232"},
    {"cdn.discordapp.net",              "162.159.133.232"},
    {"api.discord.com",                 "162.159.128.233"},
    {"discordapp.net",                  "162.159.134.233"},
    {"updates.discord.com",             "162.159.135.232"},
    {NULL, NULL}
};

static const char *discord_dns_domains[] = {
    "discord.com",
    "discord.gg",
    "discordapp.com",
    "discordapp.net",
    "discord.media",
    "remote-auth-gateway.discord.gg",
    "gateway.discord.gg",
    "cdn.discordapp.net",
    "dl.discordapp.net",
    "media.discordapp.net",
    NULL
};

static int is_root(void) { return getuid() == 0; }

// команды «на всякий случай» (удаление правил, создание цепочки) — ошибки допустимы
static void sh(const char *cmd) {
    int rc = system(cmd);
    (void)rc;
}

// команды, без которых обход не заработает: молчаливый отказ здесь и есть причина
// «релей работает, а трафик не перехватывается»
static void sh_check(const char *cmd) {
    int rc = system(cmd);
    if (rc == -1) {
        fprintf(stderr, "[DISCORD] iptables: не удалось выполнить: %s\n", cmd);
    } else if (WIFEXITED(rc) && WEXITSTATUS(rc) != 0) {
        fprintf(stderr, "[DISCORD] iptables: ошибка %d: %s\n", WEXITSTATUS(rc), cmd);
    } else if (!WIFEXITED(rc)) {
        fprintf(stderr, "[DISCORD] iptables: аварийно завершилась: %s\n", cmd);
    }
}

discord_ctx_t *discord_get_ctx(void) { return &ctx; }

// ── Настройки (webui/discord.conf, необязательно) ────────────────────────
//
// Модуль не трогает ничего, кроме собственных адресов Discord:
//   - перехватываются только IP, которые он сам разрешил для своих доменов;
//   - чужие диапазоны (весь Cloudflare) не перехватываются никогда;
//   - правил в таблице filter модуль не ставит вообще: DROP на udp/443
//     приводит к тому, что клиент ждёт QUIC-ответа и считает сеть мёртвой,
//     а блокировка DoH к 1.1.1.1/8.8.8.8 ломает другие модули;
//   - адреса, уже занятые другим модулем, пропускаются (реестр claims).
#define DISCORD_CONF "webui/discord.conf"

// Метка модуля. Та же, что у реля: ею помечаются и его апстрим-сокеты, и
// наши собственные пробы, поэтому проба проходит мимо собственных
// правил модуля.
#define DISCORD_SO_MARK 0x4d5a

// Discord по умолчанию идёт через рель с разрывом SNI: измерено, что
// провайдер режет handshake по имени домена (SNI=discord.com — тишина,
// SNI=api.vrchat.cloud на том же IP — TLS 1.3 проходит). Без разрыва
// модуль не может ничего сделать, поэтому рель включён по умолчанию.
// use_relay=0 оставляет трафик напрямую — имеет смысл только если домен
// не режется.
static int opt_use_relay = 1;
static int opt_relay_chunk = 0;
static int opt_relay_pause_ms = 0;
static int opt_relay_cidr = 0;
static int opt_probe_pins = 0;
// relay_idle_sec убран: он читался в поле sni_relay_config_t, которого нет —
// sni_relay не имеет таймаута простоя вообще. Ключ, который читается вхолостую,
// вводит в заблуждение сильнее, чем его отсутствие. (У vrchat своя копия поля
// есть, потому что vrchat ходит через plain_relay, где таймаут предусмотрен.)
static int opt_split_ch = 1;
// 1 = модуль сам решает, рвать ли SNI, по результату живой пробы.
// 0 = уважать split_ch из конфига как есть.
// Заготовка под сквозную автоматику; сейчас выключена, потому что
// сигнал (site_probe_sni) оказался нестабилен. См. раздел выше.
static int opt_auto_split = 0;
static int opt_no_split_hs = 1;

// Сдвиг регистра SNI. Разрыв SNI ломает поток к Cloudflare примерно на
// 16 КБ, а сдвиг длину записи не меняет — обход остаётся, поток цел.
static int opt_shift_sni = 0;
static int opt_multi_parts = 2;
static int opt_frag_delay_ms = 30;
static int opt_frag_first_seg = 20;
static int opt_split_data = 0;
static int opt_split_size = 512;
static int opt_split_delay_ms = 0;

// Путь к конфигу. Раньше здесь был просто относительный "webui/discord.conf",
// и модуль читал его только если рабочий каталог процесса оказался корнем
// проекта. Под systemd это работает (в rmf.service задан WorkingDirectory),
// а при ручном запуске откуда угодно — нет: fopen не находит файл, и модуль
// МОЛЧА уходил на дефолты. Тихий откат опаснее явной ошибки, поэтому путь
// ищется от бинарника, от окружения и от каталога, и о неудаче сообщается.
static void discord_conf_path(char *out, size_t out_sz) {
    const char *env = getenv("RMF_ROOT");
    if (env && *env) {
        snprintf(out, out_sz, "%s/webui/discord.conf", env);
        if (access(out, R_OK) == 0) return;
    }
    char exe[1024];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n > 0) {
        exe[n] = '\0';
        char dir[1024];
        snprintf(dir, sizeof(dir), "%s", exe);
        // Поднимаемся от каталога бинарника к корню и ищем webui/discord.conf
        // на каждом уровне. Глубина разная: плагин лежит в build/bin/plugs/,
        // а тест — в src/modules/discord/build/, поэтому фиксированный
        // список путей рано или поздно перестаёт совпадать.
        for (int level = 0; level < 6; level++) {
            char cand[1200];
            snprintf(cand, sizeof(cand), "%s/webui/discord.conf", dir);
            if (access(cand, R_OK) == 0) {
                snprintf(out, out_sz, "%s", cand);
                return;
            }
            char *slash = strrchr(dir, '/');
            if (!slash || slash == dir) break;
            *slash = '\0';
        }
    }
    snprintf(out, out_sz, "%s", DISCORD_CONF);
}

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

static void load_conf(void) {
    char conf[1200];
    discord_conf_path(conf, sizeof(conf));
    if (access(conf, R_OK) != 0)
        fprintf(stderr, "[DISCORD] конфиг не найден (%s) — работаю на встроенных "
                        "значениях. Запуск не из корня проекта? Проверь RMF_ROOT.\n", conf);
    else
        printf("[DISCORD] конфиг: %s\n", conf);

    opt_use_relay       = conf_int(conf, "use_relay", 1);
    opt_relay_chunk     = conf_int(conf, "relay_chunk", 0);
    opt_relay_pause_ms  = conf_int(conf, "relay_pause_ms", 0);
    opt_split_ch        = conf_int(conf, "split_ch", 1);
    opt_auto_split      = conf_int(conf, "auto_split", 0);
    opt_no_split_hs     = conf_int(conf, "no_split_hs", 1);
    opt_frag_delay_ms   = conf_int(conf, "frag_delay_ms", 30);
    opt_frag_first_seg  = conf_int(conf, "frag_first_seg", 20);
    opt_split_data      = conf_int(conf, "split_data", 0);
    opt_shift_sni      = conf_int(conf, "shift_sni", 0);
    opt_multi_parts     = conf_int(conf, "multi_parts", 2);
    opt_split_size      = conf_int(conf, "split_size", 512);
    opt_split_delay_ms  = conf_int(conf, "split_delay_ms", 0);
    opt_relay_cidr      = conf_int(conf, "relay_cidr", 0);
    opt_probe_pins      = conf_int(conf, "probe_pins", 0);
    if (opt_relay_chunk < 0) opt_relay_chunk = 0;
    // relay_pause_ms: -1 означает «без пауз» (так его трактует sni_relay),
    // поэтому отрицательные значения НЕ обнуляем. Раньше здесь стоял
    // opt_relay_pause_ms < 0 -> 0, и объявленный в sni_relay.h способ
    // отключить паузу был недостижим: 0 там превращался в 1 мс.
    if (opt_relay_pause_ms < 0) opt_relay_pause_ms = -1;
    if (opt_frag_delay_ms < 0) opt_frag_delay_ms = 0;
    if (opt_frag_first_seg < 1) opt_frag_first_seg = 1;
    if (opt_split_size < 1) opt_split_size = 1;
    if (opt_split_delay_ms < 0) opt_split_delay_ms = 0;
    if (opt_multi_parts < 2) opt_multi_parts = 2;
    // Ключи, для которых 0 означает «выключено», приводим к 0/1 явно:
    // мусор в файле не должен молча включать разрыв SNI.
    if (opt_use_relay < 0) opt_use_relay = 0;
    if (opt_split_ch < 0) opt_split_ch = 0;
    if (opt_auto_split < 0) opt_auto_split = 0;
    if (opt_no_split_hs < 0) opt_no_split_hs = 0;
    if (opt_shift_sni < 0) opt_shift_sni = 0;
    if (opt_split_data < 0) opt_split_data = 0;
    if (opt_relay_cidr < 0) opt_relay_cidr = 0;
    if (opt_probe_pins < 0) opt_probe_pins = 0;
    if (opt_split_ch > 1) opt_split_ch = 1;
    if (opt_auto_split > 1) opt_auto_split = 1;
    if (opt_no_split_hs > 1) opt_no_split_hs = 1;
    if (opt_shift_sni > 1) opt_shift_sni = 1;
    if (opt_split_data > 1) opt_split_data = 1;
    if (opt_relay_cidr > 1) opt_relay_cidr = 1;
    if (opt_probe_pins > 1) opt_probe_pins = 1;
}

// ── iptables ─────────────────────────────────────────────────────────────



  static void iptables_base(void) {
      if (!is_root()) return;
      sh("iptables -t nat -N DISCORD_BYPASS 2>/dev/null || true");
      // Цепочку обязательно очищаем перед наполнением. Раньше здесь стоял
      // только -N ... || true, и это делало inject неидемпотентным: каждый
      // запуск ДОБАВЛЯЛ правила к уже существующим, ничего не убирая.
      //
      // Последствия были такие. Если процесс плагина умирает, не доиграв до
      // cleanup (SIGKILL, падение, kill -9), правила остаются в системе
      // навсегда. Веб после этого обнуляет pid модуля, и следующий
      // /api/stop?plugin=discord становится пустой операцией — сносить правила
      // уже некому. Дальше они только копятся: модуль перехватывал адреса на
      // мёртвый порт реля, и клиент получал мгновенный RST, то есть
      // ERR_CONNECTION_REFUSED при выключенном модуле.
      //
      // С очисткой на старте это самоисцеляется: осиротевшие правила уходят при
      // следующем включении, а дубликаты не накапливаются.
      //
      // Сброс безопасен: ниже все нужные правила ставятся заново, а
      // параллельно работающих копий модуля быть не может — веб держит по
      // одному процессу на имя.
      sh("iptables -t nat -F DISCORD_BYPASS 2>/dev/null || true");
      // Помеченные пакеты любого модуля не трогаем: 0x4d5a discord, 0x4d5b vrchat,
      // 0x4d5c google, 0x4d5e speedtest -> маска 0x4d50/0xfff0.
      sh_check("iptables -t nat -C DISCORD_BYPASS -m mark --mark 0x4d50/0xfff0 -j RETURN "
         "2>/dev/null || iptables -t nat -I DISCORD_BYPASS 1 -m mark --mark 0x4d50/0xfff0 -j RETURN");
      sh("iptables -t nat -D OUTPUT -j DISCORD_BYPASS 2>/dev/null");
      sh_check("iptables -t nat -I OUTPUT 1 -j DISCORD_BYPASS");
  }

static void iptables_add_dns_rule(const char *domain) {
    if (!is_root() || !domain || !*domain) return;
    // Через общий слой, а не своей сборкой команды. Раньше здесь был
    // -m string --string "%s", куда уходили СЫРЫЕ байты длины лейбла прямо
    // через system(): длина 34 даёт 0x22 ("), 36 — 0x24 ($), 39 — 0x27 ('),
    // и любой такой домен молча ломал бы команду. Сейчас список доменов
    // короткий, но это бомба с часовым механизмом.
    //
    // nf_dns_redirect кодирует шаблон в hex (|07…|), ограничивает длину
    // и сам делает пару -C/-A. Плюс он печатает в лог, а не молчит.
    if (nf_dns_redirect("DISCORD_BYPASS", domain, 53) != 0)
        fprintf(stderr, "[DISCORD] не удалось поставить DNS-правило для %s\n", domain);
}

// Диапазон Discord. DNS (в том числе /etc/hosts) может отдать любой адрес
// из набора — проверено: 162.159.138.232 и 162.159.128.233 проходят через
// рель, а 162.159.137.232 (его отдаёт /etc/hosts) режется провайдером.
// Поэтому перехватываем /18, где Discord держит свои адреса. Это не «весь
// Cloudflare», как было раньше, — только выделенный Discord диапазон.
static const char *const discord_ranges[] = { "162.159.128.0/18", NULL };

static void iptables_add_redirect(const char *ip) {
    if (!is_root() || !ip) return;
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "iptables -t nat -C DISCORD_BYPASS -p tcp -d %.63s --dport 443 "
        "-j REDIRECT --to-ports %d 2>/dev/null || "
        "iptables -t nat -A DISCORD_BYPASS -p tcp -d %.63s --dport 443 "
        "-j REDIRECT --to-ports %d",
        ip, ctx.relay_port, ip, ctx.relay_port);
    sh_check(cmd);
}

// QUIC к Discord надо не глушить, а отклонять мгновенно.
//
// Раньше стоял DROP на udp/443. Разница для браузера огромная: при DROP
// пакет исчезает без ответа, клиент ждёт таймаута и только потом решает, что
// QUIC не работает. При REJECT клиент получает отказ сразу и мгновенно
// откатывается на TCP. На практике это разница между «Discord открывается
// сразу» и «половина вкладок висит по десять секунд».
// Отклонение QUIC для адресов Discord.
//
// Правила кладём в СВОЮ цепочку, а не прямо в filter/OUTPUT. Причина:
// правила в OUTPUT сносились только частично — по маске и по другому
// действию, — и REJECT живых QUIC-правил уезжали в вечность. Один запуск
// start discord выключал HTTP/3 у всего Cloudflare, и stop их не снимал.
//
// Диапазоны намеренно УЗКИЕ: только адреса Discord. Раньше стояли
// 104.16.0.0/12 и 104.18.0.0/16, а в них попадают все три адреса VRChat
// (104.18.26.36, 104.18.6.156, 104.16.241.118) — то есть один модуль глушил
// QUIC другому. Теперь перечислены конкретные адреса.
// ── Накопленный набор адресов Discord ─────────────────────────────────────
//
// Почему это вообще нужно. Раньше здесь стоял вывод: «клиент не может получить
// адрес вне проверенного набора», потому что DNS-запросы Discord заворачиваются
// на 127.0.0.1:53. Это допущение неверно: у Chrome включён Secure DNS, он
// спрашивает адреса у собственного DoH (проверено: соединение chrome ->
// 85.192.63.126:443) и наш редирект UDP/53 его не касается. Клиент выбирает
// адрес сам, из всего пула Cloudflare, а правила стоят только на той части,
// которую мы успели увидеть при inject'е.
//
// Отсюда ровно то, что видно в логе браузера: часть ресурсов идёт по TCP и
// работает, часть падает с ERR_QUIC_PROTOCOL_ERROR. Разница стабильная, потому
// что Chrome кеширует адрес на origin. QUIC-отклонение срабатывало ноль раз из
// 15 правил — не потому что REJECT сломан (он работает, проверено пробой
// пакета), а потому что к моменту обращения правила для этого адреса не было.
//
// Почему не закрыть диапазоном 162.159.128.0/18. Он накрыл бы всю дыру, но
// в нём же лежит x.com — 162.159.140.229. REJECT udp/443 на /18 унёс бы
// HTTP/3 у Twitter/X, то есть сломал бы чужой сайт. Поэтому диапазон
// применять нельзя, а набор адресов надо растить.
//
// Набор копится в /run/rmf/pins/DISCORD.ips и пополняется фоновой
// перепроверкой. Важно: туда попадают только адреса, прошедшие проверку
// принадлежности в collect_own_ips, поэтому чужие адреса в принципе не могут
// попасть ни в REDIRECT, ни в QUIC-REJECT. Это и есть «обойти, не сломав».
#define DC_SET_MAX 64
static char dc_set[DC_SET_MAX][64];
static int dc_set_n;
static int dc_set_loaded;

static void dc_set_path(char *out, size_t cap) {
    snprintf(out, cap, "/run/rmf/pins/DISCORD.ips");
}

static int dc_set_has(const char *ip) {
    for (int i = 0; i < dc_set_n; i++)
        if (strcmp(dc_set[i], ip) == 0) return 1;
    return 0;
}

// Вернуть адрес в набор. Новые адреса помечаем, чтобы фоновая нить знала, что
// для них надо доставить правила. Список на диск пишем сразу: переживать
// перезапуск модуля должен сам набор, а не память процесса.
static int dc_set_add(const char *ip) {
    if (!dc_set_loaded) dc_set_loaded = 1;
    if (dc_set_has(ip)) return 0;
    if (dc_set_n >= DC_SET_MAX) return 0;
    snprintf(dc_set[dc_set_n], sizeof dc_set[0], "%.63s", ip);
    dc_set_n++;
    char path[512], tmp[560];
    mkdir("/run/rmf", 0755);
    mkdir("/run/rmf/pins", 0755);
    dc_set_path(path, sizeof path);
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (f) {
        for (int i = 0; i < dc_set_n; i++) fprintf(f, "%s\n", dc_set[i]);
        fclose(f);
        rename(tmp, path);
    }
    return 1;
}

// Набор с прошлых запусков. Проверку принадлежности он уже прошёл в момент,
// когда егоaddress был добавлен, поэтому берём как есть — но только если это
// действительно адрес, а не мусор в файле.
static void dc_set_load(void) {
    dc_set_n = 0;
    dc_set_loaded = 1;
    char path[512];
    dc_set_path(path, sizeof path);
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[80];
    while (fgets(line, sizeof line, f) && dc_set_n < DC_SET_MAX) {
        char *nl = strpbrk(line, " \t\r\n");
        if (nl) *nl = '\0';
        struct in_addr a;
        if (line[0] && inet_pton(AF_INET, line, &a) == 1)
            snprintf(dc_set[dc_set_n++], sizeof dc_set[0], "%.63s", line);
    }
    fclose(f);
    if (dc_set_n)
        printf("[DISCORD] накопленный набор: %d адресов из %s\n", dc_set_n, path);
}



static void iptables_quic_base(void) {
    if (!is_root()) return;
    sh("iptables -N DISCORD_QUIC 2>/dev/null || true");
    sh("iptables -F DISCORD_QUIC 2>/dev/null || true");
    sh("iptables -D OUTPUT -j DISCORD_QUIC 2>/dev/null");
    sh("iptables -I OUTPUT 1 -j DISCORD_QUIC");
}

static void iptables_quic_reject(const char *net) {
    if (!is_root() || !net) return;
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "iptables -C DISCORD_QUIC -p udp --dport 443 -d %.63s -j REJECT "
        "--reject-with icmp-port-unreachable 2>/dev/null || "
        "iptables -A DISCORD_QUIC -p udp --dport 443 -d %.63s -j REJECT "
        "--reject-with icmp-port-unreachable",
        net, net);
    sh_check(cmd);
}

// Лежит ли адрес (или префикс) в инфраструктуре Discord. Определение ниже,
// рядом с самой таблицей диапазонов; здесь нужно раньше по коду.
static int dest_in_discord(const char *tok);

static void iptables_del_rules(void) {
    if (!is_root()) return;
    sh("iptables -t nat -D OUTPUT -j DISCORD_BYPASS 2>/dev/null");
    sh("iptables -t nat -F DISCORD_BYPASS 2>/dev/null");
    sh("iptables -t nat -X DISCORD_BYPASS 2>/dev/null");
    // Свою цепочку снимаем целиком — так REJECT точно не останется висеть.
    sh("iptables -D OUTPUT -j DISCORD_QUIC 2>/dev/null");
    sh("iptables -F DISCORD_QUIC 2>/dev/null");
    sh("iptables -X DISCORD_QUIC 2>/dev/null");
    // Старые версии модуля оставляли DROP в filter: снимаем, чтобы не осталось
    // правил, которые молча глушат QUIC и DoH.
    sh("iptables -D OUTPUT -p udp --dport 443 -d 162.159.0.0/16 -j DROP 2>/dev/null");
    sh("iptables -D OUTPUT -p udp --dport 443 -d 104.16.0.0/12 -j DROP 2>/dev/null");
    sh("iptables -D OUTPUT -p udp --dport 443 -d 104.18.0.0/16 -j DROP 2>/dev/null");
    sh("iptables -D OUTPUT -p udp --dport 443 -d 162.159.128.0/18 -j DROP 2>/dev/null");
    sh("iptables -D OUTPUT -p udp --dport 443 -d 162.159.128.0/18 -j REJECT "
       "--reject-with icmp-port-unreachable 2>/dev/null");
    // Старые версии ставили DROP на КАЖДЫЙ адрес отдельным правилом (/32), а
    // чистились только правила с маской /16. Хвосты оставались в системе навсегда
    // и молча глушили QUIC.
    //
    // Перебор идёт через iptables -S только на чтение: он перечисляет правила,
    // а удаляем мы каждое точным -D. Два условия обязательны:
    //
    //   * адрес назначения лежит в наших диапазонах. Без этой проверки снос
    //     ушёл бы по любому правилу udp/443 в OUTPUT — включая чужие модули,
    //     docker и правила самого пользователя;
    //   * только DROP и REJECT.
    //
    // Превращение строки в команду: -A OUTPUT и -D OUTPUT отличаются РОВНО
    // ОДНИМ символом, поэтому достаточно заменить line[1] на 'D'. Раньше здесь
    // стоял memmove, который сдвигал начало на 6 байт и терял «OUTPUT», из-за
    // чего на выходе шло «iptables -A -p udp ...» без имени цепочки: правило не
    // удалялось, ошибка глоталась, блок был мёртвым.
    {
        char line[512];
        FILE *f = popen("iptables -S OUTPUT 2>/dev/null", "r");
        if (f) {
            while (fgets(line, sizeof(line), f)) {
                if (!strstr(line, "--dport 443") || !strstr(line, "udp")) continue;
                if (!strstr(line, "-j DROP") && !strstr(line, "-j REJECT")) continue;
                if (strncmp(line, "-A ", 3) != 0) continue;
                const char *d = strstr(line, " -d ");
                if (!d) continue;
                d += 4;
                char tok[64];
                size_t k = 0;
                while (d[k] && d[k] != ' ' && k + 1 < sizeof(tok)) { tok[k] = d[k]; k++; }
                tok[k] = '\0';
                if (!dest_in_discord(tok)) continue;
                char *nl = strchr(line, '\n');
                if (nl) *nl = '\0';
                line[1] = 'D';                     // -A -> -D, больше ничего
                char cmd[600];
                snprintf(cmd, sizeof(cmd), "iptables %s 2>/dev/null", line);
                sh(cmd);
                printf("[DISCORD]   снят хвост старой версии: %s\n", tok);
            }
            pclose(f);
        }
    }
    sh("iptables -D OUTPUT -p tcp -m multiport --dports 443,853 "
       "-d 1.1.1.1,1.0.0.1 -j DROP 2>/dev/null");
    sh("iptables -D OUTPUT -p tcp -m multiport --dports 443,853 "
       "-d 8.8.8.8,8.8.4.4 -j DROP 2>/dev/null");
    sh("iptables -D OUTPUT -p tcp -m multiport --dports 443,853 "
       "-d 9.9.9.9,149.112.112.112 -j DROP 2>/dev/null");
}

// ── Свои адреса ──────────────────────────────────────────────────────────

// Инфраструктура, в которой адреса Discord действительно наблюдались.
// Это фильтр правдоподобия, а не доказательство принадлежности: Cloudflare и
// CloudFront общие, и адрес чужого сайта может лежать рядом. Ловит подмену
// (sinkhole вроде 8.47.69.0), мусор из hosts.txt и адреса, которых в Discord
// не бывает. bits == 0 — конец списка.
typedef struct { unsigned char net[4]; int bits; } discord_net_t;

static const discord_net_t discord_owned[] = {
    { {162, 159, 128, 0}, 18 },   // Cloudflare: адреса Discord
    { {104,  16,   0, 0}, 12 },   // Cloudflare: dl.discordapp.net
    { { 34, 126,   0, 0}, 16 },   // GCP: dl2.discordapp.net
    { {  0,   0,   0, 0},  0 },
};

static int parse_ipv4(const char *s, unsigned char out[4]) {
    struct in_addr a;
    if (!s || !*s || inet_pton(AF_INET, s, &a) != 1) return 0;
    memcpy(out, &a.s_addr, 4);
    return 1;
}

static int net_contains(const discord_net_t *n, const unsigned char *ip) {
    if (n->bits <= 0) return 0;
    int full = n->bits / 8, rem = n->bits % 8;
    if (full > 0 && memcmp(ip, n->net, (size_t)full) != 0) return 0;
    if (!rem) return 1;
    unsigned char mask = (unsigned char)(0xFFu << (8 - rem));
    return (ip[full] & mask) == (n->net[full] & mask);
}

// Границы, в которых модулю РАЗРЕШЕНО удалять правила.
//
// Узко, и это принципиально. Здесь решает, что можно снести, поэтому в список
// попадает только то, что старые версии модуля действительно ставили:
//
//   * адреса из таблицы пинов;
//   * 162.159.128.0/18 — диапазон, объявленный самим модулем.
//
// НЕ попадают 104.16.0.0/12 и 104.18.0.0/16, хотя модуль их тоже ставил:
// внутри них живут адреса VRChat (104.18.26.36, 104.18.6.156, 104.16.241.118),
// и правило на /32 такого адреса снеслось бы вместе с нашими. Широкие правила
// старых версий снимаются отдельно — точным -D по конкретной спецификации,
// а /32 внутри /12 такое удаление не задевает.
static int dest_in_discord(const char *tok) {
    if (!tok || !*tok) return 0;
    char ip[64];
    snprintf(ip, sizeof(ip), "%s", tok);
    char *slash = strchr(ip, '/');
    if (slash) *slash = '\0';
    unsigned char b[4];
    if (!parse_ipv4(ip, b)) return 0;
    char key[32];
    snprintf(key, sizeof(key), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    for (int i = 0; discord_pins[i].domain; i++)
        if (strcmp(key, discord_pins[i].pinned_ip) == 0) return 1;
    static const discord_net_t legacy_range = { {162, 159, 128, 0}, 18 };
    return net_contains(&legacy_range, b);
}

// Хук реля: дёшево и без сети. relay_ip_allowed дёргает его на каждого
// кандидата при каждом соединении (sni_relay.c:527), поэтому сеть здесь
// недопустима — это отдельная проверка, см. discord_ip_reachable.
int discord_validate_ip(const char *ip) {
    unsigned char b[4];
    if (!parse_ipv4(ip, b)) return 0;
    for (int i = 0; discord_owned[i].bits > 0; i++)
        if (net_contains(&discord_owned[i], b)) return 1;
    return 0;
}

// Живая проверка: до адреса доходит TCP-рукопожатие.
//
// Проба обязана быть помеченной. Непомеченная идёт мимо правил модуля по
// остаточным причинам и measures accept собственного реля вместо пути до
// адреса — ровно та ошибка, из-за которой в пины VRChat попал заблокированный
// 143.204.238.54. Помеченная проба идёт напрямую.
//
// Только TCP, а не SNI. Блокировка Discord сделана по имени в ClientHello
// (комментарий выше), поэтому SNI-проба не отвечает by design и забраковала
// бы все живые адреса. TCP-рукопожатие проходит.
//
// Требует root: без права ставить SO_MARK проба осталась бы непомеченной и
// повторила бы ровно то, что мы чиним. Без root проверку пропускаем целиком,
// а не делаем вид, что адрес годен.
static int discord_ip_reachable(const char *ip) {
    if (!is_root()) return 1;
    return site_probe_tcp(ip, 443, 3000) == 1;
}

// Вердикт с запоминанием: один адрес встречается у нескольких доменов, а
// проба стоит TCP-рукопожатие.
typedef struct { char ip[64]; int verdict; } discord_verdict_t;

static int ip_admitted(const discord_verdict_t *cache, int ncache, const char *ip) {
    for (int i = 0; i < ncache; i++)
        if (strcmp(cache[i].ip, ip) == 0) return cache[i].verdict;
    return -1;                                   // ещё не решали
}

// Возвращает 1 — адрес годится, 0 — отсеян, и печатает почему.
//
// probe: живой TCP или только правдоподобие. Для адресов, разрешённых только
// что, проба обязательна — это единственный способ отсеять протухшее. Для
// зашитых пинов она по умолчанию выключена: список отобран руками, и ложный
// «не отвечает» на живом адресе из этого списка ломает Discord сильнее, чем
// один лишний адрес в правилах. Включается probe_pins=1.
static int admit_ip(const char *ip, int probe, const char *why,
                    discord_verdict_t *cache, int *ncache) {
    int known = ip_admitted(cache, *ncache, ip);
    if (known < 0) {
        known = discord_validate_ip(ip) && (!probe || discord_ip_reachable(ip));
        if (*ncache < 32) {
            snprintf(cache[*ncache].ip, sizeof(cache[0].ip), "%s", ip);
            cache[(*ncache)++].verdict = known;
        }
    }
    if (!known) printf("[DISCORD]   %s %s — адрес отсеян, в правила не идёт\n", ip, why);
    return known;
}

// Разрешает домены Discord и возвращает список адресов, которые принадлежат
// именно этому модулю. Всё, что не прошло проверку, сюда не попадает и до
// iptables не доходит.
static int collect_own_ips(char ips[][64], int max) {
    int n = 0;
    discord_verdict_t cache[32];
    int ncache = 0;
    for (int i = 0; discord_dns_domains[i] && n < max; i++) {
        char ip[64] = {0};
        if (doh_resolve_a(discord_dns_domains[i], ip, sizeof(ip)) != 0 &&
            dns_resolve_udp(ctx.primary, discord_dns_domains[i], ip, sizeof(ip)) != 0)
            dns_resolve_udp(ctx.fallback, discord_dns_domains[i], ip, sizeof(ip));
        if (!ip[0]) { printf("[DISCORD]   %s -> DNS FAIL\n", discord_dns_domains[i]); continue; }
        int dup = 0;
        for (int j = 0; j < n; j++) dup |= (strcmp(ips[j], ip) == 0);
        if (dup) continue;
        if (!admit_ip(ip, 1, "(не наш диапазон или не отвечает)", cache, &ncache)) continue;
        snprintf(ips[n++], 64, "%s", ip);
        printf("[DISCORD]   %s -> %s\n", discord_dns_domains[i], ip);
    }
    for (int i = 0; discord_pins[i].domain && n < max; i++) {
        int dup = 0;
        for (int j = 0; j < n; j++) dup |= (strcmp(ips[j], discord_pins[i].pinned_ip) == 0);
        if (dup) continue;
        // Пин проверяем на правдоподобие всегда (это бесплатно и ловит
        // подмену), а вот живую пробу — только если её включил пользователь.
        if (!admit_ip(discord_pins[i].pinned_ip, opt_probe_pins,
                      "(пин вне наших диапазонов)", cache, &ncache)) continue;
        snprintf(ips[n++], 64, "%s", discord_pins[i].pinned_ip);
    }
    return n;
}

// ── lifecycle ────────────────────────────────────────────────────────────

void discord_module_init(discord_config_t *config) {
    if (discord_initialized) return;

    snprintf(ctx.primary, sizeof(ctx.primary), "%s", "127.0.0.1");
    snprintf(ctx.fallback, sizeof(ctx.fallback), "%s", "8.8.8.8");
    if (config && config->primary_dns) snprintf(ctx.primary, sizeof(ctx.primary), "%s", config->primary_dns);
    if (config && config->fallback_dns) snprintf(ctx.fallback, sizeof(ctx.fallback), "%s", config->fallback_dns);
    ctx.primary[31] = '\0';
    ctx.fallback[31] = '\0';
    char *c;
    if ((c = strchr(ctx.primary, ':'))) *c = '\0';
    if ((c = strchr(ctx.fallback, ':'))) *c = '\0';

    ctx.relay_port = (config && config->relay_port > 0 && config->relay_port <= 65535)
        ? config->relay_port : 18443;
    ctx.relay_pid = -1;
    ctx.socket_fd = -1;
    ctx.mode = 0;

    discord_initialized = true;
    printf("[DISCORD] init: DNS %s / %s, relay:%d (own IPs only)\n",
           ctx.primary, ctx.fallback, ctx.relay_port);
}

void discord_module_cleanup(void) {
    if (!discord_initialized) return;
    discord_module_remove();
    if (ctx.socket_fd >= 0) { close(ctx.socket_fd); ctx.socket_fd = -1; }
    discord_initialized = false;
    printf("[DISCORD] cleanup done\n");
}

// ── Нужен ли разрыв SNI ─────────────────────────────────────────────────
//
// Разрыв SNI на этой сети — не плата за обход, а сам обход. Замерено в обоих
// состояниях, оракулом на Content-Length (styles.css, 782354 Б):
//
//     сеть открыта:  split_ch=0 -> 782354 целиком,  split_ch=1 -> обрыв
//     сеть закрыта:  split_ch=0 -> 0 байт,          split_ch=1 -> ~190-205 КБ
//
// Ни одна фиксированная настройка не выигрывает всегда, а состояние сети
// меняется за минуты (наблюдалось: открыто -> закрыто -> открыто в пределах
// сессии). Значит решать надо в момент включения, по факту.
//
// ПОЧЕМУ ЗАМЕР СДЕЛАН ТАК. Первая попытка опиралась на site_probe_sni и
// провалилась: проба на одном и том же адресе с одним и тем же SNI то
// отвечала, то молчала, то есть давала ложные отрицания. Здесь вместо
// синтетической пробы — НАСТОЯЩИЙ TLS через штатный путь модуля: то же
// соединение, которое делает браузер (тот же адрес, тот же порт, те же
// правила REDIRECT, тот же перебор кандидатов внутри реля), только вместо
// страницы читается поток и считается объём.
//
// Порог срезается по факту: если с текущим вариантом пришло заметно больше
// данных, он и оставлен, независимо от того, что написано в конфиге.

// Сколько байт считаем «поток жив». Обрез при разрыве SNI даёт 20-25 КБ,
// нормальная передача — сотни килобайт. Порог посередине.
// Окно замера. 5 с было мало: соединение через проходной рель уходит в
// перебор кандидатов и на заблокированном адресе ждёт CONNECT_TIMEOUT,
// поэтому успешный запрос успевает занять 10-15 с. Слишком короткое окно
// давало ложное «путь закрыт» — и модуль выбирал разрыв SNI там, где
// проходной путь работал.
#define DISCORD_MEASURE_SEC     15
// Столько адресов перебираем при замере. Больше — медленно: на каждый уходит
// своё окно, а весь inject выполняется синхронно и держит веб.
#define DISCORD_MEASURE_ADDRS     4
// Эталонный ассет Discord: 782354 байта по Content-Length. Взят из разбора
// страницы; при обрыве приходит 20-205 КБ, при полной доставке — все 782354.
#define DISCORD_MEASURE_FULL     782354
#define DISCORD_MEASURE_URL \
    "https://discord.com/w/assets/3ae7a3b831a56041cc902e92f73907e4e121f31d/styles.css"
// Ниже этого объёма поток считается оборванным.
#define DISCORD_MEASURE_FLOOR   262144


// Запуск реля в заданном режиме разрыва SNI. Один помощник на оба
// варианта: иначе конфиг реля пришлось бы дублировать, и при правке
// одного места второе молча разошлось бы (так уже было с split_data).
static int start_relay(int use_split) {
    sni_relay_config_t rc = {
        .port = ctx.relay_port,
        .so_mark = DISCORD_SO_MARK,
        .validate_ip = discord_validate_ip,
        .frag_delay_ms = opt_frag_delay_ms,
        .frag_first_seg = opt_frag_first_seg,
        .primary_dns = ctx.primary,
        .fallback_dns = ctx.fallback,
        // Ключ модуля и поле реля названы по-разному, поэтому инверсия:
        // split_ch=1 означает «рвать», а поле значит «не рвать».
        .no_split_client_hello = use_split ? 0 : 1,
        .shift_sni = opt_shift_sni,
        .split_data_records = opt_split_data,
        .split_record_size = opt_split_size,
        .split_record_delay_ms = opt_split_delay_ms,
        .data_chunk = opt_relay_chunk > 0 ? opt_relay_chunk : 0,
        .data_pause_ms = opt_relay_pause_ms,
        .no_split_handshake_records = opt_no_split_hs,
        .multi_parts = opt_multi_parts,
    };
    if (sni_relay_start(&rc) != 0) return -1;
    ctx.relay_pid = sni_relay_pid();
    return 0;
}

// Настоящий TLS к адресу модуля. Возвращает число прочитанных байт или -1,
// если рукопохатие не состоялось. Именно -1 отличает «сеть закрыта» от
// «поток жив, просто не успели» — это разные ветки решения.
// Диагностика замера: куда именно он упал.
static char g_measure_why[192];

// Замер объёма через РЕАЛЬНЫЙ путь: тот же адрес и порт, куда уйдёт клиент,
// те же правила REDIRECT, тот же рель с перебором кандидатов. Считаем, сколько
// байт доехало.
//
// Почему curl, а не свой OpenSSL-клиент. Браузеры и curl дополняют
// ClientHello (TLS 1.3 padding) примерно до 517 байт, и это видно в логе реля
// как blen=517. Самодельный ClientHello без padding DPI режет: проверено, что
// на живом адресе curl отдавал 191-205 КБ, а самодельное рукопощатие падало с
// ssl_err=5 и пустым буфером ошибок OpenSSL — то есть соединение закрывали.
// Такой замер давал бы ложные отрицания и решения на нём принимать нельзя.
//
// Тот же приём уже применён в src/dns/doh_resolve.c (fork+curl), так что это
// не новый способ, а уже принятый в проекте.
static long measure_path(const char *ip);

// Замер по НЕСКОЛЬКИМ адресам с выбором лучшего.
//
// Раньше мерился один адрес — первый в списке. Это и было причиной
// расхождений: модуль писал «20508 Б», пока реальный трафик в это же время
// отдавал 782354 Б. Клиент идёт на тот адрес, который дал его DNS, а замер
// смотрел на произвольный. Часть адресов Discord отдаёт файл целиком, часть
// режет поток примерно на 20 КБ, поэтому один замер не показателен.
//
// Возвращает лучший результат; в best_ip кладётся адрес-победитель, чтобы
// рель дальше ходил именно в него (sni_relay_prefer).
static long measure_best(const char ips[][64], int n, char *best_ip, size_t cap) {
    long best = -1;
    const int tries = n < DISCORD_MEASURE_ADDRS ? n : DISCORD_MEASURE_ADDRS;
    for (int i = 0; i < tries; i++) {
        long got = measure_path(ips[i]);
        printf("[DISCORD]   замер %s -> %ld Б\n", ips[i], got);
        if (got > best) {
            best = got;
            // Явная копия с границей: gcc не может доказать, что элемент
            // двумерного массива короче sizeof(best_ip), и ругался на %s.
            size_t k = 0;
            while (k + 1 < cap && ips[i][k]) { best_ip[k] = ips[i][k]; k++; }
            best_ip[k] = '\0';
        }
    }
    return best;
}

static long measure_path(const char *ip) {
    g_measure_why[0] = '\0';

    struct sigaction ignore, saved;
    memset(&ignore, 0, sizeof ignore);
    ignore.sa_handler = SIG_IGN;
    sigemptyset(&ignore.sa_mask);
    int have_saved = (sigaction(SIGPIPE, &ignore, &saved) == 0);

    char tmp[] = "/tmp/rmf-discord-measure.XXXXXX";
    int fd = mkstemp(tmp);
    if (fd < 0) {
        snprintf(g_measure_why, sizeof g_measure_why, "не создать временный файл");
        if (have_saved) sigaction(SIGPIPE, &saved, NULL);
        return -1;
    }
    close(fd);

    char cmd[1200];
    snprintf(cmd, sizeof cmd,
             "curl -s -m %d -o '%s' --resolve 'discord.com:443:%s' '%s' 2>/dev/null",
             DISCORD_MEASURE_SEC, tmp, ip, DISCORD_MEASURE_URL);

    long got = -1;
    struct stat st;
    if (system(cmd) == 0 && stat(tmp, &st) == 0)
        got = (long)st.st_size;
    else if (stat(tmp, &st) == 0)
        got = (long)st.st_size;      // curl вернёт非0 при обрыве — размер всё равно полезен
    unlink(tmp);

    if (got <= 0) {
        got = -1;
        snprintf(g_measure_why, sizeof g_measure_why,
                 "ни одного байта за %d с — путь закрыт", DISCORD_MEASURE_SEC);
    } else if (got < DISCORD_MEASURE_FLOOR) {
        snprintf(g_measure_why, sizeof g_measure_why,
                 "поток оборвался на %ld Б (полный файл %d Б)", got, DISCORD_MEASURE_FULL);
    }
    if (have_saved) sigaction(SIGPIPE, &saved, NULL);
    return got;
}


// ── Фоновая перепроверка набора адресов ──────────────────────────────────
//
// Набор, собранный на момент inject'а, протухает: Cloudflare отдаёт клиенту
// другой адрес, и до следующего перезапуска модуля для него нет ни REDIRECT,
// ни QUIC-REJECT. Раньше это лечилось только перезапуском модуля в вебе —
// то есть руками и не вовремя. Нить переспрашивает адреса и доставляет
// правила для новых сама.
//
// Заодно это лечит не только QUIC, но и обрыв потока на ~20 КБ: без REDIRECT
// клиент идёт напрямую в заблокированный адрес и не получает ничего.
static volatile int dc_refresh_stop;
static int dc_refresh_split;
static pthread_t dc_refresh_th;
static int dc_refresh_running;
static pthread_mutex_t dc_wait_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t dc_wait_cv = PTHREAD_COND_INITIALIZER;

// Пауза между обходами, прерываемая мгновенно. Раньше здесь был sleep(1) в
// цикле, из-за чего выключение модуля растягивалось: веб-интерфейс шлёт SIGTERM
// и ровно через секунду бьёт SIGKILL, а pthread_join ждал завершения текущей
// секунды. С SIGKILL очистка не выполняется вообще, и в системе остаются
// правила REDIRECT на уже мёртвый порт реля — клиент получает мгновенный RST,
// то есть ERR_CONNECTION_CLOSED/REFUSED при выключенном модуле.
static void dc_wait(int sec) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += sec;
    pthread_mutex_lock(&dc_wait_mu);
    if (!dc_refresh_stop)
        pthread_cond_timedwait(&dc_wait_cv, &dc_wait_mu, &ts);
    pthread_mutex_unlock(&dc_wait_mu);
}

// Разбудить ожидание при остановке.
static void dc_wait_wake(void) {
    pthread_mutex_lock(&dc_wait_mu);
    pthread_cond_broadcast(&dc_wait_cv);
    pthread_mutex_unlock(&dc_wait_mu);
}

static void *dc_refresh_thread(void *arg) {
    (void)arg;
    int round = 0;
    while (!dc_refresh_stop && ctx.mode) {
        // Ровно минута между обходами. Быстрее бессмысленно: адреса так часто
        // не меняются, а каждый обход — это DoH-запросы и exec iptables.
        for (int slept = 0; slept < 60 && !dc_refresh_stop && ctx.mode; slept++)
            dc_wait(1);
        if (dc_refresh_stop || !ctx.mode) break;
        round++;

        char ips[32][64];
        int n = collect_own_ips(ips, 32);
        int added = 0;
        for (int i = 0; i < n; i++) {
            // Проверяем флаг на каждой итерации: collect_own_ips ходит в сеть и
            // занимает секунды, за это время модуль могут остановить. Без этой
            // проверки нить успевает поставить правила ПОСЛЕ очистки, и на
            // системе остаётся комплект REDIRECT на мёртвый порт реля — клиент
            // получает мгновенный RST, то есть ровно ERR_CONNECTION_REFUSED.
            if (dc_refresh_stop || !ctx.mode) return NULL;
            if (claims_taken_by_other("discord", ips[i])) continue;
            if (!dc_set_add(ips[i])) continue;      // уже был — молча
            added++;
            if (!opt_use_relay) continue;
            // Правила доставляем сразу, иначе адрес успеет отслужить.
            iptables_add_redirect(ips[i]);
            if (dc_refresh_split) iptables_quic_reject(ips[i]);
        }
        if (added)
            printf("[DISCORD] перепроверка %d: +%d адрес, в наборе %d\n",
                   round, added, dc_set_n);
    }
    return NULL;
}

void discord_module_inject(int fd) {
    (void)fd;
    if (!discord_initialized) { fprintf(stderr, "[DISCORD] not initialized\n"); return; }

    load_conf();
    printf("[DISCORD] inject: свои домены, редирект только своих адресов...\n");

    iptables_base();
    // Проба адресов обязана быть помеченной, иначе она измеряет собственный
    // рель. Ставим до первого collect_own_ips.
    site_probe_set_mark(DISCORD_SO_MARK);
    for (int i = 0; discord_dns_domains[i]; i++) iptables_add_dns_rule(discord_dns_domains[i]);

    char ips[32][64];
    int n = collect_own_ips(ips, 32);
    // Набор адресов накапливается между перезапусками. Свежие ответы — в
    // первую очередь, но и то, что видели раньше, остаётся в обороте: клиент
    // может прийти на любой из них.
    dc_set_load();
    for (int i = 0; i < n; i++) dc_set_add(ips[i]);
    if (n <= 0) {
        fprintf(stderr, "[DISCORD] не удалось разрешить ни один домен, выхожу\n");
        iptables_del_rules();
        ctx.mode = 0;
        return;
    }

    // Реестр: предупреждаем остальные модули, что эти адреса наши.
    const char *claim_list[33];
    for (int i = 0; i < n; i++) claim_list[i] = ips[i];
    claim_list[n] = NULL;
    claims_store("discord", claim_list, (size_t)n);

    int use_split = opt_split_ch;
    if (!use_split && opt_use_relay)
        printf("[DISCORD]   разрыв SNI выключен: рель пропускает байты как есть.\n"
               "               Обход идёт перебором кандидатов (connect_upstream),\n"
               "               поток остаётся целым — это и есть рабочий режим.\n");

    // QUIC отклоняем мгновенно, чтобы браузер сразу ушёл на TCP — но РОВНО на
    // тех адресах, куда мы дальше перенаправляем TCP. Отклонять QUIC там, куда
    // TCP не идёт, бессмысленно: для обхода это ничего не даёт, а HTTP/3 у
    // посторонних сайтов ломает. Поэтому набор один и тот же.
    // Цепочка QUIC нужна только когда мы actively уходим от DPI разрывом
    // и хотим мгновенный откат на TCP. Без разрыва HTTP/3 наши адреса
    // не трогаем: ломать QUIC у посторонних сайтов незачем.
    if (opt_use_relay) {
        // Цепочку пересоздаём ВСЕГДА, независимо от разрыва. Иначе осиротевшие
        // REJECT от прошлого запуска (например, когда разрыв был включён) пережили
        // бы смену режима и глушили бы QUIC там, где он больше не нужен.
        // Сама цепочка при этом пустая — правила добавляются ниже только когда
        // use_split действительно включён.
        iptables_quic_base();
    }

    int used = 0, skipped = 0;
    for (int i = 0; i < dc_set_n; i++) {
        const char *ip = dc_set[i];
        if (claims_taken_by_other("discord", ip)) {
            printf("[DISCORD]   %s занят другим модулем — не трогаю\n", ip);
            skipped++;
            continue;
        }
        if (opt_use_relay) {
            // Редирект ставим ВСЕГДА, когда включён рель, независимо от
            // разрыва SNI. Рель и без разрыва полезен: connect_upstream
            // перебирает кандидатов и, если закреплённый адрес не отвечает,
            // берёт другой из DoH. Замерено: 3 адреса Discord из 7 отдают
            // 0 байт, так что упереться в заблокированный реально.
            //
            // Без редиректа модуль сводится к подмене DNS и держится только
            // на том, что hosts.txt попал в неблокируемый адрес.
            iptables_add_redirect(ip);
            if (use_split) iptables_quic_reject(ip);
            used++;
        }
    }
    // Диапазон целиком НЕ перехватываем.
    //
    // Раньше здесь стояло REDIRECT на 162.159.128.0/18 — 16 384 адреса. Это
    // диапазон Cloudflare, а не Discord: в нём лежит, например, 162.159.140.229,
    // на который hosts.txt пинит x.com, api.twitter.com и всю twimg. Включённый
    // Discord уводил весь Twitter/X в свой рель, хотя модуль к нему отношения
    // не имеет. Проверить диапазон нечем: claims-реестр оперирует одиночными
    // адресами, а x.com в нём не значится — модуля у него нет.
    //
    // Смысла в /18 тоже нет: DNS-запросы Discord модуль заворачивает на
    // 127.0.0.1:53, а там ядро отдаёт адреса из hosts.txt, и все десять наших
    // доменов там покрыты. Клиент не может получить адрес вне проверенного
    // набора, и правило по каждому адресу выше его перекрывает.
    //
    // Если hosts.txt всё же протух и придёт адрес вне набора — этот адрес не
    // перехватится, и клиент пойдёт напрямую. Это заметно и безопасно, в
    // отличие от обратного. Аварийный возврат прежнего поведения:
    // relay_cidr=1 в webui/discord.conf.
    if (opt_use_relay && opt_relay_cidr) {
        for (int i = 0; discord_ranges[i]; i++) {
            iptables_add_redirect(discord_ranges[i]);
            iptables_quic_reject(discord_ranges[i]);
        }
        printf("[DISCORD]   диапазон %s перехвачен (relay_cidr=1)\n", discord_ranges[0]);
    }

    ctx.mode = 1;
    if (opt_use_relay) {
        if (start_relay(use_split) != 0) {
            fprintf(stderr, "[DISCORD] relay start failed: %s\n", strerror(errno));
            iptables_del_rules();
            claims_release("discord");
            ctx.mode = 0;
            return;
        }
        printf("[DISCORD]   relay 127.0.0.1:%d (pid %d), перехвачено адресов: %d, пропущено: %d\n",
               ctx.relay_port, ctx.relay_pid, used, skipped);
        printf("[DISCORD]   параметры: hs_не_резать=%d данные=%d размер=%d пауза_записей=%d "
               "порция=%d пауза_порции=%d частей_CH=%d\n",
               opt_no_split_hs, opt_split_data, opt_split_size, opt_split_delay_ms,
               opt_relay_chunk, opt_relay_pause_ms, opt_multi_parts);

        // ── Автоопределение по фактической замерке ────────────────────
        //
        // Путь клиента уже собран: REDIRECT стоит, рель слушает, перебор
        // кандидатов работает. Осталось измерить оба варианта разрыва и
        // оставить тот, что даёт больше данных.
        if (opt_auto_split) {
            char best_a[64] = {0}, best_b[64] = {0};
            long a_bytes = measure_best(dc_set, dc_set_n, best_a, sizeof best_a);
            printf("[DISCORD]   замер: разрыв %s -> %ld Б%s%s\n",
                   use_split ? "включён" : "выключен", a_bytes,
                   a_bytes < 0 ? " ПРИЧИНА: " : "", a_bytes < 0 ? g_measure_why : "");

            sni_relay_stop();
            usleep(400000);
            int flipped = !use_split;
            int ok2 = (start_relay(flipped) == 0);
            long b_bytes = ok2 ? measure_best(dc_set, dc_set_n, best_b, sizeof best_b) : -1;
            printf("[DISCORD]   замер: разрыв %s -> %ld Б%s%s\n",
                   flipped ? "включён" : "выключен", b_bytes,
                   b_bytes < 0 ? " ПРИЧИНА: " : "", b_bytes < 0 ? g_measure_why : "");

            // -1 хуже любого положительного: это «сеть закрыта».
            long av = a_bytes < 0 ? -1 : a_bytes;
            long bv = b_bytes < 0 ? -1 : b_bytes;

            if (bv > av) {
                use_split = flipped;
                printf("[DISCORD]   авто: оставляю разрыв %s (%ld Б против %ld Б)\n",
                       use_split ? "включён" : "выключен", bv, av);
            } else {
                // первый вариант лучше — возвращаем его
                sni_relay_stop();
                usleep(400000);
                if (start_relay(use_split) != 0)
                    fprintf(stderr, "[DISCORD] не удалось вернуть прежний режим реля\n");
                printf("[DISCORD]   авто: оставляю разрыв %s (%ld Б против %ld Б)\n",
                       use_split ? "включён" : "выключен", av, bv);
            }
            printf("[DISCORD]   эталон %d Б, окно замера %d с; оборванным считаем "
                   "всё, что ниже %d Б\n",
                   DISCORD_MEASURE_FULL, DISCORD_MEASURE_SEC, DISCORD_MEASURE_FLOOR);

            // Рельу говорим адрес-победитель. Без этого он идёт по первому
            // принявшему соединение адресу, а обрезающий соединение принимает
            // нормально — просто не отдаёт файл, и перебор кандидатов его не
            // отбрасывает. Победитель из замера как раз обходит эту дыру.
            const char *winner = use_split ? best_a : best_b;
            if (winner && winner[0]) {
                sni_relay_prefer(winner);
                printf("[DISCORD]   рель настроен на адрес с полным потоком: %s\n", winner);
            }
        } else {
            printf("[DISCORD]   разрыв SNI: %s (auto_split=0, как в конфиге)\n",
                   use_split ? "включён" : "выключен");
        }
    } else {
        printf("[DISCORD]   relay off: трафик идёт напрямую (адресов: %d, пропущено: %d)\n",
               n - skipped, skipped);
    }

    if (opt_use_relay && is_root()) {
        dc_refresh_stop = 0;
        dc_refresh_split = use_split;
        // Именно joinable, без detach: пока нить жива, сносить правила рано.
        if (pthread_create(&dc_refresh_th, NULL, dc_refresh_thread, NULL) == 0)
            dc_refresh_running = 1;
    }

    printf("[DISCORD] inject done (%s)\n",
           is_root() ? "iptables active" : "no root — iptables skipped");
}

void discord_module_remove(void) {
    if (!discord_initialized) return;
    dc_refresh_stop = 1;
    dc_wait_wake();
    // Ждём, пока нить допишет своё. Пока она в collect_own_ips или в iptables,
    // сносить правила нельзя: она поставит их снова уже после очистки.
    // Ожидание нити прерываемое (dc_wait_wake), поэтому join возвращается сразу,
    // а не ждёт конца паузы.
    if (dc_refresh_running) {
        pthread_join(dc_refresh_th, NULL);
        dc_refresh_running = 0;
    }
    sni_relay_stop();
    iptables_del_rules();
    claims_release("discord");
    ctx.relay_pid = -1;
    ctx.mode = 0;
    printf("[DISCORD] remove done\n");
}

const char *discord_get_status(void) {
    if (!discord_initialized) return "Off";
    if (!ctx.mode) return "Idle";
    if (!opt_use_relay) return "Active (DNS pinning, direct)";
    return sni_relay_running() ? "Active (SNI-split relay)" : "Active (relay down!)";
}
