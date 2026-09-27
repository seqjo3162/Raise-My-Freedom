// Запуск слоя десинхронизации отдельно от ядра.
//
// Нужен, чтобы проверить слой на живом трафике, не трогая ни ядро, ни веб.
//   sudo ./build/bin/rmf-desync --iface enp42s0 --cidr 162.159.128.0/18
//   --dport 443 --fake-sni www.google.com --ttl 3
//
// Печатает счётчики раз в секунду, чтобы было видно, работает ли подделка.

#define _GNU_SOURCE
#include "desync.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile int stop = 0;

static void on_sig(int s) { (void)s; stop = 1; }

static unsigned g_cli_target;
static unsigned g_cli_mask;

// Грубая проверка «входит ли этот /16 в заданную цель» — только для вывода.
static int in_target_ntop(const char *net16) {
    unsigned a, b, c, d;
    if (sscanf(net16, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0;
    unsigned net = (a << 24) | (b << 16) | (c << 8) | d;
    unsigned m = g_cli_mask;
    if (!m) return 0;
    return (net & m) == (g_cli_target & m);
}

static void usage(const char *me) {
    printf("слой десинхронизации rmf\n\n");
    printf("  %s --iface <интерфейс> --cidr <адрес[/маска]> [параметры]\n\n", me);
    printf("  --iface <имя>       сетевой интерфейс, обязательно\n");
    printf("  --cidr <адрес>      адрес или диапазон цели, обязательно\n");
    printf("  --dport <порт>      порт назначения, по умолчанию 443\n");
    printf("  --fake-sni <имя>    имя в подделке, по умолчанию vk.ru\n");
    printf("                      Российское намеренно: ТСПУ глубоко разбирает\n");
    printf("                      заблокированные ресурсы и почти не трогает\n");
    printf("                      российские площадки. Подделка с российским\n");
    printf("                      именем выглядит для DPI как рутина.\n");
    printf("  --ttl <1..255>      TTL подделки, по умолчанию 3.\n");
    printf("                      DPI стоит ближе, чем сервер: 2-4 обычно хватает,\n");
    printf("                      больше — подделка долетит до сервера и сломает TLS\n");
    printf("  --mode fake|tail    когда отправлять подделку, по умолчанию fake\n");
    printf("  --mark <hex>        SO_MARK для своих пакетов, чтобы не попасть\n");
    printf("                      в правила iptables модуля\n");
    printf("  --quiet             не печатать счётчики\n");
}

int main(int argc, char **argv) {
    desync_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.dport = 443;
    cfg.fake_ttl = 3;
    cfg.mode = DESYNC_MODE_FAKE;
    int quiet = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v = (i + 1 < argc) ? argv[i + 1] : NULL;
#define NEED(x) do { if (!v) { fprintf(stderr, "%s: нужно значение\n", x); return 1; } i++; } while (0)
        if (!strcmp(a, "--iface")) { NEED(a); cfg.iface = v; }
        else if (!strcmp(a, "--cidr")) { NEED(a); cfg.cidr = v; }
        else if (!strcmp(a, "--dport")) { NEED(a); cfg.dport = atoi(v); }
        else if (!strcmp(a, "--fake-sni")) { NEED(a); cfg.fake_sni = v; }
        else if (!strcmp(a, "--ttl")) { NEED(a); cfg.fake_ttl = (unsigned char)atoi(v); }
        else if (!strcmp(a, "--mark")) { NEED(a); cfg.so_mark = (unsigned int)strtoul(v, NULL, 0); }
        else if (!strcmp(a, "--quiet")) quiet = 1;
        else if (!strcmp(a, "--mode")) {
            NEED(a);
            if (!strcmp(v, "fake")) cfg.mode = DESYNC_MODE_FAKE;
            else if (!strcmp(v, "tail")) cfg.mode = DESYNC_MODE_FAKE_TAIL;
            else { fprintf(stderr, "--mode: нужно fake или tail\n"); return 1; }
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(argv[0]); return 0; }
        else { fprintf(stderr, "неизвестный аргумент: %s\n", a); usage(argv[0]); return 1; }
#undef NEED
    }

    if (!cfg.iface || !cfg.cidr) { usage(argv[0]); return 1; }
    {
        // Запоминаем цель в том же виде, что и слой, чтобы помечать подходящие
        // диапазоны в выводе.
        unsigned a, b, c, d, bits = 32;
        char tmp[64];
        snprintf(tmp, sizeof(tmp), "%s", cfg.cidr);
        char *sl = strchr(tmp, '/');
        if (sl) { *sl = '\0'; bits = (unsigned)atoi(sl + 1); }
        if (sscanf(tmp, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
            g_cli_target = (a << 24) | (b << 16) | (c << 8) | d;
            g_cli_mask = bits >= 32 ? 0xFFFFFFFFu : (0xFFFFFFFFu << (32 - bits));
        }
    }
    if (cfg.fake_ttl < 2 || cfg.fake_ttl > 64) {
        fprintf(stderr, "ttl должен быть 2..64: меньше — подделка не долетит до DPI, "
                        "больше — долетит до сервера\n");
        return 1;
    }

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    if (desync_start(&cfg) != 0) {
        fprintf(stderr, "не запустился: %s\n", desync_last_error());
        return 1;
    }
    printf("слой работает: %s, цель %s:%d, подделка «%s» ttl=%d, режим %s\n",
           cfg.iface, cfg.cidr, cfg.dport, cfg.fake_sni ? cfg.fake_sni : "-",
           cfg.fake_ttl, desync_mode_name(cfg.mode));
    printf("Ctrl+C — остановить\n");

    desync_stats_t prev;
    memset(&prev, 0, sizeof(prev));
    int quiet_ticks = 0;
    int top_ticks = 0;
    while (!stop) {
        sleep(1);
        if (quiet) continue;
        desync_stats_t now;
        desync_get_stats(&now);
        // Печатаем при изменении ЛЮБОГО счётчика, а не только подделок.
        // Иначе нельзя отличить «трафика не было» от «слой ничего не видит» —
        // а это разные поломки с разными причинами.
        int changed = now.seen != prev.seen || now.matched != prev.matched ||
                      now.hellos != prev.hellos || now.injected != prev.injected ||
                      now.no_fake != prev.no_fake || now.skipped != prev.skipped;
        if (changed) {
            printf("  просмотрено %llu  подошло %llu  ClientHello %llu  "
                   "подделок %llu  без SNI %llu  своих пропущено %llu\n",
                   (unsigned long long)now.seen, (unsigned long long)now.matched,
                   (unsigned long long)now.hellos, (unsigned long long)now.injected,
                   (unsigned long long)now.no_fake, (unsigned long long)now.skipped);
            fflush(stdout);
        }
        prev = now;
        if (changed) {
            quiet_ticks = 0;
        } else if (++quiet_ticks >= 5) {
            // Пусто несколько секунд подряд: значит ТРАФИКА НЕТ, и это не
            // поломка слоя. Пусть об этом сказано прямо, а не молчанием.
            quiet_ticks = 0;
            printf("  тишина 5 с: трафика к цели нет\n");
            fflush(stdout);
        }
        // Куда трафик идёт на самом деле — раз в 15 с независимо ни от чего.
        // Раньше этот список печатался только при полной тишине, а при
        // работающем трафике не появлялся никогда: то есть в самый нужный
        // момент диагностика молчала.
        if (++top_ticks >= 5) {
            top_ticks = 0;
            desync_proto_stats_t ps;
            desync_get_proto_stats(&ps);
            desync_top_peer_t top[DESYNC_TOP_N];
            int tn = 0;
            desync_top_peers(top, DESYNC_TOP_N, &tn);
            // Печатаем всегда, даже если адресов нет. Условие «показывать, только
            // если есть что показать» раньше прятало вывод именно в том случае,
            // когда разбираться и нужно: TCP не дошёл до разбора вовсе.
            printf("  направление: к нам %llu | к другому хосту %llu | ПОСЫЛАЕМЫЕ НАМИ %llu\n",
                   ps.to_us, ps.to_other, ps.outgoing);
            printf("  разбор пакетов: всего %llu | TCP %llu | UDP %llu | ICMP %llu |"
                   " прочее %llu | не IPv4 %llu | длинный заголовок %llu |"
                   " короткий %llu | не ClientHello %llu\n",
                   (unsigned long long)ps.tcp + ps.udp + ps.icmp + ps.other +
                       ps.not_v4 + ps.long_hdr + ps.short_pkt,
                   ps.tcp, ps.udp, ps.icmp, ps.other, ps.not_v4, ps.long_hdr, ps.short_pkt, ps.no_sni);
            if (tn > 0) {
                printf("  адреса, куда идёт TCP:\n");
                for (int k = 0; k < tn; k++)
                    printf("      %-16s %llu%s\n", top[k].net, top[k].pkts,
                           in_target_ntop(top[k].net) ? "   <-- входит в цель" : "");
            } else {
                printf("  адресов TCP: нет — ни один пакет TCP не дошёл до разбора\n");
            }
            fflush(stdout);
        }
    }
    desync_stop();
    printf("остановлен\n");
    return 0;
}
