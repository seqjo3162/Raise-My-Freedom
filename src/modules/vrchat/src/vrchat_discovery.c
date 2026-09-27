// Автоматика адресов VRChat.
//
// Зачем. Раньше адреса VRChat были зашиты в коде, и они протухали: старые
// 65.9.106.85 и 3.174.18.93 пришлось менять руками. Хуже — адреса приходят
// по несколько, CloudFront их крутит, и часть из них провайдер режет. Модуль
// знал по одному адресу на хост, поэтому три четверти аватаров и миров
// уходили мимо перехвата.
//
// Здесь две разные задачи, и их важно не путать:
//
//   СЕССИОННЫЕ хосты (api, pipeline, vrchat.com, gateway) — держим РОВНО ОДИН
//   адрес. Диапазон здесь не годится: исходящий адрес зависит от адреса
//   назначения, и если клиент уйдёт на соседний фронт-энд, у него сменится
//   видимый адрес, а VRChat мгновенно рвёт сессию — выкидывает из аккаунта
//   сразу после входа. Проверено: 104.18.26.36 и 104.18.6.156 дают разный
//   выход (195.46.162.142 против 195.178.4.137).
//
//   КОНТЕНТНЫЕ хосты (files, assets, docs) — держим ВСЕ рабочие адреса плюс
//   диапазон. Сессии там нет, ротация не страшна, а диапазон страхует от
//   появления новых адресов раньше, чем мы их узнали.
//
// Фоновая нить каждые DISCOVER_INTERVAL_SEC делает одно и то же: получает
// кандидатов через DoH, проверяет каждый обычным TCP-соединением и оставляет
// только те, что действительно соединяются. Проверять надо соединением, а не
// резолвом: адреса 143.204.238.54 и 108.157.229.98 исправно резолвятся через
// DoH и при этом не проходят.

#define _GNU_SOURCE
#include "vrchat_discovery.h"

#include "src/common/site_probe.h"
#include "src/dns/doh_resolve.h"

#include <pthread.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_CAND      8      // сколько адресов пробим на один домен
#define MAX_HOSTS     16
#define MAX_ADDRS     6      // сколько рабочих адресов держим на контентный хост
#define PROBE_MS      2000

static vrchat_discovery_cfg_t g_cfg;
static pthread_t g_thread;
static int g_running;

// Результат последнего обхода. Читается только из своей копии: правила
// iptables ставятся по ней, а обновляет её поток разведки.
static vrchat_discovery_report_t g_report;

// Монотонное время для замеров задержки: CLOCK_MONOTRONIC не прыгает при
// переводе часов, в отличие от time().
static long probe_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}


// Проверить один адрес. Просто «соединился или нет» недостаточно для выбора
// сессионного адреса: нужен тот, что отвечает быстро, иначе вход в игру
// будет подтормаживать.
// Проверяем не просто «соединился», а «соединился и отвечает на наше имя».
// Адрес может принимать соединение и при этом не обслуживать наш SNI —
// такое отсеиваем сразу, а не после рукопожатий в игре.
static int addr_alive(const char *ip, const char *host, int *ms_out) {
    long t0 = probe_now_ms();
    if (site_probe_sni(ip, host, PROBE_MS) != 1) return 0;
    if (ms_out) *ms_out = (int)(probe_now_ms() - t0);
    return 1;
}

// Общий адрес для всего сессионного набора.
//
// Считать по одному адресу на хост нельзя: исходящий адрес зависит от адреса
// назначения, поэтому два соседних фронт-энда дают клиенту два разных
// видимых адреса. Сессия VRChat привязана к адресу, и при смене он рвётся
// мгновенно — выкидывает из аккаунта сразу после входа. Проверено на
// 104.18.26.36 и 104.18.6.156: выходы 195.46.162.142 и 195.178.4.137.
//
// Поэтому: собираем кандидатов по всем сессионным именам, оставляем те,
// что отвечают на КАЖДОЕ имя из набора, и из них берём самый быстрый. Один
// адрес на весь набор — тогда видимый адрес не меняется.
// Гистерезис: если текущий адрес ещё отвечает, новый НЕ выбирается.
//
// Без этого общий адрес сессии прыгал каждые 15 минут: выбирался кандидат с
// наименьшей задержкой, а она у всех фронт-эндов одинаковая, так что выбор
// определялся шумом. Любой скачок = смена адреса назначения = смена видимого
// адреса у клиента = мгновенный разрыв сессии VRChat и выход из аккаунта.
// Ровно то, от чего вся конструкция и защищает. Смена допустима только когда
// текущий адрес перестал отвечать — тогда иначе некуда деваться.
static int pick_shared_session_addr(char *out, size_t out_sz) {
    // С запасом относительно кандидатов: snprintf обязан уметь показать
    // усечение, а не писать за пределы буфера.
    char shared[80] = {0};
    int shared_ms = 0;
    char current[64] = {0};
    for (int i = 0; i < MAX_HOSTS && g_report.generation; i++)
        if (g_report.hosts[i].session_critical && g_report.hosts[i].pinned[0]) {
            snprintf(current, sizeof(current), "%.63s", g_report.hosts[i].pinned);
            break;
        }

    for (int i = 0; i < MAX_HOSTS; i++) {
        const char *host = g_cfg.hosts[i].host;
        if (!host || !g_cfg.hosts[i].session_critical) continue;

        char cands[MAX_CAND][64];
        int n = 0;
        if (doh_resolve_a_multi(host, cands, MAX_CAND, &n) != 0 || n <= 0) continue;

        // Первый кандидат, ради которого и затевался обход: текущий адрес.
        // Если он отвечает на все имена набора — всё, берём его и выходим, не
        // давая выбрать что-то «быстрее» на шуме задержки.
        if (current[0]) {
            for (int k = 0; k < n; k++) {
                if (strcmp(current, cands[k]) != 0) continue;
                int ok = 1;
                for (int j = 0; j < MAX_HOSTS && ok; j++) {
                    const char *other = g_cfg.hosts[j].host;
                    if (!other || !g_cfg.hosts[j].session_critical) continue;
                    if (site_probe_sni(cands[k], other, PROBE_MS) != 1) ok = 0;
                }
                if (ok) {
                    snprintf(shared, sizeof(shared), "%.63s", cands[k]);
                    goto done;
                }
                break;
            }
        }

        for (int k = 0; k < n; k++) {
            // Уже проверен как общий — повторно не гоним.
            if (shared[0] && strcmp(shared, cands[k]) == 0) goto next_host;

            // Адрес годится, только если отвечает на ВСЕ имена набора.
            int ok = 1;
            for (int j = 0; j < MAX_HOSTS && ok; j++) {
                const char *other = g_cfg.hosts[j].host;
                if (!other || !g_cfg.hosts[j].session_critical) continue;
                if (site_probe_sni(cands[k], other, PROBE_MS) != 1) ok = 0;
            }
            if (!ok) continue;

            int ms = 0;
            addr_alive(cands[k], host, &ms);
            if (!shared[0] || ms < shared_ms) {
                snprintf(shared, sizeof(shared), "%.63s", cands[k]);
                shared_ms = ms;
            }
        next_host:;
        }
    }

done:
    if (!shared[0]) return -1;
    snprintf(out, out_sz, "%.63s", shared);
    return 0;
}

static void discover_once(vrchat_discovery_report_t *rep) {
    memset(rep, 0, sizeof(*rep));
    rep->generation++;

    // Сначала один общий адрес на весь сессионный набор, потом уже всё
    // остальное. Порядок важен: адрес выбирается до того, как назначается
    // хостам, иначе каждый снова получит свой собственный.
    char shared_session[64] = {0};
    int have_shared = g_running &&
                    pick_shared_session_addr(shared_session, sizeof(shared_session)) == 0;

    for (int i = 0; i < MAX_HOSTS; i++) {
        // Проверка остановки между хостами: полный проход тянется минутами,
        // и без этого остановка модуля ждала бы его на pthread_join.
        if (!g_running) break;
        vrchat_discovery_host_t *h = &g_cfg.hosts[i];
        if (!h->host) continue;
        vrchat_discovery_host_out_t *o = &rep->hosts[i];
        snprintf(o->host, sizeof(o->host), "%s", h->host);
        o->session_critical = h->session_critical;
        o->pinned[0] = '\0';
        o->count = 0;
        o->alive = 0;
        o->tried = 0;

        char cands[MAX_CAND][64];
        int n = 0;
        if (doh_resolve_a_multi(h->host, cands, MAX_CAND, &n) != 0 || n <= 0) {
            snprintf(o->note, sizeof(o->note), "DoH не дал кандидатов");
            // Запасной вариант: зашитый адрес всё ещё может быть живым.
            if (h->fallback_ip) snprintf(o->pinned, sizeof(o->pinned), "%s", h->fallback_ip);
            continue;
        }
        o->tried = n;

        char best[64] = {0};
        int best_ms = 0;
        int naddrs = 0;

        for (int k = 0; k < n; k++) {
            int ms = 0;
            if (!addr_alive(cands[k], h->host, &ms)) continue;
            o->alive++;
            if (naddrs < MAX_ADDRS) {
                snprintf(o->addrs[naddrs], sizeof(o->addrs[0]), "%s", cands[k]);
                naddrs++;
            }
            if (!best[0] || ms < best_ms) {
                snprintf(best, sizeof(best), "%s", cands[k]);
                best_ms = ms;
            }
        }

        o->count = naddrs;
        for (int k = 0; k < naddrs; k++) {
            o->addrs[k][sizeof(o->addrs[k]) - 1] = '\0';
        }

        if (h->session_critical) {
            // Общий адрес важнее всего, что нашлось для этого конкретного
            // имени: сессия привязана к видимому адресу, и соседний
            // фронт-энд её рвёт мгновенно.
            if (have_shared) {
                snprintf(o->pinned, sizeof(o->pinned), "%s", shared_session);
                snprintf(o->note, sizeof(o->note), "общий адрес сессии");
            } else if (h->fallback_ip) {
                snprintf(o->pinned, sizeof(o->pinned), "%s", h->fallback_ip);
                snprintf(o->note, sizeof(o->note), "общий не найден, держим зашитый");
            } else {
                snprintf(o->note, sizeof(o->note), "нет живого адреса");
            }
            o->best_ms = best_ms;
        } else {
            snprintf(o->note, sizeof(o->note), "%s",
                     naddrs > 0 ? "контент: адреса и диапазон" : "живых адресов нет");
        }
    }
}

static void *worker(void *arg) {
    (void)arg;
    while (g_running) {
        vrchat_discovery_report_t rep;
        discover_once(&rep);
        if (!g_running) break;
        // Публикуем отчёт целиком: читатель видит либо старый, либо новый,
        // но никогда половину обновлённого.
        g_report = rep;

        for (int t = 0; t < g_cfg.interval_sec && g_running; t++) sleep(1);
    }
    return NULL;
}

// Отчёт, заполненный зашитыми адресами, без всяких проверок.
//
// Нужен потому, что первый проход разведки занимает время (DoH плюс TCP-проба
// на каждого кандидата), и до его конца отчёт пуст. Тогда lookup_ip провалился
// бы в старый кэш пынов, где лежит адрес от ПРЕЖНЕЙ пообъектной проверки —
// и сессионные хосты снова разъезжаются по разным адресам, то есть ровно то
// самое, что чиним. С таким посевом все хосты сразу на одном адресе, а разведка
// потом его улучшает.
static void seed_report_with_fallbacks(void) {
    memset(&g_report, 0, sizeof(g_report));
    g_report.generation = 1;
    char *session_addr = NULL;
    for (int i = 0; i < MAX_HOSTS; i++) {
        vrchat_discovery_host_t *h = &g_cfg.hosts[i];
        if (!h->host) continue;
        if (h->session_critical && h->fallback_ip && !session_addr)
            session_addr = (char *)h->fallback_ip;
    }
    for (int i = 0; i < MAX_HOSTS; i++) {
        vrchat_discovery_host_t *h = &g_cfg.hosts[i];
        if (!h->host) continue;
        vrchat_discovery_host_out_t *o = &g_report.hosts[i];
        snprintf(o->host, sizeof(o->host), "%s", h->host);
        o->session_critical = h->session_critical;
        if (h->session_critical && session_addr) {
            snprintf(o->pinned, sizeof(o->pinned), "%s", session_addr);
            snprintf(o->note, sizeof(o->note), "зашитый общий адрес");
        } else if (h->fallback_ip) {
            snprintf(o->pinned, sizeof(o->pinned), "%s", h->fallback_ip);
            snprintf(o->note, sizeof(o->note), "зашитый адрес");
        }
    }
}

int vrchat_discovery_start(const vrchat_discovery_cfg_t *cfg) {
    if (!cfg || !cfg->hosts || g_running) return -1;
    if (getuid() != 0) return -1;          // DoH и TCP-проба требуют сети, но не root
    g_cfg = *cfg;
    g_cfg.interval_sec = cfg->interval_sec > 0 ? cfg->interval_sec : 900;
    g_running = 1;
    seed_report_with_fallbacks();
    if (pthread_create(&g_thread, NULL, worker, NULL) != 0) {
        g_running = 0;
        return -1;
    }
    return 0;
}

void vrchat_discovery_stop(void) {
    if (!g_running) return;
    g_running = 0;
    pthread_join(g_thread, NULL);
}

int vrchat_discovery_copy_report(vrchat_discovery_report_t *out) {
    if (!out || !g_running) return -1;
    *out = g_report;
    return 0;
}

long vrchat_discovery_generation(void) {
    return g_report.generation;
}
