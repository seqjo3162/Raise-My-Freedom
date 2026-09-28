#define _GNU_SOURCE
#include "src/common/site_bypass.h"
#include "src/netfilter/netfilter.h"
#include "src/dns/dns_resolve.h"
#include "src/dns/doh_resolve.h"
#include <pthread.h>
#include "src/common/plain_relay.h"
#include "src/common/site_probe.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_SITE_DOMAINS 64

// Таймауты пробы: компромисс между точностью и временем старта модуля.
#define PROBE_TIMEOUT_MS 1000
#define PROBE_MAX_IPS    3
#define DNS_READY_TIMEOUT_MS 2000

typedef struct {
    char domain[256];
    char ip[64];
} site_pin_t;

// Опережающее объявление: ответчик пользуется перечитыванием раньше, чем
// доходит до определения, потому что сам ответчик описан выше по файлу.
static void pins_reload(const char *path, size_t cap);

static site_pin_t site_pins[MAX_SITE_DOMAINS];
static int site_pin_count;
// Домены, у которых не нашлось ни одного достижимого адреса. Считается при
// подборе адресов, читается доктором при решении про рель.
static int g_blocked_domains;
static int (*site_ip_validator)(const char *ip);
static const char *site_fallback_ips[16];
static size_t site_fallback_count;

static int site_ip_allowed(const char *ip) {
    struct in_addr parsed;
    if (!ip || inet_pton(AF_INET, ip, &parsed) != 1) return 0;
    return !site_ip_validator || site_ip_validator(ip);
}

static int valid_token(const char *value) {
    if (!value || !*value || strlen(value) > 63) return 0;
    for (const unsigned char *p = (const unsigned char *)value; *p; p++)
        if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
            (*p >= '0' && *p <= '9') || *p == '_' || *p == '-')
            continue;
        else
            return 0;
    return 1;
}

static void normalize_domain(const char *input, char *out, size_t out_size) {
    if (!input || !out || out_size == 0) return;
    snprintf(out, out_size, "%s", input);
    size_t len = strlen(out);
    while (len > 0 && out[len - 1] == '.') out[--len] = '\0';
}

static int domain_matches(const char *query, const char *base) {
    if (!query || !base) return 0;
    size_t qlen = strlen(query);
    size_t blen = strlen(base);
    if (strcasecmp(query, base) == 0) return 1;
    return qlen > blen && query[qlen - blen - 1] == '.' &&
           strcasecmp(query + qlen - blen, base) == 0;
}

static const char *lookup_pin(const char *domain) {
    // Сначала точное совпадение, и только потом — по суффиксу.
    //
    // Порядок важен. Закрепление зоны нужно, чтобы один адрес покрывал её
    // поддомены: у VRChat это api, pipeline, www. Но если у поддомена есть
    // собственный адрес, суффиксный не должен его забивать. Иначе
    // cdn-lfs-eu-1.hf.co получал адрес hf.co, стоявший в списке раньше, и
    // отдавал чужой сертификат: у HF это разные сервисы за разными адресами.
    // Наблюдалось прямо: в файле стояло
    //   hf.co                    34.198.14.237
    //   cdn-lfs-eu-1.hf.co       13.249.8.45
    // а DNS для cdn-lfs-eu-1.hf.co отдавал 34.198.14.237 — первое совпадение
    // по суффиксу, собственный адрес проигнорирован.
    if (!domain) return NULL;
    for (int i = 0; i < site_pin_count; i++)
        if (strcasecmp(domain, site_pins[i].domain) == 0) return site_pins[i].ip;
    for (int i = 0; i < site_pin_count; i++)
        if (domain_matches(domain, site_pins[i].domain)) return site_pins[i].ip;
    return NULL;
}


// «Доктор»: проверяет закреплённые адреса и решает, нужен ли рель.
//   - адрес, до которого не доходит TCP, выбрасывается: рель не поможет,
//     он соединяется с того же адреса;
//   - если хотя бы на один запрос сервер не отвечает, домен режут по имени
//     и нужен рель с разрывом SNI; если отвечают все — рель не нужен.
static int site_doctor(const site_bypass_config_t *config) {
    int kept = 0, silent = 0, tested = 0;
    // Собираем оставшиеся записи отдельно и переписываем таблицу целиком.
    // Раньше выброшенные адреса сдвигались на месте со счётчиком, который
    // уменьшался на КАЖДЫЙ оставленный адрес, — таблица схлопывалась в ноль,
    // и модуль терял все закрепления: ответчик уходил в апстрим, а REDIRECT
    // не устанавливался вовсе.
    site_pin_t kept_pins[MAX_SITE_DOMAINS];

    for (int i = 0; i < site_pin_count; i++) {
        const char *ip = site_pins[i].ip;
        if (!site_probe_tcp(ip, 443, PROBE_TIMEOUT_MS)) {
            printf("[%s] %s -> %s: TCP не доходит, адрес выброшен\n",
                   config->name, site_pins[i].domain, ip);
            continue;
        }
        // Проверяем имя в сертификате. Без этого адрес, перешедший к другому
        // владельцу, выглядит живым: на TCP отвечает, TLS завершает, и все
        // прежние проверки считают его годным. Именно так в закреплениях
        // Hugging Face остался адрес Amazon'а вместо huggingface.co, и CDN
        // файлов отдавал мусор вместо моделей.
        //
        // Три исхода различаются сами по себе, допрашивать сервер не нужно:
        //   1 — сертификат выдан этому имени: адрес верный;
        //   0 — рукопожато��ь состоялось, а имя в сертификате чужое: адрес
        //       достался постороннему, выбрасываем;
        //  -1 — рукопожатие не состоялось: домен режут по имени, адрес верный,
        //       и он нужен как раз для рельа с разрывом SNI.
        int cert = site_probe_cert_ok(ip, site_pins[i].domain, PROBE_TIMEOUT_MS);
        if (cert == 0) {
            printf("[%s] %s -> %s: сертификат выдан другому имени, "
                   "адрес выброшен\n", config->name, site_pins[i].domain, ip);
            continue;
        }
        if (tested < PROBE_MAX_IPS) {
            if (cert == 1) {
                // Проверяем дважды: блокировка у провайдера меняется во времени,
                // и по одной удачной пробе доктор снимал рель у домена, который
                // через минуту снова оказывался зарезанным. Два подряд «вижу» —
                // верим; любая тишина — считаем домен режется по имени.
                int sni1 = site_probe_sni(ip, site_pins[i].domain, PROBE_TIMEOUT_MS);
                int sni2 = (sni1 == 1)
                    ? site_probe_sni(ip, site_pins[i].domain, PROBE_TIMEOUT_MS) : 0;
                if (sni1 != 1 || sni2 != 1) silent++;
            } else {
                // TCP до адреса доходит, а рукопожатие не завершается. Это
                // блокировка по имени: соединение открывают, TLS рвут. Именно так
                // ведёт себя huggingface.co — на 143.204.238.31 порт 443 отвечает
                // сразу, а сертификат не выдаётся никогда.
                //
                // Раньше такой пин сохранялся молча и в счётчик не попадал, а
                // доктор видел только здоровые домены и решал, что рель не
                // нужен. Из-за этого зарезанный домен оставался недоступным,
                // и подменять его было нечем: закрыты все четыре адреса.
                silent++;
            }
            tested++;
        }
        if (kept < MAX_SITE_DOMAINS) kept_pins[kept++] = site_pins[i];
    }

    if (kept == 0) {
        if (site_pin_count > 0) {
            // Были закрепления, и все оказались чужими. Считать сайт
            // недоступным нельзя: сбрасываем закрепления, чтобы домен
            // перерезолвился заново через DoH. Так чинится Hugging Face после
            // того, как закреплённый адрес перешёл к Amazon'у.
            printf("[%s] все %d закреплений не прошли проверку, "
                   "перерезолвиваю заново\n", config->name, site_pin_count);
            site_pin_count = 0;
            memset(site_pins, 0, sizeof(site_pins));
            silent = 0;
            tested = 0;
        } else {
            printf("[%s] ни один адрес не отвечает — сайт недоступен из этой "
                   "сети, рель не поможет\n", config->name);
            return -1;
        }
    }
    if (kept != site_pin_count)
        printf("[%s] закреплений осталось %d из %d\n", config->name, kept, site_pin_count);
    memcpy(site_pins, kept_pins, sizeof(kept_pins[0]) * (size_t)kept);
    site_pin_count = kept;

    if (tested == 0)
        printf("[%s] проверку SNI выполнить не удалось, беру решение по умолчанию\n",
               config->name);
    else
        printf("[%s] проверка SNI: проверено %d, молчат %d\n",
               config->name, tested, silent);

    if (config->use_relay >= 0) {
        if (config->use_relay) printf("[%s] рель включён принудительно\n", config->name);
        return config->use_relay;
    }
    // Домен без достижимого адреса — тоже блокировка, даже если site_probe_sni
    // ничего не показал: до адреса просто не доходит, и тишина тут не про SNI.
    if (silent > 0 || g_blocked_domains > 0) {
        if (g_blocked_domains > 0)
            printf("[%s] доменов без достижимого адреса: %d — рель обязателен\n",
                   config->name, g_blocked_domains);
        if (silent > 0)
            printf("[%s] домен режут по имени → нужен рель с разрывом SNI\n", config->name);
        return 1;
    }
    printf("[%s] домен дважды подряд ответил как есть → рель не нужен, "
           "трафик напрямую\n", config->name);
    return 0;
}

static void rules_add_dns(const site_bypass_state_t *state, const char *domain) {
    if (!state || !domain) return;
    if (nf_dns_redirect(state->chain, domain, state->dns_port) != 0)
        fprintf(stderr, "[%s] не удалось добавить перехват DNS для %s\n",
                state->chain, domain);
}

static void rules_add_redirect(const site_bypass_state_t *state, const char *ip) {
    if (!state || !ip) return;
    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) != 1) return;
    nf_tcp_redirect(state->chain, ip, 443, state->relay_port);
}

static void rules_install(site_bypass_state_t *state, const site_bypass_config_t *config,
                          int use_relay) {
    if (!state || !config) return;
    if (nf_chain_create(state->chain) != 0) return;
    // Сначала исключение собственного трафика, иначе пакеты обхода снова
    // попадут в цепочку и замкнутся в петлю.
    nf_exempt_own_traffic(state->chain);
    nf_hook_output(state->chain, 1);
    for (size_t i = 0; i < config->domain_count; i++) {
        if (!config->domains || !config->domains[i]) continue;
        char domain[256];
        normalize_domain(config->domains[i], domain, sizeof(domain));
        if (domain[0]) rules_add_dns(state, domain);
    }
    // Решение принимает доктор, и оно уже учтено в use_relay. Раньше здесь
    // проверялось config->use_relay, где для авто-режима стояло -1, и REDIRECT
    // не ставился вовсе: рель работал, но в него никто не попадал.
    if (use_relay)
        for (int i = 0; i < site_pin_count; i++)
            rules_add_redirect(state, site_pins[i].ip);
    state->rules_installed = true;
}

static void rules_remove(site_bypass_state_t *state) {
    if (!state || !state->chain[0]) return;
    nf_chain_destroy(state->chain);
    state->rules_installed = false;
}

static int extract_qname(const unsigned char *pkt, int len, char *out, int out_size) {
    if (!pkt || len < 13 || !out || out_size < 2) return -1;
    int pos = 12, used = 0;
    while (pos < len && pkt[pos] != 0) {
        int label = pkt[pos++];
        if ((label & 0xc0) == 0xc0 || label == 0 || label > 63) return -1;
        if (pos + label > len || used + label + 2 >= out_size) return -1;
        if (used > 0) out[used++] = '.';
        memcpy(out + used, pkt + pos, (size_t)label);
        used += label;
        pos += label;
    }
    if (pos >= len || pkt[pos] != 0) return -1;
    out[used] = '\0';
    return used;
}

static int skip_qname(const unsigned char *pkt, int len) {
    if (!pkt || len < 13) return -1;
    int pos = 12;
    while (pos < len && pkt[pos] != 0) {
        int label = pkt[pos++];
        if ((label & 0xc0) == 0xc0) return pos + 1 < len ? pos + 1 : -1;
        if (label == 0 || label > 63 || pos + label > len) return -1;
        pos += label;
    }
    return pos < len ? pos + 1 : -1;
}

static int build_a_response(const unsigned char *query, int query_len,
                            unsigned char *response, int response_size,
                            const char *ip) {
    int qname_end = skip_qname(query, query_len);
    if (qname_end < 0 || qname_end + 4 > query_len || qname_end + 4 + 24 > response_size)
        return -1;
    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) != 1) return -1;
    memcpy(response, query, (size_t)(qname_end + 4));
    response[2] = 0x81;
    response[3] = 0x80;
    response[4] = 0;
    response[5] = 1;
    response[6] = 0;
    response[7] = 1;
    response[8] = 0;
    response[9] = 0;
    response[10] = 0;
    response[11] = 0;
    int out = qname_end + 4;
    response[out++] = 0xc0;
    response[out++] = 0x0c;
    response[out++] = 0;
    response[out++] = 1;
    response[out++] = 0;
    response[out++] = 1;
    response[out++] = 0;
    response[out++] = 0;
    response[out++] = 0;
    response[out++] = 120;
    response[out++] = 0;
    response[out++] = 4;
    memcpy(response + out, &addr, 4);
    return out + 4;
}

static int build_empty_response(const unsigned char *query, int query_len,
                                unsigned char *response, int response_size) {
    int qname_end = skip_qname(query, query_len);
    if (qname_end < 0 || qname_end + 4 > query_len || qname_end + 4 > response_size)
        return -1;
    memcpy(response, query, (size_t)(qname_end + 4));
    response[2] = 0x81;
    response[3] = 0x80;
    response[4] = 0;
    response[5] = 1;
    response[6] = 0;
    response[7] = 0;
    response[8] = 0;
    response[9] = 0;
    response[10] = 0;
    response[11] = 0;
    return qname_end + 4;
}

static int forward_query(const unsigned char *query, int query_len,
                         unsigned char *response, int response_size,
                         const site_bypass_state_t *state) {
    const char *servers[2] = {state->primary, state->fallback};
    for (int i = 0; i < 2; i++) {
        if (!servers[i] || !servers[i][0]) continue;
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) continue;
        nf_mark_socket_as(fd, (unsigned int)state->mark);
        struct sockaddr_in destination = {0};
        destination.sin_family = AF_INET;
        destination.sin_port = htons(53);
        if (inet_pton(AF_INET, servers[i], &destination.sin_addr) != 1 ||
            sendto(fd, query, (size_t)query_len, 0,
                   (struct sockaddr *)&destination, sizeof(destination)) != query_len) {
            close(fd);
            continue;
        }
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int result = poll(&pfd, 1, 2000);
        int length = -1;
        if (result > 0 && (pfd.revents & POLLIN)) {
            ssize_t received = recvfrom(fd, response, (size_t)response_size, 0, NULL, NULL);
            if (received >= 12 && response[0] == query[0] && response[1] == query[1])
                length = (int)received;
        }
        close(fd);
        if (length > 0) return length;
    }
    return -1;
}

static void dns_child(site_bypass_state_t *state, int ready_fd) {
    prctl(PR_SET_PDEATHSIG, SIGTERM);
    if (getppid() == 1) _exit(0);
    setsid();
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, SIG_DFL);
    signal(SIGCHLD, SIG_DFL);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) _exit(1);
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons((uint16_t)state->dns_port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) != 0) _exit(2);
    if (ready_fd >= 0) {
        char ok = 1;
        if (write(ready_fd, &ok, 1) != 1) _exit(3);
        close(ready_fd);
    }

    unsigned char query[4096], response[4096];
    while (1) {
        // Файл закреплений перечитываем, когда он изменился.
        //
        // Ответчик — отдельный процесс, форкнутый от модуля, и раньше он
        // держал копию закреплений в памяти на всё время жизни. Фоновая
        // перепроверка в родителе дописывает в файл удачные адреса, и без
        // этого они были видны только после перезапуска модуля.
        if (state->pin_path[0]) {
            struct stat pst;
            if (stat(state->pin_path, &pst) == 0 && pst.st_mtime != state->pin_mtime) {
                state->pin_mtime = pst.st_mtime;
                pins_reload(state->pin_path, sizeof(state->pin_path));
            }
        }
        struct sockaddr_in client;
        socklen_t client_len = sizeof(client);
        ssize_t received = recvfrom(fd, query, sizeof(query), 0,
                                    (struct sockaddr *)&client, &client_len);
        if (received < 13) continue;
        char domain[256];
        if (extract_qname(query, (int)received, domain, sizeof(domain)) < 0) continue;
        int qname_end = skip_qname(query, (int)received);
        if (qname_end < 0 || qname_end + 1 >= received) continue;
        int qtype = (query[qname_end] << 8) | query[qname_end + 1];
        const char *ip = lookup_pin(domain);
        int response_len = -1;
        if (ip && qtype == 1) {
            response_len = build_a_response(query, (int)received, response,
                                            sizeof(response), ip);
        } else if (ip) {
            response_len = build_empty_response(query, (int)received, response,
                                                sizeof(response));
        } else {
            response_len = forward_query(query, (int)received, response,
                                         sizeof(response), state);
        }
        if (response_len > 0)
            sendto(fd, response, (size_t)response_len, 0,
                   (struct sockaddr *)&client, client_len);
    }
}

static int dns_start(site_bypass_state_t *state) {
    int ready[2];
    if (pipe2(ready, O_CLOEXEC) < 0) return -1;
    pid_t pid = fork();
    if (pid < 0) {
        close(ready[0]);
        close(ready[1]);
        return -1;
    }
    if (pid == 0) {
        close(ready[0]);
        dns_child(state, ready[1]);
        _exit(0);
    }
    close(ready[1]);
    char ok = 0;
    struct pollfd pfd = { .fd = ready[0], .events = POLLIN };
    int result = poll(&pfd, 1, DNS_READY_TIMEOUT_MS);
    ssize_t got = result > 0 ? read(ready[0], &ok, 1) : 0;
    close(ready[0]);
    if (got != 1 || ok != 1) {
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
        return -1;
    }
    state->dns_pid = pid;
    return 0;
}

static void dns_stop(site_bypass_state_t *state) {
    if (!state || state->dns_pid <= 0) return;
    pid_t pid = state->dns_pid;
    state->dns_pid = 0;
    kill(pid, SIGTERM);
    for (int i = 0; i < 20; i++) {
        if (waitpid(pid, NULL, WNOHANG) == pid) return;
        usleep(50000);
    }
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
}


// ── Фоновая перепроверка закреплений ───────────────────────────────────────
//
// Зачем. Сегодня модуль узнаёт об изменившейся сети только при перезапуске:
// адрес, который провайдер зарезал, остаётся в ответе DNS, и сайт лежит до
// того, как модуль перезапустят руками. Наблюдалось на github.com — он уехал
// на зарезанный адрес, и сайт не открывался до перезапуска.
//
// Что делает поток. Раз в REFITSH_INTERVAL секунд проверяет закреплённые адреса
// помеченной пробой. Ответил — ничего не трогаем. Не ответил — ищем новый
// адрес и записываем его в файл. Ответчик перечитывает файл по mtime, и новый
// адрес доезжает до клиента без перезапуска.
//
// Поток создаётся строго после dns_start. Ответчик — форкнутый процесс, и
// поток в нём оказаться не должен: иначе он продолжит работать в копии, где
// нет ни сокета ответчика, ни изменений.
//
// Поток не трогает site_pins и не ставит правила сам: он пишет только файл.
// Всё остальное подхватывает ответчик по mtime. Так не появляется гонка между
// потоком и основным потоком модуля за общий список закреплений.
#define REFRESH_INTERVAL 120

typedef struct {
    site_bypass_state_t *state;
    char module[64];
    const char *const *domains;
    size_t domain_count;
    int relay_on;
} refresh_ctx_t;


// Заменить строку "домен адрес" в файле закреплений или дописать её.
//
// Пишем через временный файл и rename, потому что ответчик читает этот файл
// на лету и при обычной перезаписи увидел бы обрезанный на середине.
static void pin_file_replace(const char *path, const char *line) {
    if (!path || !path[0] || !line || !line[0]) return;
    char tmp[560];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    char cur[256], ip[64];
    char keep[64][400];
    int nkeep = 0;
    // Домен из новой строки. Раньше тут сравнивался домен со всей строкой
    // целиком, сравнение никогда не сходилось, и старая запись оставалась в
    // файле: в итоге на один домон приходилось два адреса, и ответчик отдавал
    // заведомо мёртвый первый.
    char new_dom[256];
    if (sscanf(line, "%255s", new_dom) != 1) return;
    FILE *f = fopen(path, "r");
    if (f) {
        char buf[400];
        while (nkeep < 64 && fgets(buf, sizeof(buf), f)) {
            if (sscanf(buf, "%255s %63s", cur, ip) != 2) continue;
            if (strcasecmp(cur, new_dom) == 0) continue;
            snprintf(keep[nkeep], sizeof(keep[0]), "%s %s\n", cur, ip);
            nkeep++;
        }
        fclose(f);
    }
    FILE *o = fopen(tmp, "w");
    if (!o) return;
    for (int i = 0; i < nkeep; i++) fputs(keep[i], o);
    fputs(line, o);
    fclose(o);
    rename(tmp, path);
}

// Контекст фоновой перепроверки. Живёт всё время работы модуля, поток его
// не освобождает: состояние остановки видно по state->stopping.
static refresh_ctx_t g_refresh;
static pthread_t g_refresh_th;
static bool g_refresh_running;

// Запуск фоновой перепроверки. Вызывается только после dns_start: ответчик
// форкнут, и поток не должен попасть в его копию.
static void *pin_refresh_thread(void *arg);
static void start_pin_refresh(site_bypass_state_t *state,
                              const site_bypass_config_t *config) {
    if (g_refresh_running) return;
    if (!config || !config->domains || !config->domain_count) return;
    if (!config->name || !config->name[0]) return;
    g_refresh.state = state;
    g_refresh.domains = config->domains;
    g_refresh.domain_count = config->domain_count;
    snprintf(g_refresh.module, sizeof(g_refresh.module), "%s", config->name);
    g_refresh.relay_on = state->relay_on;
    if (pthread_create(&g_refresh_th, NULL, pin_refresh_thread, &g_refresh) == 0)
        g_refresh_running = true;
}

static void *pin_refresh_thread(void *arg) {
    refresh_ctx_t *ctx = arg;
    site_bypass_state_t *state = ctx->state;

    while (state->active && !state->stopping) {
        for (size_t i = 0; i < ctx->domain_count; i++) {
            if (!state->active || state->stopping) break;
            if (!ctx->domains[i]) continue;
            char domain[256];
            normalize_domain(ctx->domains[i], domain, sizeof(domain));
            if (!domain[0]) continue;

            char cur[64] = {0};
            for (int k = 0; k < site_pin_count; k++)
                if (strcasecmp(site_pins[k].domain, domain) == 0) {
                    snprintf(cur, sizeof(cur), "%.*s", 63, site_pins[k].ip);
                    break;
                }
            // Домен не закреплён — подбираем, но не каждый круг, иначе модуль
            // без правил перезапустит подбор с нуля на каждом проходе.
            if (!cur[0]) continue;
            if (site_probe_tcp(cur, 443, PROBE_TIMEOUT_MS) &&
                site_probe_cert_ok(cur, domain, PROBE_TIMEOUT_MS) != 0)
                continue;   // адрес жив, ничего не делаем

            char cands[8][64];
            int nc = 0;
            doh_resolve_a_multi(domain, cands, 8, &nc);
            for (int c = 0; c < nc; c++) {
                if (strcmp(cands[c], cur) == 0) continue;
                if (!site_probe_tcp(cands[c], 443, PROBE_TIMEOUT_MS)) continue;
                if (site_probe_cert_ok(cands[c], domain, PROBE_TIMEOUT_MS) == 0) continue;
                char line[340];
                snprintf(line, sizeof(line), "%.*s %.*s\n", 200, domain, 63, cands[c]);
                pin_file_replace(state->pin_path, line);
                printf("[%s]   фон: %s переехал с %s на %s (старый не отвечает)\n",
                       ctx->module, domain, cur, cands[c]);
                break;
            }
        }
        for (int s = 0; s < REFRESH_INTERVAL && state->active && !state->stopping; s++)
            sleep(1);
    }
    return NULL;
}

// Стабильные закрепления.
//
// CDN отдают новый адрес на каждый запрос, поэтому после каждого перезапуска
// модуль выбирал другой, и клиент видел постоянно меняющийся набор серверов —
// для VRChat это выглядит как подмена трафика. Поэтому прошлый выбор
// запоминаем и берём снова, пока адрес отвечает; меняем только когда старый
// перестал работать.
static site_pin_t prev_pins[MAX_SITE_DOMAINS];
static int prev_pin_count;

static void pins_path(char *out, size_t cap, const char *name) {
    snprintf(out, cap, "/run/rmf/pins/%s.pin", name);
}

// Перечитывание файла закреплений прямо в рабочий набор.
//
// Ответчик работает в форкнутом процессе и держит свою копию site_pins с
// момента запуска. Фоновая перепроверка в родителе дописывает в файл удачные
// адреса, поэтому без перечитывания они доезжали бы только после перезапуска
// модуля — а весь смысл фоновой работы в том, чтобы не перезапускать.
//
// Файл читается целиком и применяется только если он не пуст: иначе временно
// обрезанный при записи файл оставил бы ответчик вовсе без закреплений.
static void pins_reload(const char *path, size_t cap) {
    (void)cap;
    if (!path || !path[0]) return;
    site_pin_t fresh[MAX_SITE_DOMAINS];
    int n = 0;
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[400];
    while (n < MAX_SITE_DOMAINS && fgets(line, sizeof(line), f)) {
        char dom[256], ip[64];
        if (sscanf(line, "%255s %63s", dom, ip) != 2) continue;
        snprintf(fresh[n].domain, sizeof(fresh[n].domain), "%s", dom);
        snprintf(fresh[n].ip, sizeof(fresh[n].ip), "%s", ip);
        n++;
    }
    fclose(f);
    if (n == 0) return;              // пустой или обрезанный файл — не применяем
    memcpy(site_pins, fresh, sizeof(fresh[0]) * (size_t)n);
    site_pin_count = n;
}

static int pins_load(const char *name) {
    prev_pin_count = 0;
    if (!name || !name[0]) return 0;
    char path[512];
    pins_path(path, sizeof(path), name);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[400];
    while (prev_pin_count < MAX_SITE_DOMAINS && fgets(line, sizeof(line), f)) {
        char dom[256], ip[64];
        if (sscanf(line, "%255s %63s", dom, ip) != 2) continue;
        snprintf(prev_pins[prev_pin_count].domain,
                 sizeof(prev_pins[prev_pin_count].domain), "%s", dom);
        snprintf(prev_pins[prev_pin_count].ip,
                 sizeof(prev_pins[prev_pin_count].ip), "%s", ip);
        prev_pin_count++;
    }
    fclose(f);
    return prev_pin_count;
}

static const char *prev_pin_for(const char *domain) {
    for (int i = 0; i < prev_pin_count; i++)
        if (strcasecmp(prev_pins[i].domain, domain) == 0) return prev_pins[i].ip;
    return NULL;
}

static void pins_save(const char *name) {
    if (!name || !name[0]) return;
    mkdir("/run/rmf", 0755);
    mkdir("/run/rmf/pins", 0755);
    char path[512], tmp[560];
    pins_path(path, sizeof(path), name);
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f) return;
    // Писать пустой файл тоже нужно. Раньше здесь стоял ранний выход при
    // site_pin_count == 0, и когда доктор отбрасывал все закрепления, старый
    // файл оставался на диске как есть. Следующий запуск грузил его обратно и
    // получал те же неверные адреса — то есть вылечить адрес, ушедший к
    // другому владельцу, было невозможно. Именно так застрял Hugging Face.
    for (int i = 0; i < site_pin_count; i++)
        fprintf(f, "%s %s\n", site_pins[i].domain, site_pins[i].ip);
    fclose(f);
    rename(tmp, path);
}

int site_bypass_start(site_bypass_state_t *state, const site_bypass_config_t *config) {
    if (!state || !config || !valid_token(config->chain) || !config->domains ||
        config->domain_count == 0 || config->domain_count > MAX_SITE_DOMAINS ||
        config->dns_port <= 1024 || config->dns_port > 65535 ||
        config->relay_port <= 1024 || config->relay_port > 65535 ||
        config->dns_port == config->relay_port) return -1;
    if (state->active || state->dns_pid > 0) site_bypass_stop(state);
    memset(state, 0, sizeof(*state));
    snprintf(state->primary, sizeof(state->primary), "%s",
             config->primary_dns && *config->primary_dns ? config->primary_dns : "1.1.1.1");
    snprintf(state->fallback, sizeof(state->fallback), "%s",
             config->fallback_dns && *config->fallback_dns ? config->fallback_dns : "8.8.8.8");
    snprintf(state->chain, sizeof(state->chain), "%s", config->chain);
    state->dns_port = config->dns_port;
    state->relay_port = config->relay_port;
    state->mark = config->mark;
    // Помечаем сокеты проверок, чтобы они не попадали в собственные
    // REDIRECT-правила модуля. Без этого доктор измеряет собственный рель, а
    // не провайдера: закреплённый адрес проверяется через рель, тот отвечает
    // с задержкой на разрыве SNI, проба упирается в таймаут и выглядит как
    // «домен недоступен». Раньше метку ставили только discord и vrchat, а все
    // остальные site-модули мерили сами себя.
    site_probe_set_mark((unsigned int)state->mark);
    state->dns_fd = -1;
    if (config->name && config->name[0]) {
        pins_path(state->pin_path, sizeof(state->pin_path), config->name);
        struct stat pst;
        state->pin_mtime = (stat(state->pin_path, &pst) == 0) ? pst.st_mtime : 0;
    }
    pins_load(config->name);
    site_pin_count = 0;
    site_ip_validator = config->validate_ip;
    site_fallback_count = config->fallback_count < 16 ? config->fallback_count : 16;
    for (size_t i = 0; i < site_fallback_count; i++)
        site_fallback_ips[i] = config->fallback_ips ? config->fallback_ips[i] : NULL;

    g_blocked_domains = 0;
    for (size_t i = 0; i < config->domain_count && site_pin_count < MAX_SITE_DOMAINS; i++) {
        if (!config->domains[i]) continue;
        char domain[256], ip[64] = {0};
        normalize_domain(config->domains[i], domain, sizeof(domain));
        if (!domain[0]) continue;

        // Точечная прибивка из таблицы модуля: важнее всего прошлого адреса и
        // разрешения, потому что хосты одного домена могут требовать разных
        // адресов, а разрешение для них нестабильно.
        for (size_t k = 0; config->preset_pins && k < config->preset_count; k++) {
            if (strcasecmp(config->preset_pins[k].domain, domain) != 0) continue;
            const char *pip = config->preset_pins[k].ip;
            if (!site_ip_allowed(pip)) {
                printf("[%s] %s: прибивка %s отклонена проверкой адресов\n",
                       config->name, domain, pip);
                break;
            }
            snprintf(ip, sizeof(ip), "%s", pip);
            goto pin_ready;
        }

        // Прошлый адрес этого домена оставляем только если он и дальше отдаёт
        // сертификат именно этого имени: так набор серверов не прыгает при
        // каждом перезапуске модуля.
        //
        // Проверки одного TCP мало. Адрес CloudFront принимает соединение и
        // при этом обрывает TLS, то есть на проверку «доходит ли» отвечает,
        // а сертификат не отдаёт. Такое закрепление держалось вечно: путь
        // ниже, с перебором кандидатов и сверкой сертификата, до него просто
        // не доходил. Наблюдалось на transfer.xethub.hf.co: закреплён был
        // 143.204.238.109, который отвечает на TCP и молчит на TLS, тогда как
        // 143.204.238.52 из того же ответа DoH отдаёт верный сертификат.
        //
        // Строгое условие (только верный сертификат) стоит нескольких лишних
        // проб при старте для заблокированных доменов, но даёт верный выбор:
        // для них перебор кандидатов ниже всё равно заканчивается запасным
        // закрытым адресом, то есть результат тот же.
        const char *prev = prev_pin_for(domain);
        if (prev && site_ip_allowed(prev) &&
            site_probe_tcp(prev, 443, PROBE_TIMEOUT_MS) &&
            site_probe_cert_ok(prev, domain, PROBE_TIMEOUT_MS) == 1) {
            snprintf(ip, sizeof(ip), "%.*s", (int)sizeof(ip) - 1, prev);
            goto pin_ready;
        }

        // Кандидаты: сначала все A-записи от DoH, затем обязательно обычный
        // DNS, затем запасные адреса модуля. Берём первый, до которого доходит
        // TCP: раньше брался первый попавшийся, и если он недостижим — терялся
        // весь домен.
        //
        // Обычный DNS добавляется всегда, а не только когда DoH не ответил.
        // Разные резолверы дают для одного домена разные адреса, и у них может
        // быть разная доступность. Для github.com Cloudflare отдаёт
        // 4.225.11.194, а 8.8.8.8 и 9.9.9.9 — 140.82.121.3, который у
        // провайдера режется. Раньше при сбое DoH домен целиком уезжал на
        // этот заблокированный адрес и висел, хотя рабочий рядом был. Со
        // сбором обоих источников проба просто находит живой.
        char cands[8][64];
        int ncand = 0;
        doh_resolve_a_multi(domain, cands, 8, &ncand);
        if (ncand < 8) {
            char one[64];
            if (dns_resolve_udp(state->primary, domain, one, sizeof(one)) == 0) {
                int dup = 0;
                for (int i = 0; i < ncand; i++)
                    if (strcmp(cands[i], one) == 0) { dup = 1; break; }
                if (!dup) snprintf(cands[ncand++], 64, "%.*s", 63, one);
            }
        }
        if (ncand < 8) {
            char one[64];
            if (dns_resolve_udp(state->fallback, domain, one, sizeof(one)) == 0) {
                int dup = 0;
                for (int i = 0; i < ncand; i++)
                    if (strcmp(cands[i], one) == 0) { dup = 1; break; }
                if (!dup) snprintf(cands[ncand++], 64, "%.*s", 63, one);
            }
        }
        for (size_t j = 0; j < site_fallback_count && ncand < 8; j++)
            if (site_fallback_ips[j])
                snprintf(cands[ncand++], 64, "%.*s", 63, site_fallback_ips[j]);

        ip[0] = '\0';
        char blocked[64] = {0};
        int tried = 0;
        for (int c = 0; c < ncand; c++) {
            if (!site_ip_allowed(cands[c])) continue;
            tried++;
            if (site_probe_tcp(cands[c], 443, PROBE_TIMEOUT_MS)) {
                // TCP отвечает — этого мало. CloudFront обслуживает на одном
                // адресе сразу много доменов и по SNI отдаёт сертификат того
                // домена, который попался первым. Поэтому адрес, годный для
                // hf.co, проходил проверку TCP и тут же закреплялся за
                // huggingface.co, cdn-lfs и cdn-oauth, а те получали чужой
                // сертификат и не грузились. Сверяем имя: 0 — сертификат
                // чужой, такой адрес для этого домена не годится; -1 — рукопо-
                // жатие не состоялось, домен режут по имени, адрес оставляем
                // (для него и нужен рель).
                int cert = site_probe_cert_ok(cands[c], domain, PROBE_TIMEOUT_MS);
                if (cert == 0) {
                    if (config->name)
                        printf("[%s] %s: %s отдаёт чужой сертификат, пропускаю\n",
                               config->name, domain, cands[c]);
                    continue;
                }
                if (cert == 1) {
                    // Ограниченная копия: cands[c] — элемент массива, и без
                    // предела gcc считает источник потенциально выходщим.
                    snprintf(ip, sizeof(ip), "%.*s", (int)sizeof(ip) - 1, cands[c]);
                    break;
                }
                // Домен режут по имени. Сохраняем как запасной, но продолжаем
                // искать лучший: у одного и того же CloudFront часть адресов
                // закрыта, а часть отвечает. Для transfer.xethub.hf.co из
                // четырёх адресов два не отвечают и два отдают нужный
                // сертификат, поэтому первый закрытый нельзя принимать сразу.
                if (!blocked[0])
                    snprintf(blocked, sizeof(blocked), "%.*s",
                             (int)sizeof(blocked) - 1, cands[c]);
                continue;
            }
            if (config->name)
                printf("[%s] %s: адрес %s недостижим, пробуем следующий\n",
                       config->name, domain, cands[c]);
        }
        // Ни одного адреса с верным сертификатом не нашлось — берём закрытый,
        // для него и нужен рель с разрывом SNI.
        if (!ip[0] && blocked[0])
            snprintf(ip, sizeof(ip), "%.*s", (int)sizeof(ip) - 1, blocked);
        if (!site_ip_allowed(ip)) {
            // Одно сообщение на домен с конкретной причиной: раньше их было
            // два подряд и оба неверные, из-за чего вывод путался.
            if (ncand == 0)
                printf("[%s] %s: не разрешился (нет A-записи через DoH и DNS)\n",
                       config->name, domain);
            else if (tried == 0)
                printf("[%s] %s: ни один адрес не прошёл проверку\n",
                       config->name, domain);
            else
                printf("[%s] %s: все адреса недостижимы с этой сети\n",
                       config->name, domain);
            // Домен без единого достижимого адреса — самый сильный сигнал,
            // что провайдер режет его по имени, и рель здесь обязателен.
            //
            // Раньше такой домен просто пропускался: адреса выбрасывались, а
            // счётчик блокировок при этом не пополнялся. Доктор же принимает
            // решение на модуль, а не на домен, и у HF одновременно есть и
            // вполне рабочие домены (hf.co, cdn-lfs), и один зарезанный
            // целиком (huggingface.co). Рабочие давали «ответил как есть», и
            // рель не включался — а именно из-за него huggingface.co и не
            // открывался: закрыты все четыре адреса, и подменять их нечем.
            //
            // Теперь отсутствие адреса засчитывается как блокировка, и рель
            // поднимается на весь модуль: он ничего не портит работающим
            // доменам, а зарезанному становится единственным путём.
            if (g_blocked_domains < MAX_SITE_DOMAINS) g_blocked_domains++;
        }
        if (!site_ip_allowed(ip)) continue;   // причина уже напечатана выше
pin_ready:
        snprintf(site_pins[site_pin_count].domain,
                 sizeof(site_pins[site_pin_count].domain), "%s", domain);
        snprintf(site_pins[site_pin_count].ip,
                 sizeof(site_pins[site_pin_count].ip), "%s", ip);
        site_pin_count++;
    }
    pins_save(config->name);
    if (site_pin_count == 0) {
        printf("[%s] ни один домен не дал пригодного адреса — обход не запущен\n",
               config->name);
        return -1;
    }
    if (dns_start(state) != 0) return -1;

    int use_relay = site_doctor(config);
    if (use_relay < 0) { site_bypass_stop(state); return -1; }

    rules_install(state, config, use_relay);
    if (!use_relay) {
        state->relay_on = false;
        state->active = true;
        start_pin_refresh(state, config);
        return 0;
    }
    // Рель остаётся plain_relay.
    //
    // sni_relay здесь пробовался и не годится: при включении все домены
    // модуля зависали по 18-20 с, потому что у реля не было живого кандидата и
    // он уходил в собственный резолв. Параметры разрыва из discord не помогли.
    //
    // Помогло другое: выбор живого адреса из кандидатов. huggingface.co сидел
    // на 143.204.238.31, который зарезан, и после правки отбора переехал на
    // 143.204.238.110, который отвечает. Рель для этого не требовался.
    plain_relay_config_t relay = {
        .port = state->relay_port,
        .so_mark = state->mark,
        .split_client_hello = 1,
        .frag_delay_ms = 30,
        .frag_first_seg = 20,
    };
    if (plain_relay_start(&relay) != 0) {
        site_bypass_stop(state);
        return -1;
    }
    state->relay_on = true;
    state->active = true;
    start_pin_refresh(state, config);
    return 0;
}

void site_bypass_stop(site_bypass_state_t *state) {
    if (!state) return;
    // Поток останавливаем первым: он пишет файл закреплений, а ответчик и
    // рель сейчас будут сняты. Если он успеет дописать после этого, следующий
    // запуск стартует с адреса, которого никто не проверял.
    state->stopping = true;
    if (g_refresh_running) {
        pthread_join(g_refresh_th, NULL);
        g_refresh_running = false;
    }
    if (state->rules_installed || state->chain[0]) rules_remove(state);
    dns_stop(state);
    plain_relay_stop();
    state->active = false;
    state->rules_installed = false;
    state->dns_fd = -1;
    site_pin_count = 0;
    site_ip_validator = NULL;
    site_fallback_count = 0;
    memset(site_fallback_ips, 0, sizeof(site_fallback_ips));
}

int site_bypass_active(const site_bypass_state_t *state) {
    if (!state || !state->active || state->dns_pid <= 0) return 0;
    return state->relay_on ? plain_relay_running() : 1;
}
