// Валидатор модулей для веб-конструктора.
//
// Принимает JSON-спецификацию модуля на stdin и выдаёт JSON с результатами
// проверок: что сломано, на каком этапе, с точными байтами и с подсказками,
// какое значение поставить вместо текущего.
//
// Проверки идут от дешёвых к дорогим и останавливаются на первом фатальном:
//   1. схема и диапазоны
//   2. домены
//   3. порты (занятость и конфликты)
//   4. резолв доменов выбранным DNS
//   5. TCP до полученных адресов
//   6. арифметика фрагментации TLS ClientHello (для режима SNI-split)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include "src/dns/dns_resolve.h"
#include "src/dns/doh_resolve.h"

#define MAX_DOMAINS 64
#define MAX_DIAG    32

typedef struct {
    char name[64];
    char chain[64];
    char domains[MAX_DOMAINS][128];
    int  domain_count;
    int  dns_port;
    int  relay_port;
    unsigned int mark;
    char primary[64];
    char fallback[64];
    int  mode;              // 0 dns, 1 relay+sni, 2 mtproto
    int  frag_first_seg;    // размер первого TCP-сегмента
    int  frag_delay_ms;
    int  mt_port;
} spec;

static struct { char level[8]; char step[48]; char msg[512]; char hint[512]; } diag[MAX_DIAG];
static int diag_n = 0;
static int fatal = 0;

static void add_diag(const char *level, const char *step, const char *msg, const char *hint) {
    if (diag_n >= MAX_DIAG) return;
    snprintf(diag[diag_n].level, sizeof(diag[diag_n].level), "%s", level);
    snprintf(diag[diag_n].step,  sizeof(diag[diag_n].step),  "%s", step);
    snprintf(diag[diag_n].msg,   sizeof(diag[diag_n].msg),   "%s", msg);
    snprintf(diag[diag_n].hint,  sizeof(diag[diag_n].hint),  "%s", hint ? hint : "");
    diag_n++;
}
static void die(const char *step, const char *msg, const char *hint) {
    add_diag("error", step, msg, hint);
    fatal = 1;
}

// ─────────────────────────── мини-парсер JSON ───────────────────────────
// Достаёт строку, число или bool по ключу верхнего уровня.

static const char *json_find(const char *json, const char *key) {
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

static int json_str(const char *json, const char *key, char *out, size_t cap) {
    const char *p = json_find(json, key);
    if (!p || *p != '"') return -1;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i < cap - 1) {
        if (*p == '\\' && p[1]) { p++; if (*p == 'n') out[i++] = '\n'; else out[i++] = *p; }
        else out[i++] = *p;
        p++;
    }
    out[i] = '\0';
    return 0;
}

static int json_int(const char *json, const char *key, int dflt) {
    const char *p = json_find(json, key);
    if (!p) return dflt;
    if (*p == '"') p++;
    return atoi(p);
}


// достаёт массив строк "domains": [ "...", "..." ]
static int json_str_array(const char *json, const char *key, char out[][128], int max) {
    const char *p = json_find(json, key);
    if (!p || *p != '[') return 0;
    p++;
    int n = 0;
    while (*p && *p != ']' && n < max) {
        while (*p == ' ' || *p == ',') p++;
        if (*p != '"') break;
        p++;
        size_t i = 0;
        while (*p && *p != '"' && i < 127) out[n][i++] = *p++;
        out[n][i] = '\0';
        n++;
        if (*p == '"') p++;
    }
    return n;
}

// ─────────────────────────── проверки ───────────────────────────

static int port_free(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 0;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((unsigned short)port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int ok = bind(fd, (struct sockaddr *)&a, sizeof(a)) == 0;
    close(fd);
    return ok;
}

static int tcp_probe(const char *ip, int port, int timeout_ms) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, ip, &a.sin_addr) != 1) { close(fd); return -1; }
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    int r = connect(fd, (struct sockaddr *)&a, sizeof(a));
    if (r < 0 && errno != EINPROGRESS) { close(fd); return -1; }
    struct pollfd p = { fd, POLLOUT, 0 };
    int pr = poll(&p, 1, timeout_ms);
    int ok = 0;
    if (pr > 0) {
        int err = 0;
        socklen_t l = sizeof(err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &l);
        ok = (err == 0);
    }
    close(fd);
    return ok ? 0 : -1;
}

static int valid_token(const char *s) {
    if (!s || !*s) return 0;
    for (const char *p = s; *p; p++)
        if (!isalnum((unsigned char)*p) && *p != '_') return 0;
    return 1;
}

// ── синтетический ClientHello, чтобы проверить арифметику разреза ──
static int build_ch(const char *host, unsigned char *hs, int cap) {
    int hl = (int)strlen(host);
    // SNI: server_name_list(2) + name_type(1) + host_len(2) + host
    int sni_data = 5 + hl;
    int ext_total = 4 + sni_data;
    int body_len = 2 + 32 + 2 + 10 + 2 + 2 + ext_total;
    if (body_len + 4 > cap) return -1;

    int n = 4;
    hs[n++] = 0x03; hs[n++] = 0x03;
    for (int i = 0; i < 32; i++) hs[n++] = (unsigned char)(i * 7 + 3);
    hs[n++] = 0x00;                                   // session_id
    static const unsigned char cs[] = {0x13,0x01,0x13,0x02,0xc0,0x2b,0xc0,0x2f,0x00,0x9e};
    hs[n++] = (unsigned char)(sizeof(cs) >> 8); hs[n++] = (unsigned char)sizeof(cs);
    memcpy(hs + n, cs, sizeof(cs)); n += (int)sizeof(cs);
    hs[n++] = 0x01; hs[n++] = 0x00;                   // compression
    hs[n++] = (unsigned char)(ext_total >> 8); hs[n++] = (unsigned char)ext_total;
    hs[n++] = 0x00; hs[n++] = 0x00;                   // extension type: server_name
    hs[n++] = (unsigned char)(sni_data >> 8); hs[n++] = (unsigned char)sni_data;
    int list_len = 3 + hl;
    hs[n++] = (unsigned char)(list_len >> 8); hs[n++] = (unsigned char)list_len;
    hs[n++] = 0x00;                                   // name_type: host_name
    hs[n++] = (unsigned char)(hl >> 8); hs[n++] = (unsigned char)hl;
    memcpy(hs + n, host, (size_t)hl); n += hl;

    hs[0] = 0x01;                                     // ClientHello
    hs[1] = (unsigned char)((n - 4) >> 16);
    hs[2] = (unsigned char)((n - 4) >> 8);
    hs[3] = (unsigned char)(n - 4);
    return n;
}

// ищет позицию SNI-имени внутри ClientHello и проверяем, куда попал разрез
static void check_split(const spec *sp) {
    unsigned char hs[2048];
    int hs_len = build_ch(sp->domains[0], hs, sizeof(hs));
    if (hs_len < 46) { die("fragment", "ClientHello не собрался", "проверьте длину домена"); return; }

    const unsigned char *body = hs + 4;
    int p = 2 + 32;
    int sid = body[p]; p += 1 + sid;
    int cs = (body[p] << 8) | body[p + 1]; p += 2 + cs;
    int comp = body[p]; p += 1 + comp;
    int ext_total = (body[p] << 8) | body[p + 1]; p += 2;
    int end = p + ext_total;

    int name_off = -1, name_len = 0;
    while (p + 4 <= end) {
        int et = (body[p] << 8) | body[p + 1];
        int el = (body[p + 2] << 8) | body[p + 3];
        if (p + 4 + el > end) break;
        if (et == 0x0000 && el >= 5) {
            const unsigned char *ed = body + p + 4;
            name_len = (ed[3] << 8) | ed[4];
            name_off = 4 + p + 4 + 5;
            break;
        }
        p += 4 + el;
    }
    if (name_off < 0) { die("fragment", "SNI-имя не найдено в ClientHello", ""); return; }

    int cut = name_off + name_len / 2;
    if (cut < 2 || cut >= hs_len) {
        die("fragment", "точка разреза вне ClientHello", "уменьшите длину домена");
        return;
    }
    int r1 = 5 + cut;
    int fs = sp->frag_first_seg;
    if (fs >= r1) {
        char hint[256];
        snprintf(hint, sizeof(hint),
                 "frag_first_seg=%d не меньше длины первой записи %d Б — первый сегмент "
                 "не разорвёт её. Поставьте 16..%d (для этого домена оптимально %d)",
                 fs, r1, r1 - 1, r1 / 3 > 0 ? r1 / 3 : 16);
        add_diag("error", "fragment", 
                 "первый TCP-сегмент длиннее TLS-записи, фрагментация не сработает", hint);
        fatal = 1;
        return;
    }
    if (fs < 4) {
        char hint[160];
        snprintf(hint, sizeof(hint), "frag_first_seg=%d слишком мал, поставьте 16..%d", fs, r1 - 1);
        add_diag("warn", "fragment", "первый сегмент короче 4 байт", hint);
    }
    if (sp->frag_delay_ms < 5 || sp->frag_delay_ms > 200) {
        char hint[160];
        snprintf(hint, sizeof(hint), "frag_delay_ms=%d вне рабочего диапазона, поставьте 20..50",
                 sp->frag_delay_ms);
        add_diag("warn", "fragment", "пауза между сегментами выбрана неудачно", hint);
    }
    char ok[256];
    snprintf(ok, sizeof(ok),
             "разрез внутри SNI: байты %d..%d, cut=%d, запись1=%d Б, первый сегмент=%d Б",
             name_off, name_off + name_len - 1, cut, r1, fs);
    add_diag("ok", "fragment", ok, "");
}

// ─────────────────────────── main ───────────────────────────

int main(void) {
    static char json[65536];
    ssize_t n = read(0, json, sizeof(json) - 1);
    if (n <= 0) { printf("{\"ok\":false,\"diags\":[],\"error\":\"пустой ввод\"}\n"); return 1; }
    json[n] = '\0';

    spec sp;
    memset(&sp, 0, sizeof(sp));
    json_str(json, "name", sp.name, sizeof(sp.name));
    json_str(json, "chain", sp.chain, sizeof(sp.chain));
    sp.domain_count = json_str_array(json, "domains", sp.domains, MAX_DOMAINS);
    sp.dns_port   = json_int(json, "dns_port", 0);
    sp.relay_port = json_int(json, "relay_port", 0);
    sp.mark       = (unsigned)json_int(json, "mark", 0);
    json_str(json, "primary_dns", sp.primary, sizeof(sp.primary));
    json_str(json, "fallback_dns", sp.fallback, sizeof(sp.fallback));
    sp.mode           = json_int(json, "mode", 0);
    sp.frag_first_seg = json_int(json, "frag_first_seg", 20);
    sp.frag_delay_ms  = json_int(json, "frag_delay_ms", 30);
    sp.mt_port        = json_int(json, "mt_port", 0);

    // ── 1. схема ──
    if (!sp.name[0]) die("schema", "не задано имя модуля", "впишите имя латиницей");
    else for (const char *q = sp.name; *q; q++)
        if (!isalnum((unsigned char)*q) && *q != '_' && *q != '-')
            die("schema", "в имени есть недопустимые символы", "только буквы, цифры, _ и -");
    if (sp.domain_count == 0) die("domains", "не указан ни один домен", "добавьте хотя бы один");
    if (sp.domain_count > MAX_DOMAINS) {
        char h[128]; snprintf(h, sizeof(h), "максимум %d доменов, сейчас %d", MAX_DOMAINS, sp.domain_count);
        add_diag("warn", "domains", "слишком много доменов", h);
    }
    if (!sp.chain[0]) {
        char h[128];
        snprintf(h, sizeof(h), "для имени %s", sp.name[0] ? sp.name : "модуля");
        add_diag("warn", "schema", "не задана цепочка iptables — правила не попадут в OUTPUT", h);
    } else if (!valid_token(sp.chain)) {
        char h[160];
        snprintf(h, sizeof(h), "в цепочке «%s» есть недопустимые символы", sp.chain);
        die("schema", h, "только латинские буквы, цифры и _ — например MY_SITE");
    }
    if (sp.mode != 2 && sp.dns_port <= 0) die("ports", "не задан dns_port", "укажите свободный порт, например 1053");
    if (sp.mode != 0 && sp.relay_port <= 0) die("ports", "не задан relay_port", "укажите свободный порт, например 18443");
    if (sp.mode == 2 && sp.mt_port <= 0) die("ports", "не задан mt_port", "укажите порт MTProxy, например 1443");
    if (sp.primary[0] && !strchr(sp.primary, '.')) die("dns", "primary_dns не похож на IP", "например 1.1.1.1");
    if (fatal) goto out;

    // ── 2. домены ──
    for (int i = 0; i < sp.domain_count; i++) {
        const char *d = sp.domains[i];
        if (!d[0]) { add_diag("warn", "domains", "пустой домен в списке", "уберите его"); continue; }
        if (!strchr(d, '.')) {
            char h[160]; snprintf(h, sizeof(h), "домен «%s» без точки — похоже, опечатка", d);
            add_diag("warn", "domains", h, "укажите FQDN, например example.com");
        }
        for (int k = 0; k < i; k++)
            if (!strcasecmp(d, sp.domains[k])) {
                char h[160]; snprintf(h, sizeof(h), "домен «%s» продублирован", d);
                add_diag("warn", "domains", h, "оставьте один экземпляр");
            }
    }

    // ── 3. порты ──
    int ports[3] = { sp.dns_port, sp.relay_port, sp.mt_port };
    const char *pnames[3] = { "dns_port", "relay_port", "mt_port" };
    for (int i = 0; i < 3; i++) {
        if (ports[i] <= 0) continue;
        if (ports[i] < 1024) {
            char h[160]; snprintf(h, sizeof(h), "%s=%d ниже 1024 — нужны права root", pnames[i], ports[i]);
            die("ports", h, "поставьте порт выше 1024, например 1053");
        }
        if (ports[i] > 65535) {
            char h[160]; snprintf(h, sizeof(h), "%s=%d вне диапазона", pnames[i], ports[i]);
            die("ports", h, "поставьте 1024..65535");
        }
        for (int k = 0; k < i; k++)
            if (ports[k] == ports[i]) {
                char h[200]; snprintf(h, sizeof(h), "%s и %s совпадают (%d)", pnames[i], pnames[k], ports[i]);
                die("ports", h, "разведите порты: например 1053 и 18443");
            }
        if (!port_free(ports[i])) {
            char h[200]; snprintf(h, sizeof(h), "порт %d уже занят другим процессом", ports[i]);
            add_diag("error", "ports", h, "выберите другой порт или остановите конфликтующий модуль");
            fatal = 1;
        }
    }
    if (fatal) goto out;

    // ── 4. резолв ──
    if (!sp.primary[0]) strncpy(sp.primary, "1.1.1.1", sizeof(sp.primary) - 1);
    int resolved = 0;
    for (int i = 0; i < sp.domain_count; i++) {
        char ip[64] = {0};
        int r = dns_resolve_udp(sp.primary, sp.domains[i], ip, sizeof(ip));
        if (r != 0 && sp.fallback[0]) r = dns_resolve_udp(sp.fallback, sp.domains[i], ip, sizeof(ip));
        if (r == 0 && ip[0]) {
            char m[192];
            snprintf(m, sizeof(m), "%s -> %s", sp.domains[i], ip);
            add_diag("ok", "dns", m, "");
            // ── 5. TCP до адреса ──
            if (tcp_probe(ip, 443, 3000) == 0) {
                char t[192];
                snprintf(t, sizeof(t), "%s:443 отвечает", ip);
                add_diag("ok", "tcp", t, "");
            } else {
                char t[256];
                snprintf(t, sizeof(t), "%s:443 не отвечает — трафик режется или адрес мёртв", ip);
                add_diag("warn", "tcp", t, "проверьте, не блокирует ли провайдер этот адрес");
            }
            resolved++;
        } else {
            char m[256];
            snprintf(m, sizeof(m), "домен %s не резолвится через %s%s%s",
                     sp.domains[i], sp.primary, sp.fallback[0] ? " / " : "", sp.fallback[0] ? sp.fallback : "");
            // если уже стоит публичный резолвер — менять нечего, совет другой
            int public_dns = (!strcmp(sp.primary, "1.1.1.1") || !strcmp(sp.primary, "8.8.8.8") ||
                              !strcmp(sp.primary, "9.9.9.9") || !strcmp(sp.primary, "8.8.4.4"));
            const char *hint = public_dns
                ? "резолвер и так публичный — скорее всего домен режется провайдером. Проверьте другой режим обхода или доступность домена извне"
                : "смените primary_dns на 1.1.1.1 — текущий не отвечает";
            add_diag("warn", "dns", m, hint);
        }
    }
    if (resolved == 0) { die("dns", "ни один домен не резолвится", "проверьте домены и DNS"); goto out; }

    // ── 6. арифметика фрагментации ──
    if (sp.mode == 1) {
        check_split(&sp);
    } else {
        add_diag("ok", "fragment", "режим без фрагментации TLS — проверка не требуется", "");
    }

out:
    printf("{\"ok\":%s,\"diags\":[", fatal ? "false" : "true");
    for (int i = 0; i < diag_n; i++) {
        if (i) printf(",");
        printf("{\"level\":\"%s\",\"step\":\"%s\",\"msg\":\"", diag[i].level, diag[i].step);
        for (const char *p = diag[i].msg; *p; p++) {
            if (*p == '"' || *p == '\\') printf("\\");
            if (*p == '\n') printf("\\n");
            else putchar(*p);
        }
        printf("\",\"hint\":\"");
        for (const char *p = diag[i].hint; *p; p++) {
            if (*p == '"' || *p == '\\') printf("\\");
            putchar(*p);
        }
        printf("\"}");
    }
    printf("],\"summary\":\"");
    int errs = 0, warns = 0, oks = 0;
    for (int i = 0; i < diag_n; i++) {
        if (!strcmp(diag[i].level, "error")) errs++;
        else if (!strcmp(diag[i].level, "warn")) warns++;
        else oks++;
    }
    printf("ошибок: %d, предупреждений: %d, успешных проверок: %d", errs, warns, oks);
    printf("\"}\n");
    return fatal ? 1 : 0;
}
