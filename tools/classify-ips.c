/* Классификатор адресов: где обход нужен, а где вредит.
 *
 * Зачем. Правило REDIRECT стоит по адресу, значит проверить адрес «в обход
 * правил» нельзя: тот же адрес уводит трафик в рель, и результат говорит
 * о реле, а не о провайдере. Поэтому проба идёт с меткой сокета — модули
 * сами этот приём используют, RETURN по метке стоит выше REDIRECT.
 *
 * Три исхода:
 *   1 — сертификат выдан этому имени, адрес доступен напрямую. Обход не нужен,
 *       а рель только добавляет лишний узел и точки отказа.
 *   0 — рукопожато��ь состоялось, имя чужое: адрес обслуживает другой сервис.
 *  -1 — рукопожатие не состоялось: провайдер рвёт соединение. Здесь обход
 *       обязателен, иначе приложение не соединится вовсе.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "src/common/site_probe.h"

struct row { const char *ip, *host, *who; };

static const struct row rows[] = {
    /* Discord */
    {"162.159.128.233", "discord.com",           "discord"},
    {"162.159.129.233", "discord.com",           "discord"},
    {"162.159.130.233", "discord.com",           "discord"},
    {"162.159.133.232", "discord.com",           "discord"},
    {"162.159.133.234", "discord.gg",            "discord"},
    {"162.159.134.233", "discord.com",           "discord"},
    {"162.159.135.232", "discord.com",           "discord"},
    {"162.159.136.232", "status.discord.com",    "discord"},
    {"162.159.137.234", "discord.com",           "discord"},
    {"104.18.48.115",   "dl.discordapp.net",     "discord"},
    {"34.126.226.51",   "dl2.discordapp.net",    "discord"},
    /* VRChat */
    {"104.18.26.36",    "api.vrchat.cloud",      "vrchat"},
    {"104.18.27.36",    "api.vrchat.cloud",      "vrchat"},
    {"104.18.6.156",    "vrchat.com",            "vrchat"},
    {"143.204.238.8",   "assets.vrchat.com",     "vrchat"},
    {"143.204.238.91",  "assets.vrchat.com",     "vrchat"},
    {"108.157.229.62",  "files.vrchat.cloud",    "vrchat"},
    {"108.157.229.98",  "files.vrchat.cloud",    "vrchat"},
    /* GitHub */
    {"185.199.108.133", "raw.githubusercontent.com", "github"},
    {"4.225.11.194",    "github.com",            "github"},
    {"140.82.121.3",    "github.com",            "github"},
    {"140.82.112.3",    "github.com",            "github"},
    /* Hugging Face */
    {"18.213.84.241",   "hf.co",                 "hf"},
    {"34.202.8.246",    "hf.co",                 "hf"},
    {"143.204.238.52",  "transfer.xethub.hf.co", "hf"},
    {"143.204.238.109", "transfer.xethub.hf.co", "hf"},
    {"143.204.238.31",  "huggingface.co",        "hf"},
    {"143.204.238.109", "huggingface.co",        "hf"},
    {"65.9.46.66",      "cdn-lfs-us-1.hf.co",    "hf"},
};

int main(int argc, char **argv) {
    int timeout = argc > 1 ? atoi(argv[1]) : 4000;
    /* Метка модуля Discord: её RETURN стоит выше REDIRECT в его цепочке.
     * Для адресов других модулей цепочка Discord тоже не мешает, потому что
     * правила в ней отбираются по адресу назначения, а не по метке. */
    site_probe_set_mark(0x4d53);

    const char *last = NULL;
    for (size_t i = 0; i < sizeof(rows)/sizeof(rows[0]); i++) {
        if (!last || strcmp(last, rows[i].who) != 0) {
            printf("\n  === %s ===\n", rows[i].who);
            last = rows[i].who;
        }
        int c = site_probe_cert_ok(rows[i].ip, rows[i].host, timeout);
        const char *verdict = c == 1 ? "ОБХОД НЕ НУЖЕН (вред)"
                          : c == 0 ? "ЧУЖОЙ АДРЕС"
                                   : "ОБХОД НЕОБХОДИМ";
        printf("    %-15s %-26s cert=%2d  %s\n",
               rows[i].ip, rows[i].host, c, verdict);
    }
    return 0;
}
