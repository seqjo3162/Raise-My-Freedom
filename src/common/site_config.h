#ifndef SITE_CONFIG_H
#define SITE_CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Параметры модуля, которые можно менять без правки кода.
//
// Модуль по-прежнему собирается из макросов в src/modules/<имя>/src/module.c —
// это значения по умолчанию. Но рядом с модулем лежит module.conf, и если он
// есть, значения из файла перекрывают собранные. Формат простой, key = value,
// без вложенности: его одинаково легко писать руками и генерировать из веба.
//
//   label        = GitHub
//   chain        = GITHUB_BYPASS
//   method       = relay            # sni | relay | pin | drop
//   dns_port     = 18590
//   relay_port   = 18490
//   mark         = 0x4d55
//   primary_dns  = 1.1.1.1
//   fallback_dns = 8.8.8.8
//   domain       = github.com       # можно повторять
//   cidr         = 140.82.121.0/24  # можно повторять
//   fallback_ip  = 1.2.3.4          # можно повторять
//
// Почему method, а не отдельные наборы полей: у sni, реля и закрепления
// разные параметры, и в вебе это один дропдаун, а не три формы.

#define SITE_CONF_MAX_DOMAINS   64
#define SITE_CONF_MAX_CIDR      32
#define SITE_CONF_MAX_FALLBACK  16
#define SITE_CONF_MAX_LINE      512
#define SITE_CONF_MAX_CHAIN     64
#define SITE_CONF_MAX_LABEL     64
#define SITE_CONF_MAX_HOST      64

// Способы обхода. Значение попадает в файл как слово, в вебе это дропдаун.
typedef enum {
    SITE_METHOD_SNI = 0,   // разрыв SNI в реле, трафик идёт через рель
    SITE_METHOD_RELAY,     // прозрачный рель, SNI не трогаем
    SITE_METHOD_PIN,       // только закрепление DNS-адресов
    SITE_METHOD_DROP       // пропускать, ничего не делая (для проверки)
} site_method_t;

typedef struct {
    char label[SITE_CONF_MAX_LABEL];
    char chain[SITE_CONF_MAX_CHAIN];
    site_method_t method;
    int  dns_port;                 // 0 = не перехватывать DNS
    int  relay_port;               // 0 = рель не нужен
    unsigned int mark;
    char primary_dns[SITE_CONF_MAX_HOST];
    char fallback_dns[SITE_CONF_MAX_HOST];

    char domains[SITE_CONF_MAX_DOMAINS][SITE_CONF_MAX_HOST];
    size_t domain_count;

    // Диапазоны адресов: модуль сразу заворачивает весь диапазон, а не
    // один адрес. Нужно играм, где текущий инстанс работает, а соседний нет.
    char cidrs[SITE_CONF_MAX_CIDR][SITE_CONF_MAX_HOST];
    size_t cidr_count;

    char fallback_ips[SITE_CONF_MAX_FALLBACK][SITE_CONF_MAX_HOST];
    size_t fallback_count;
} site_config_t;

const char *site_method_name(site_method_t m);
site_method_t site_method_from_name(const char *name);

// Значения по умолчанию: пустые, значит модуль работает на своих #define.
void site_config_defaults(site_config_t *cfg);

// Разбор файла. 0 — успешно, -1 — файл не открылся, -2 — не разобран
// (тогда err получает причину). Отсутствие файла — не ошибка: модуль
// остаётся на встроенных значениях.
int site_config_load(const char *path, site_config_t *cfg, char *err, size_t errsz);

// Запись файла. Перед записью значения проверяются; при отказе возвращается
// -1 и err объясняет, что не так.
int site_config_save(const char *path, const site_config_t *cfg, char *err, size_t errsz);

// Проверка без записи. Правила: порты 1..65535, метка в 0x4d50..0x4d5f,
// цепочка из заглавных букв, цифр и подчёркивания, домен без схемы и пути,
// диапазон в виде a.b.c.d/nn.
int site_config_validate(const site_config_t *cfg, char *err, size_t errsz);

#endif
