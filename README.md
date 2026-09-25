# Raise-My-Freedom

DNS и TLS-обход ограничений ТСПУ. Ядро на C, модули — shared-библиотеки `.xo`, веб-UI — отдельный бинарник на C.

Идея и базовые приёмы обхода — из проекта **[zapret](https://github.com/bol-van/zapret)** (форк nfqws). Здесь переработанная архитектура с модульной системой: каждый сервис — отдельный плагин, общий обход вынесен в `src/common/site_bypass.c`.

Порты: DNS `127.0.0.1:53` (ядро), веб `127.0.0.1:8080`, модули `18562–18590` (DNS) и `18443–18490` (релей), telegram `1443`.

---

## Как работает модуль: Discord

`src/modules/discord/src/discord_module.c` — 393 строки, собственный модуль, не шаблонный. Ядро вызывает `discord_module_inject(fd)`, модуль делает шесть шагов:

1. **`iptables_base()`** — создаёт цепочку `DISCORD_BYPASS` в таблице `nat` и вешает её на `OUTPUT`.
2. **`iptables_add_vrchat_exceptions()`** — исключения, чтобы не мешать VRChat.
3. **`iptables_add_dns_rule(domain)`** — для каждого из 16 доменов ставит правило по hex-паттерну DNS-имени:
   ```
   iptables -t nat -A DISCORD_BYPASS -p udp --dport 53 \
     -m string --algo bm --hex-string "<wire-pattern>" \
     -j DNAT --to-destination 127.0.0.1:<dns_port>
   ```
   Запрос резолвера к любому из доменов Discord заворачивается на локальный форвардер и не уходит провайдеру.
4. **`resolve_and_redirect()`** — резолвит домены через DoH и на каждый полученный IP вешает:
   ```
   iptables -t nat -A DISCORD_BYPASS -p tcp -d <ip> --dport 443 \
     -j REDIRECT --to-ports <relay_port>
   ```
5. **`discord_relay_start(relay_port)`** — поднимает SNI-split релей на `127.0.0.1:<relay_port>`. Он принимает соединение, читает ClientHello и пересылает зашифрованную полезную нагрузку, разрывая TLS-запись, — это то, что обходит DPI.
6. **IP pinning** — 16 доменов закреплены за конкретными адресами (`discord.com → 162.159.128.233`, `discord.gg → 162.159.135.234` и т.д.), чтобы провайдерский DNS не подсунул свой ответ.

Без root шаги 1–4 пропускаются (`getuid() != 0`), остаётся только релей. `discord_module_remove()` останавливает релей и снимает правила.

---

## Как работает модуль: Telegram

`src/modules/telegram/` — другой подход, без iptables. `module.c` (99 строк) на старте поднимает **MTProxy** на `127.0.0.1:1443`, а `mtproto.c` реализует сам протокол.

```c
void telegram_module_inject(int fd) {
    if (telegram_proxy_start(ctx.proxy_port) == 0) ctx.mode = 1;
}
```

Настройки лежат в `webui/telegram.conf` и правятся через веб:

```ini
secret=<32 hex-символа>
port=1443
prefer_ipv6=1
fake_tls=1
```

`fake_tls` переключает classic-MTProto на FakeTLS — для клиентов, которым нужен маскирующий handshake. Веб отдаёт секрет замаскированным: первые 4 символа и длина, полное значение наружу не уходит (`webui/server.c`, `telegram_settings_json`).

---

## Как написать свой модуль

### Вариант 1: шаблонный

Модули `activision`, `battlenet`, `electronicarts`, `epicgames`, `github`, `roblox`, `soundcloud`, `spotify`, `steam`, `twitch` не содержат логики — только декларацию. Реализация берётся из `src/common/site_module_impl.h` → `src/common/site_bypass.c`.

Создайте `src/modules/<имя>/include/header.h` с `typedef` для конфига и контекста, затем `src/modules/<имя>/src/module.c`:

```c
#include "src/modules/mysite/include/header.h"
#include <stddef.h>

static const char *const site_domains[] = {
    "mysite.com",
    "www.mysite.com",
    NULL
};

#define SITE_MODULE_PREFIX   mysite
#define SITE_MODULE_CONFIG   mysite_config_t
#define SITE_MODULE_CTX      mysite_ctx_t
#define SITE_MODULE_CHAIN    MYSITE_BYPASS
#define SITE_DNS_PORT        18580
#define SITE_RELAY_PORT      18480
#define SITE_MARK            0x4d80
#define SITE_LABEL           "MYSITE"
#include "src/common/site_module_impl.h"
```

Обязательные макросы: `SITE_MODULE_PREFIX`, `SITE_MODULE_CONFIG`, `SITE_MODULE_CTX`, `SITE_MODULE_CHAIN`, `SITE_DNS_PORT`, `SITE_RELAY_PORT`, `SITE_MARK`, `SITE_LABEL`. Список выдаёт `#error`, если что-то забыть.

Требования, которые проверяет `site_bypass_start()`: порты больше 1024, `dns_port != relay_port`, имя цепочки — только `[A-Z0-9_]`, доменов не больше лимита.

Что делает `site_bypass_start()`:
- создаёт цепочку, ставит `-m mark --mark 0x4d50/0xfff0 -j RETURN` — защита от рекурсии, трафик самого прокси не заворачивается;
- вешает цепочку в `OUTPUT` через `-I OUTPUT 1 -j <CHAIN>`;
- DNAT DNS по hex-паттерну каждого домена на `127.0.0.1:<dns_port>`;
- redirect 443 на `127.0.0.1:<relay_port>` для зарезолвленных адресов;
- поднимает форвардер и SNI-релей.

Затем добавьте в `Makefile` две строки — в `MODULES` и вызов шаблона:

```makefile
MODULES = ... mysite
$(eval $(call PLUGIN_template,mysite,mysite,mysite))
```

`make plugs` создаст `build/bin/plugs/mysite.xo`.

### Вариант 2: свой код

Пишите `<имя>_module_init / _inject / _cleanup / _get_status` сами, как в Discord или Telegram. Дублируйте `site_bypass.c` только если реально нужна другая логика.

### API для своего кода

`src/common/site_bypass.h`:

```c
int  site_bypass_start(site_bypass_state_t *state, const site_bypass_config_t *config);
void site_bypass_stop(site_bypass_state_t *state);
int  site_bypass_active(const site_bypass_state_t *state);
```

`site_bypass_config_t`: `name`, `chain`, `domains`, `domain_count`, `dns_port`, `relay_port`, `mark`, `primary_dns`, `fallback_dns`, `validate_ip`, `fallback_ips`, `fallback_count`.

Из ядра доступна `dns_resolve_udp()` — ядро собрано с `-rdynamic`. Заголовки: `src/dns/dns_resolve.h`, `src/dns/doh_resolve.h`, `src/common/sni_relay.h`.

---

## Plugin API

Каждый `.xo` обязан экспортировать пять функций (`src/plugin_api.h`):

| Функция | Смысл |
|---|---|
| `const char* plug_name(void)` | имя плагина |
| `void plug_init(void* config)` | инициализация |
| `void plug_inject(int fd)` | инъекция, здесь ставится обход |
| `void plug_cleanup(void)` | очистка |
| `const char* plug_status(void)` | статус, опционально |

Точку входа генерирует Makefile: `PLUGIN_template` пишет `build/bin/plugs/<имя>_entry.c` с `#define PLUGIN_NAME_STR`, `PLUGIN_INIT_FN`, `PLUGIN_INJECT_FN`, `PLUGIN_CLEANUP_FN`, `PLUGIN_STATUS_FN`, после чего подключает `src/plugin_entry.h`. Руками ничего писать не нужно.

Алиасы имён (`plugin_canonical_name`): `xcom`/`twitter` → `x`, `robloxcom` → `roblox`, `soundcloudcom` → `soundcloud`, `cloudflayerdnscom` → `cloudflaredns`, `speedtestnet` → `speedtestbyookla`.

---

## HTTP API

Веб: `127.0.0.1:8080`, раздаёт `webui/static/index.html`. Реализация — `webui/server.c`. Метод HTTP не проверяется, работает и GET, и POST.

| Endpoint | Что делает |
|---|---|
| `GET /api/status` | состояние прокси и всех плагинов |
| `GET /api/plugins` | список плагинов |
| `GET /api/start?plugin=<имя>` | запустить плагин |
| `GET /api/stop?plugin=<имя>` | остановить плагин |
| `GET /api/stopall` | остановить всё |
| `GET /api/flush` | снести цепочки `*_BYPASS` |
| `GET /api/info` | информация о сборке |
| `GET /api/logs` | лог |
| `GET /api/logs/tags` | список тегов/сервисов в логе |
| `GET /api/backup` | бэкап |
| `GET/POST /api/telegram` | настройки telegram: чтение и запись |
| `GET /api/constructor/list` | спецификации конструктора |
| `GET /api/constructor/load` | загрузить спецификацию |
| `GET /api/constructor/save` | сохранить спецификацию |
| `GET /api/constructor/validate` | провалидировать |
| `POST /api/rebuild` | пересобрать ядро/плагины |
| `GET /api/restart?target=web\|proxy` | перезапуск веба или прокси |

---

## Команды

### Makefile

| Цель | Действие |
|---|---|
| `make` / `make all` | ядро + все плагины + веб |
| `make core` | только `build/bin/minizapret` |
| `make plugs` | только `build/bin/plugs/*.xo` |
| `make webui` | только `build/bin/minizapret-web` |
| `make list` | список плагинов |
| `make clean` | удалить бинарники |
| `make rebuild` | clean + all |
| `make validate` | собрать `build/bin/mz-validate` |
| `make custom` | собрать `build/bin/plugs/custom.xo` из спецификации конструктора |

### Ядро

```bash
sudo build/bin/minizapret inject --<plugin>   # загрузить плагин и начать обход
sudo build/bin/minizapret list                # доступные плагины
build/bin/minizapret plugin --<plugin>        # вариант plugin
build/bin/minizapret proxy                    # standalone DNS-прокси
```

---

## Скрипты

Все лежат в `scripts/`, запускаются от root.

| Скрипт | Что делает |
|---|---|
| `scripts/install-bypass.sh` | Полная установка: останавливает старое, собирает, поднимает веб, стартует плагины `vrchat google x speedtestbyookla`, переключает DNS на `127.0.0.1`, проверяет `dig`. В конце печатает адрес веба и путь к логу |
| `scripts/start-minizapret.sh [плагин]` | Запуск только ядра с одним плагином (по умолчанию `discord`). Логи в `logs/` |
| `scripts/test_bypass.sh [URL]` | Замер скорости через обход, качает URL и печатает скорость |
| `scripts/cleanup.sh` | Удаляет **только** цепочки minizapret. Цепочки `OUTPUT` не флашатся — посторонние правила не трогаются. Перед очисткой снимает снапшот в `logs/iptables-before-cleanup.rules` |

Логи пишутся в `logs/`.

---

## Модули

17 модулей.

Шаблонные, обход через `site_bypass`:

| Модуль | Цепочка | DNS | Релей |
|---|---|---|---|
| activision | `ACTIVISION_BYPASS` | 18562 | 18462 |
| battlenet | `BATTLENET_BYPASS` | 18563 | 18463 |
| electronicarts | `ELECTRONICARTS_BYPASS` | 18564 | 18464 |
| epicgames | `EPICGAMES_BYPASS` | 18565 | 18465 |
| roblox | `ROBLOX_BYPASS` | 18566 | 18466 |
| soundcloud | `SOUNDCLOUD_BYPASS` | 18567 | 18467 |
| steam | `STEAM_BYPASS` | 18568 | 18468 |
| spotify | `SPOTIFY_BYPASS` | 18556 | 18456 |
| twitch | `TWITCH_BYPASS` | 18558 | 18458 |
| github | `GITHUB_BYPASS` | 18590 | 18490 |

Собственная реализация: `discord`, `telegram`, `x`, `google`, `vrchat`, `speedtestbyookla`, `cloudflaredns`.

У четырёх модулей имя плагина не совпадает с именем каталога в `src/modules/` — в `Makefile` они связаны через `PLUGIN_template`:

| Плагин | Каталог |
|---|---|
| `roblox` | `src/modules/robloxcom/` |
| `soundcloud` | `src/modules/soundcloudcom/` |
| `x` | `src/modules/xcom/` |
| `cloudflaredns` | `src/modules/cloudflayerdnscom/` |

`src/modules/patterns/` — не модуль, а библиотека готовых заголовков (`direct.h`, `sni.h`, `raw.h`, `forward.h`, `sniproxy.h`).

---

## Структура

```
Raise-My-Freedom/
├── Makefile
├── src/
│   ├── main.c              # ядро: загрузка плагинов, CLI
│   ├── proxy/proxy.c       # DNS-прокси
│   ├── dns/                # dns_resolve, doh_resolve
│   ├── common/             # общий код: site_bypass, sni_relay
│   ├── modules/            # модули
│   └── constructor/        # конструктор: validate, custom_plugin
├── webui/
│   ├── server.c            # HTTP-сервер и API
│   ├── static/index.html   # фронтенд
│   └── telegram.conf       # настройки MTProxy
├── scripts/                # install, start, test, cleanup
├── logs/                   # логи
└── build/bin/              # бинарники: minizapret, minizapret-web, plugs/*.xo
```

Лицензия — MIT, см. `LICENSE`.
