# 📚 Модуль стратегий обхода

## 🎯 Назначение

Папка `src/modules/` содержит **два типа файлов**:

### 1. `/patterns/` — Паттерны (шаблоны)
**Не работают сами!** Это "листочек-инструкция" о том, как стратегии выглядят.  
Твоя реализация должна быть в скриптах!

**Что здесь:**
- `sni_pattern.h` — SNI Hijacker Pattern
- `raw_pattern.h` — Raw Socks Pattern
- `direct_tunnel_pattern.h` — Direct Tunnel Pattern
- `port_forward_pattern.h` — Port Forwarding Pattern
- `sni_proxy_pattern.h` — SNI Proxy Pattern

**Как использовать:**
1. Читаешь паттерн в `.h` файле
2. В своём скрипте пишешь логику **по образцу из паттерна**
3. Вызываешь функцию обработки **сам** (не автоматически!)

---

### 2. `/battlenet/`, `/discord/`, `/google/` и др. — Модулы провайдеров
**Рабочие скрипты!** Это уже реализация для конкретных сервисов.

**Что здесь:**
- `discord/` — обход Discord (требования, правила, команды)
- `google/` — обход Google/YouTube (правила iptables)
- `steam/` — обход Steam
- и другие...

---

## 📋 Структура:

```
src/modules/
├── patterns/          ← Пустые шаблоны
│   ├── sni_pattern.h
│   ├── raw_pattern.h
│   ├── direct_tunnel_pattern.h
│   ├── port_forward_pattern.h
│   └── sni_proxy_pattern.h
│
├── discord/           ← Реализация для Discord
│   └── ...
│
├── google/            ← Реализация для Google
│   └── ...
│
└── [другие провайдеры]
```

---

## 🛠 Как добавить новую стратегию:

### Шаг 1: Читаешь паттерн
```bash
cat src/modules/patterns/sni_pattern.h
# Идентифицируешь, как работает стратегия
```

### Шаг 2: Пишешь реализацию в скрипте
```c
// В своём модуле:
#include "src/modules/patterns/sni_pattern.h"

struct sni_context ctx;
ctx.type = SNI_TYPE_CHECKER;
ctx.target_host = "youtube.com";

process_sni_request(ctx);
```

### Шаг 3: Тестируешь
```bash
sudo scripts/install-bypass.sh
curl -I https://www.youtube.com --connect-timeout 5
```

---

## ⚠️ Критичные ограничения:

1. **Никаких изменений DNS** — только редирект портов через iptables
2. **Нет MITM** — только прозрачная пересылка пакетов
3. **Не ломать интернет** — минимальные правила, не блокировать легитимный трафик
4. **Все правила читаются из .txt файлов** в корне проекта

---

## 🎯 Итог:

- **Паттерны = инструкции** (как выглядит стратегия)
- **Модулы провайдеров = реализации** (готовый код для конкретных сервисов)
- **Ты пишешь логику на основе паттернов!**