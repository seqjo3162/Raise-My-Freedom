# 📚 Модуль паттернов стратегий — rmf patterns

## ⚠️ КРИТИЧНО ВАЖНО:

**ЭТО ЛЮБОЙ ПУСТОЙ КОНТЕЙНЕР ДЛЯ ИНСТРУКЦИЙ!**

Паттерны в этой папке **НЕ РАБОТАЮТ АВТОМАТИЧЕСКИ**.  
Они содержат **только**:
- Структуры данных (`struct`)
- Перечисления (`enum`)
- Декларации функций (`extern int func()`)

**Реализацию пишут в твоих скриптах `commands/*.sh`!**

---

## 📂 СТРУКТУРА:

```
src/modules/patterns/
├── README.md           # этот файл — полное описание всех паттернов
├── sni.h               # SNI Hijacking (перехват TLS по имени)
├── raw.h               # Raw Socks (прямые сокеты через REDIRECT)
├── direct.h            # Direct Tunnel (tun/tap устройство)
├── forward.h           # Port Forwarding (перенаправление портов)
└── sniproxy.h          # SNI Proxy (TLS прокси с оригинальным сертификатом)
```

---

## 🎯 КАК ИСПОЛЬЗОВАТЬ:

### Шаг 1: Читаешь паттерн
```bash
cat src/modules/patterns/sni.h
```

### Шаг 2: Понимаешь структуру
```c
// Пример из sni.h:
struct sni_ctx {
    uint16_t type;              // SNI_TYPE_CHECKER или SNI_TYPE_BYPASS
    char target_host[256];      // "youtube.com"
    int proxy_port;             // 1083 или 1084
};
```

### Шаг 3: Пишешь свою реализацию в скрипте
```bash
#!/bin/bash
# commands/sni-bypass.sh

cat << 'EOF' > /tmp/sni_rule.txt
iptables -t nat -A OUTPUT -p tcp --dport 443 \
  -m string --string "youtube.com" \
  -j REDIRECT --to-ports 1083
EOF
```

### Шаг 4: Применяешь правила через команды
```bash
sudo commands/apply-rules.sh sni-bypass
```

---

## 📋 СПИСОК ПАТТЕРНОВ:

### 1. `sni.h` — SNI Hijacker Pattern
**Что делает:** Перехват TLS handshake на уровне SNI-заголовка.  
**Как реализовать:** Прокси пересылает DNS-запрос клиента к цели, клиент делает TLS Handshake с реальным сертификатом сервера, прокси передаёт этот handshake целевому серверу напрямую.

---

### 2. `raw.h` — Raw Socks Pattern
**Что делает:** Прямые сокеты через iptables REDIRECT.  
**Как реализовать:** iptables перехватывает пакет (port redirect), прокс принимает на порту 1083/1084, передаёт пакеты напрямую к оригинальному серверу без изменений содержимого.

---

### 3. `direct.h` — Direct Tunnel Pattern
**Что делает:** Туннелирование через tun/tap устройство.  
**Как реализовать:** Создаётся tun/tap устройство (tun0 или tap0), прокси пересылает трафик через него, IP-таблицы маршрутизации шлют пакеты напрямую к цели.

---

### 4. `forward.h` — Port Forwarding Pattern
**Что делает:** Перенаправление портов через iptables DNAT/REDIRECT.  
**Как реализовать:** iptables перехватывает соединение на порту 443, перенаправляет (DNAT) на порт прокси (1083/1084), прокси передаёт пакет дальше к оригинальному серверу.

---

### 5. `sniproxy.h` — SNI Proxy Pattern
**Что делает:** Проксирование TLS с сохранением оригинального сертификата.  
**Как реализовать:** Клиент соединяется с проксом, указывает SNI-имя в заголовке, прокси смотрит SNI и подключается к оригинальному серверу с тем же SNI (без MITM).

---

## 🛠 ПРИМЕР РЕАЛИЗАЦИИ:

### Паттерн (sni.h) — только инструкция:
```c
struct sni_ctx {
    uint16_t type;              // SNI_TYPE_CHECKER или SNI_TYPE_BYPASS
    char target_host[256];      // "youtube.com"
    int proxy_port;             // 1083
};

extern struct sni_ctx* sni_create(sni_op_t type, const char* host);
extern void sni_destroy(struct sni_ctx** ctx);
extern int sni_process_handshake(struct sni_ctx* ctx);
```

### Реализация (commands/sni-bypass.sh) — твоя работа:
```bash
#!/bin/bash
# commands/sni-bypass.sh

cat << 'EOF' > /tmp/sni-youtube.txt
iptables -t nat -A OUTPUT -p tcp --dport 443 \
  -m string --string "youtube.com" \
  -j REDIRECT --to-ports 1083
EOF

echo "SNI bypass rule for youtube.com created!"
```

---

## ❗ ПОВТОРЯЮ:

1. **Паттерны НЕ РАБОТАЮТ!** Они лишь инструкции.
2. **Реализацию пишешь сам** в скриптах `commands/*.sh`.
3. **Используешь структуры из паттернов** как основу для своих правил.
4. **Никаких изменений DNS** — только редирект портов через iptables.

---

## 📝 ДОКУМЕНТАЦИЯ:

- `src/modules/patterns/README.md` — эта документация
- `src/modules/patterns/*.h` — структуры и декларации паттернов
- `commands/*.sh` — реализации (пишешь сам!)
