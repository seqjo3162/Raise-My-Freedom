#!/usr/bin/env bash
# Сравнение Discord без слоя и со слоем.
#
# Слой desync работает на уровне IP/TCP до сборки TLS, поэтому поток он не
# трогает — в отличие от разрыва SNI, который рвёт поток на ~20 КБ.
#
# Меряем ДОЕЗЖАНИЕ ФАЙЛА ЦЕЛИКОМ по Content-Length, а не «открылась ли
# страница»: прежний критерий «код не 000» не зависел от обхода.
#
# Выводит обе серии рядом, чтобы разница была видна сразу.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/build/bin/rmf-desync"
IFACE="${IFACE:-enp42s0}"
CIDR="${CIDR:-162.159.0.0/16}"
TTL="${TTL:-3}"
# Имя в подделке ClientHello. Российское — намеренно: ТСПУ глубоко разбирает
# заблокированные ресурсы и почти не трогает трафик к российским площадкам
# (те же CDN и AS, поломка сломала бы слишком многое). Подделка с
# российским именем выглядит для DPI как рутина. Заблокированное имя в
# подделке, наоборот, читается как «здесь спрятали» и вызывает агрессию.
# Подставляется только в подделку, настоящий ClientHello не трогается.
SNI="${SNI:-vk.ru}"
MARK="${MARK:-0x4d5a}"
N="${N:-6}"
TTLS="${TTLS:-}"
LAYER_LOG="$(mktemp)"; LAYER_PID=""
CONF="webui/discord.conf"
API="http://127.0.0.1:8080"
SAVED_CONF=""; TOUCHED_CONF=0

# ── Честная подготовка ───────────────────────────────────────────────────
#
# Замерять desync поверх работающего разрыва SNI бессмысленно: рель сам
# рвёт поток на ~20 КБ, и слой не может это обойти. Первый такой замер
# дал 0/6 в обеих сериях — и это сказало о разрыве, а не о desync.
#
# Поэтому на время замера модуль discord переводится в режим
# «пропускать байты» (split_ch=0): DNS-подмену он оставляет, рукопохатие
# не трогает, и единственным способом спрятать домен остаётся desync.
# Исходный конфиг восстанавливается на любом выходе, включая Ctrl-C.
conf_get() { sed -n "s/^$1=//p" "$CONF" 2>/dev/null | head -1; }

conf_set() {   # key value, сохраняя остальные строки
    local k="$1" v="$2" t
    t="$(mktemp)" || return 1
    awk -v k="$k" -v v="$v" 'BEGIN{FS="="} $1==k{print k "=" v; next}{print}' \
        "$CONF" >"$t" && mv -f "$t" "$CONF"
}

restart_discord() {
    curl -fsS -m 10 -X POST "$API/api/stop?plugin=discord"  >/dev/null 2>&1; sleep 2
    curl -fsS -m 20 -X POST "$API/api/start?plugin=discord" >/dev/null 2>&1; sleep 3
}

prepare_passthrough() {
    [ -f "$CONF" ] || { echo "нет $CONF — пропускаю настройку, проверь вручную"; return 0; }
    local cur; cur="$(conf_get split_ch)"
    SAVED_CONF="$(mktemp)"; cp -a "$CONF" "$SAVED_CONF"
    if [ "$cur" = "1" ]; then
        conf_set split_ch 0 && restart_discord
        TOUCHED_CONF=1
        echo "  модуль discord переведён в режим пропуска (split_ch 1 -> 0),"
        echo "  чтобы замерялся desync, а не разрыв SNI. Верну обратно."
    else
        echo "  модуль discord уже в режиме пропуска (split_ch=${cur:-?})"
    fi
}

restore_conf() {
    [ "$TOUCHED_CONF" = "1" ] || return 0
    [ -s "$SAVED_CONF" ] || return 0
    cp -f "$SAVED_CONF" "$CONF" && restart_discord
    echo "  исходный конфиг discord восстановлен (split_ch=1)"
}

cleanup() {
    [[ -n "$LAYER_PID" ]] && kill "$LAYER_PID" 2>/dev/null
    wait 2>/dev/null
    restore_conf
    [[ -n "$SAVED_CONF" ]] && rm -f "$SAVED_CONF"
}
trap cleanup EXIT INT TERM

# Источник истины один на весь проект: scripts/discord-asset-check.sh сверяет
# размер с Content-Length. Прежний критерий «код не 000» и заглушка anti-bot
# на /app не зависели от обхода и объявляли успех там, где поток обрезан.
ORACLE="$ROOT/scripts/discord-asset-check.sh"
STYLES_CSS_BYTES=782354   # Content-Length основного оракула

series() {   # подпись -> одна строка итогов
    local label="$1" whole=0 sum_s=0 n silent=0
    for ((n = 0; n < N; n++)); do
        local out got want
        out="$(TIMEOUT=12 "$ORACLE" --quiet 2>/dev/null | head -1)"
        if [[ "$out" == "OK" ]]; then
            # Оракул сам знает ожидаемый размер: он сверял с Content-Length.
            got="$STYLES_CSS_BYTES"; want="$got"
        elif [[ "$out" == FAIL\ * ]]; then
            got="${out#FAIL }"; got="${got%% *}"; want="${out##* }"
        else
            # Оракул не ответил. Это НЕ успех: раньше пустой вывод проходил
            # как «got == want», и замер молча превращался в 6/6.
            silent=$((silent+1)); got=0; want=1
        fi
        [[ "$got" =~ ^[0-9]+$ ]] && sum_s=$((sum_s + got))
        [[ "$got" == "$want" && "$want" != "0" && "$silent" -eq 0 ]] && whole=$((whole+1))
    done
    printf "  %-10s styles.css доехал целиком %d/%d, средний размер %6d Б\n" \
           "$label" "$whole" "$N" $((sum_s / N))
    if [[ "$silent" -gt 0 ]]; then
        printf "  %-10s ВНИМАНИЕ: оракул не ответил %d раз из %d — эти замеры\n" "" "$silent" "$N"
        printf "  %-10s НЕ УЧТЕНЫ как успех. Проверь, что %s запускается отсюда.\n" "" "$ORACLE"
    fi
}

echo "===================================================================="
echo " Discord: без слоя и со слоем.  цель $CIDR  TTL=$TTL  имя «$SNI»"
echo " запросов на серию: $N"
echo "===================================================================="
prepare_passthrough

if [[ -z "$TTLS" ]]; then
    echo
    echo "--- серия 1: слой выключен ----------------------------------------"
    series "без слоя"
    echo
    echo "--- серия 2: слой включён -----------------------------------------"
else
    echo
    for TTL in $TTLS; do
        echo "--- слой включён, TTL=$TTL -----------------------------------"
        LAYER_PID=""
        sudo -n "$BIN" --iface "$IFACE" --cidr "$CIDR" --dport 443 \
             --fake-sni "$SNI" --ttl "$TTL" --mark "$MARK" >"$LAYER_LOG" 2>&1 &
        LAYER_PID=$!
        sleep 2
        if kill -0 "$LAYER_PID" 2>/dev/null; then
            series "TTL=$TTL"
            printf "    подделок: %s\n" "$(grep -ao "подделок [0-9]*" "$LAYER_LOG" | tail -1 | grep -oE "[0-9]+")"
        else
            echo "  слой не стартовал"
        fi
        cleanup
    done
    echo "===================================================================="
    echo " Критерий: styles.css (782354 Б) доехал целиком во всех запросах."
    echo " Если ни один TTL не дал полной доставки — подделка вредна при любом"
    echo " TTL, и подход не подходит."
    rm -f "$LAYER_LOG"
    exit 0
fi

sudo -n "$BIN" --iface "$IFACE" --cidr "$CIDR" --dport 443 \
     --fake-sni "$SNI" --ttl "$TTL" --mark "$MARK" >"$LAYER_LOG" 2>&1 &
LAYER_PID=$!
sleep 2
if kill -0 "$LAYER_PID" 2>/dev/null; then
    series "со слоем"
    echo
    echo "  счётчики слоя:"
    grep -a "подделок" "$LAYER_LOG" | tail -1 | sed 's/^/    /'
    n=$(grep -ao "подделок [0-9]*" "$LAYER_LOG" | tail -1 | grep -oE "[0-9]+")
    if [[ "${n:-0}" -eq 0 ]]; then
        echo "    ВНИМАНИЕ: подделок ноль. Слой не вмешался, серии несравнимы:"
        echo "    разница в скорости ничего не значит."
    else
        echo "    подделок отправлено: $n — слой вмешивался, серии сравнимы."
    fi
else
    echo "  слой не стартовал:"; sed 's/^/    /' "$LAYER_LOG"
fi

echo
echo "===================================================================="
echo " Про клиент Discord (логин, аватарки, голос) сказать по curl нельзя —"
echo " проверь руками в браузере. Но целостность потока уже измерена точно."
echo "===================================================================="
rm -f "$LAYER_LOG"
