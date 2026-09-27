#!/usr/bin/env bash
# Перебор TTL для поддельного ClientHello.
#
# Что этот скрипт измеряет, а что нет. Важно понимать до запуска.
#
# Меряет: доходит ли соединение и какой размер ответа. Это сетевой уровень.
# НЕ меряет: работает ли приложение Discord. Через curl Discord отдаёт
# страницу-заглушку anti-bot размером около 15 КБ независимо от того, пустил
# ли провайдер соединение или нет. Поэтому «страница выросла» здесь — не
# доказательство, что заработало приложение. Для приложения нужен настоящий
# браузер, и это отдельная ручная проверка.
#
# Зачем перебор: подделка с маленьким TTL должна умереть после первого хопа
# провайдера, не долетев до сервера. Значение подбирается, а не выводится:
#   2-4 — DPI рядом, сервер не видит подделки;
#   6 и выше — подделка может долететь до сервера и сломать TLS.
# Значит перебор не косметика: слишком большое значение хуже, чем никакого.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/build/bin/rmf-desync"

IFACE="${IFACE:-enp42s0}"
CIDR="${CIDR:-162.159.128.0/18}"
DPORT="${DPORT:-443}"
# Имя в подделке ClientHello. Российское — намеренно: ТСПУ глубоко разбирает
# заблокированные ресурсы и почти не трогает трафик к российским площадкам
# (те же CDN и AS, поломка сломала бы слишком многое). Подделка с
# российским именем выглядит для DPI как рутина. Заблокированное имя в
# подделке, наоборот, читается как «здесь спрятали» и вызывает агрессию.
# Подставляется только в подделку, настоящий ClientHello не трогается.
SNI="${SNI:-vk.ru}"
MARK="${MARK:-0x4d5a}"          # метка модуля discord: без неё подделку завернёт сам модуль
TTLS="${TTLS:-2 3 4 6}"
SAMPLES="${SAMPLES:-3}"         # замеров на значение
PAUSE="${PAUSE:-2}"             # пауза между замерами, сек
SETTLE="${SETTLE:-2}"           # дать слою встать, сек

# Проверяем именно сетевой уровень: дошёл ли TLS и что принесло.
PROBES=(
    "https://discord.com/"
    "https://cdn.discordapp.com/embed/avatars/0.png"
    "https://discord.com/api/v9/experiments"
)

if [[ ! -x "$BIN" ]]; then
    echo "нет $BIN — соберите: make desync" >&2
    exit 1
fi
if [[ "$(id -u)" -ne 0 ]]; then
    echo "нужен root: слой работает на сырых сокетах. Запустите: sudo $0" >&2
    exit 1
fi
if ! "$BIN" --help >/dev/null 2>&1; then
    echo "слой не запускается" >&2
    exit 1
fi

LAYER_PID=""
CONF="webui/discord.conf"
API="http://127.0.0.1:8080"
SAVED_CONF=""; TOUCHED_CONF=0

# Перебор TTL зашумлён, если рядом работает разрыв SNI: рель рвёт поток на
# ~20 КБ, и любой TTL покажет «плохо» независимо от подделки. На время
# замера модуль discord переводится в режим пропуска (split_ch=0), чтобы
# единственным способом спрятать домен был desync. Конфиг восстанавливается
# на любом выходе.
conf_set() {
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
    if [[ ! -f "$CONF" ]]; then
        echo "  нет $CONF — проверьте split_ch вручную, иначе замер будет зашумлён"
        return 0
    fi
    local cur; cur="$(sed -n 's/^split_ch=//p' "$CONF" | head -1)"
    SAVED_CONF="$(mktemp)"; cp -a "$CONF" "$SAVED_CONF"
    if [[ "$cur" == "1" ]]; then
        conf_set split_ch 0 && restart_discord
        TOUCHED_CONF=1
        echo "  модуль discord -> режим пропуска (split_ch 1 -> 0), верну обратно"
    else
        echo "  модуль discord уже в режиме пропуска (split_ch=${cur:-?})"
    fi
}
restore_conf() {
    [[ "$TOUCHED_CONF" == "1" ]] || return 0
    [[ -s "$SAVED_CONF" ]] || return 0
    cp -f "$SAVED_CONF" "$CONF" && restart_discord
    echo "  исходный конфиг discord восстановлен (split_ch=1)"
}
cleanup() {
    if [[ -n "$LAYER_PID" ]] && kill -0 "$LAYER_PID" 2>/dev/null; then
        kill "$LAYER_PID" 2>/dev/null
        wait "$LAYER_PID" 2>/dev/null
    fi
    LAYER_PID=""
    restore_conf
    [[ -n "$SAVED_CONF" ]] && rm -f "$SAVED_CONF"
}
trap cleanup EXIT INT TERM
prepare_passthrough

START=$SECONDS

# Целостность потока. «Есть связь» (код не 000) и «поток цел» — разные вещи:
# конфиг, где Discord отвечает, а поток обрывается на ~20 КБ, даёт связь и
# при этом бесполезен. Сверяем доехавший размер с Content-Length.
ORACLE="scripts/discord-asset-check.sh"

integrity() {   # -> "ЦЕЛ" | "ОБРЫВ <got>/<want>" | "НЕТ"
    local out got want
    out="$(TIMEOUT=15 "$ORACLE" --quiet 2>/dev/null)"
    if [[ "$out" == "OK" ]]; then echo "ЦЕЛ"; return 0; fi
    if [[ -z "$out" || "$out" == "НЕТ" ]]; then echo "НЕТ"; return 1; fi
    got="${out#FAIL }"; got="${got%% *}"; want="${out##* }"
    echo "ОБРЫВ $got/$want"; return 1
}

measure() {   # url -> "код размер секунды" либо "НЕТ связи"
    local url="$1" out
    out="$(curl -s -o /dev/null -m 12 \
             -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126 Safari/537.36" \
             -w '%{http_code} %{size_download} %{time_total}' "$url" 2>/dev/null)"
    if [[ -z "${out// /}" || "${out%% *}" == "000" ]]; then
        echo "НЕТ"
    else
        echo "$out"
    fi
}

# Слой работает, пока работает цикл. Фоновая петля гонит трафик, чтобы
# слой видел ClientHello: без потока подделок не будет, и замер ничего
# не покажет.
drive_traffic() {
    local until=$((SECONDS + $2))
    while (( SECONDS < until )); do
        curl -s -o /dev/null -m 8 "https://discord.com/" 2>/dev/null
        sleep 0.4
    done
}

last_counters() {   # достаёт последнюю строку счётчиков слоя
    local line
    line="$(grep -a 'подделок' "$1" 2>/dev/null | tail -1)"
    if [[ -z "$line" ]]; then echo "нет данных"; return; fi
    echo "$line" | sed -E 's/.*просмотрено ([0-9]+).*подошло ([0-9]+).*ClientHello ([0-9]+).*подделок ([0-9]+).*/просмотрено=\1 подошло=\2 ClientHello=\3 подделок=\4/'
}

echo "===================================================================="
echo " перебор TTL.  цель $CIDR:$DPORT  интерфейс $IFACE"
echo " адреса, на которые модуль реально идёт (источник истины — модуль):"
sed -n 's/^ *{\"\([a-z0-9.-]*\)", *\"\([0-9.]*\)"}.*/   \1 -> \2/p' \
    "$ROOT/src/modules/discord/src/discord_module.c" 2>/dev/null | head -20
echo " подделка: имя «$SNI», метка $MARK, значений: $TTLS, замеров на значение: $SAMPLES"
echo "-------------------------------------------------------------------"
echo " ВНИМАНИЕ: curl получает от Discord заглушку anti-bot ~15 КБ."
echo " Этот перебор показывает СЕТЬ. Про приложение скажет только браузер."
echo "===================================================================="

# Базовая линия: без слоя. Без неё сравнивать не с чем.
echo
echo "база (слой выключен):"
for u in "${PROBES[@]}"; do
    printf "  %-46s %s\n" "${u#https://}" "$(measure "$u")"
done

declare -A BEST
for ttl in $TTLS; do
    echo
    echo "-------------------------------------------------------------------"
    echo "TTL=$ttl"
    LOG="$(mktemp)"
    "$BIN" --iface "$IFACE" --cidr "$CIDR" --dport "$DPORT" \
           --fake-sni "$SNI" --ttl "$ttl" --mark "$MARK" >"$LOG" 2>&1 &
    LAYER_PID=$!
    sleep "$SETTLE"
    if ! kill -0 "$LAYER_PID" 2>/dev/null; then
        echo "  слой не стартовал:"; sed 's/^/    /' "$LOG"; rm -f "$LOG"; continue
    fi

    total_bad=0
    for ((i = 1; i <= SAMPLES; i++)); do
        drive_traffic x 6 &
        DPID=$!
        printf "  замер %d: " "$i"
        line=""
        for u in "${PROBES[@]}"; do
            r="$(measure "$u")"
            [[ "$r" == "НЕТ" ]] && total_bad=1
            printf '      целостность styles.css: %s\n' "$(integrity)"
            integ="$(integrity)"; [[ "$integ" == "ЦЕЛ" ]] || total_bad=1
            line+="${u%%/*}:${r}  "
        done
        echo "$line"
        wait "$DPID" 2>/dev/null
        sleep "$PAUSE"
    done
    printf "  счётчики: %s\n" "$(last_counters "$LOG")"
    # Если цель не совпала ни разу, молчать нельзя: показываем, куда трафик
    # идёт на самом деле. Раньше эти строки попадали в лог и удалялись вместе
    # с ним — самая полезная диагностика терялась именно там, где нужнее всего.
    if ! grep -qa 'подошло [1-9]' "$LOG"; then
        echo "  ВНИМАНИЕ: ни одного пакета к цели. Куда трафик идёт на самом деле:"
        grep -a -A12 'куда идёт трафик' "$LOG" | tail -11 | sed 's/^/    /'
        if ! grep -qa 'куда идёт трафик' "$LOG"; then
            echo "    (слой отработал слишком мало: 5 с на список не хватило)"
        fi
    fi
    [[ "$total_bad" -eq 1 ]] && echo "  ВНИМАНИЕ: была потеря связи"
    BEST[$ttl]="$total_bad"
    cleanup
    rm -f "$LOG"
done

echo
echo "===================================================================="
echo " итог по сетью (0 — все замеры прошли, 1 — была обрыв связи)"
for ttl in $TTLS; do
    if [[ -n "${BEST[$ttl]:-}" ]]; then
        printf "  TTL=%-3s %s\n" "$ttl" "$([[ "${BEST[$ttl]}" == 0 ]] && echo 'связь не рвалась' || echo 'связь рвалась')"
    fi
done
echo "-------------------------------------------------------------------"
echo " Потрачено времени: $((SECONDS - START)) с."
echo " Теперь главное: открой Discord в браузере или приложении."
echo " Сеть может быть в порядке, а приложение — нет: curl этого не видит."
echo "===================================================================="
