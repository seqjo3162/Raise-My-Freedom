#!/usr/bin/env bash
# Проверка слоя десинхронизации с перекрёстным контролем через tcpdump.
#
# Зачем tcpdump рядом со слоем. Счётчики слоя — это прибор, который мы сами же
# и чиним: четыре раза подряд он молчал или врал, и каждый раз это выглядело
# как «механизм не работает». tcpdump показывает то, что реально есть на
# проводе, и не зависит ни от нашего кода, ни от его счётчиков. Если слои
# расходятся — значит врёт слой; если совпадают, вердикт можно принимать.
#
# Выводит рядом: что видел слой и что видел tcpdump по тому же адресу.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/build/bin/rmf-desync"
IFACE="${IFACE:-enp42s0}"
TARGET="${TARGET:-162.159.128.233}"
DPORT="${DPORT:-443}"
CIDR="${CIDR:-$TARGET/32}"
TTL="${TTL:-3}"
# Имя в подделке ClientHello. Российское — намеренно: ТСПУ глубоко разбирает
# заблокированные ресурсы и почти не трогает трафик к российским площадкам
# (те же CDN и AS, поломка сломала бы слишком многое). Подделка с
# российским именем выглядит для DPI как рутина. Заблокированное имя в
# подделке, наоборот, читается как «здесь спрятали» и вызывает агрессию.
# Подставляется только в подделку, настоящий ClientHello не трогается.
SNI="${SNI:-vk.ru}"
MARK="${MARK:-0x4d5a}"
REQUESTS="${REQUESTS:-15}"
DURATION="${DURATION:-25}"

LAYER_LOG="$(mktemp)"; DUMP_LOG="$(mktemp)"
LAYER_PID=""; DUMP_PID=""

cleanup() {
    for p in "$LAYER_PID" "$DUMP_PID"; do
        [[ -n "$p" ]] && kill "$p" 2>/dev/null
    done
    wait 2>/dev/null
}
trap cleanup EXIT INT TERM

echo "===================================================================="
echo " слой против tcpdump.  цель $CIDR:$DPORT  TTL=$TTL  имя «$SNI»"
echo "===================================================================="

# tcpdump: что реально идёт к цели. Считаем TCP-пакеты с установленным SYN/ACK,
# то есть фактические рукопожатия, а не шум.
sudo -n timeout "$DURATION" tcpdump -n -i "$IFACE" -l \
    "host $TARGET and tcp port 443 and (tcp[tcpflags] & (tcp-syn|tcp-ack) != 0)" \
    >"$DUMP_LOG" 2>/dev/null &
DUMP_PID=$!

sudo -n "$BIN" --iface "$IFACE" --cidr "$CIDR" --dport 443 \
     --fake-sni "$SNI" --ttl "$TTL" --mark "$MARK" >"$LAYER_LOG" 2>&1 &
LAYER_PID=$!
sleep 2

if ! kill -0 "$LAYER_PID" 2>/dev/null; then
    echo "слой не стартовал:"; sed 's/^/  /' "$LAYER_LOG"; exit 1
fi

# Трафик к Discord: без него рукопожатий не будет и измерять нечего.
for ((i = 1; i <= REQUESTS; i++)); do
    curl -s -o /dev/null -m 8 "https://discord.com/" 2>/dev/null
    sleep 0.4
done
sleep 3

cleanup

echo
echo "--- что видел СЛОЙ ---------------------------------------------"
last="$(grep -a 'подделок' "$LAYER_LOG" | tail -1)"
if [[ -n "$last" ]]; then
    echo "$last" | sed -E 's/.*просмотрено ([0-9]+).*подошло ([0-9]+).*ClientHello ([0-9]+).*подделок ([0-9]+).*/  просмотрено=\1  подошло=\2  ClientHello=\3  подделок=\4/' | sed 's/^/ /'
else
    echo "  счётчиков нет"
fi
grep -a -E 'разбор пакетов|адреса, куда|^      [0-9]' "$LAYER_LOG" | tail -12 | sed 's/^/ /'

echo
echo "--- что видел TCPDUMP (независимо) ------------------------------"
syn=$(grep -ac "Flags \[S\]" "$DUMP_LOG" 2>/dev/null || echo 0)
tot=$(grep -ac "Flags" "$DUMP_LOG" 2>/dev/null || echo 0)
echo "  пакетов с флагами TCP: $tot, из них SYN: $syn"
echo "  примеры:"
grep -a "Flags" "$DUMP_LOG" | head -4 | sed 's/^/    /'

echo
echo "--- ВЕРДИКТ ------------------------------------------------------"
layer_hello="$(echo "$last" | grep -oE 'ClientHello [0-9]+' | grep -oE '[0-9]+' || echo 0)"
if [[ "$syn" -gt 0 && "${layer_hello:-0}" -eq 0 ]]; then
    echo "  РАСХОЖДЕНИЕ: tcpdump видит рукопожатия, слой — нет."
    echo "  Значит виноват слой, а не сеть."
elif [[ "$syn" -eq 0 ]]; then
    echo "  РУКОПОЖАТИЙ НЕТ ВООБЩЕ: tcpdump тоже ничего не видит."
    echo "  Тогда дело не в разборе, а в том, что трафик к цели не идёт."
else
    echo "  СОШЛОСЬ: слой увидел столько же рукопожатий, сколько tcpdump."
fi
echo "===================================================================="

rm -f "$LAYER_LOG" "$DUMP_LOG"
