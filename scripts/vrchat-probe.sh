#!/bin/bash
# vrchat-probe.sh — перебор вариантов доставки трафика для модуля vrchat.
#
# Переписывает webui/vrchat.conf, перезапускает плагин и проверяет реальными
# запросами. Победитель остаётся в конфиге и применяется.
#
#   sudo ./scripts/vrchat-probe.sh
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
CONF="$ROOT_DIR/webui/vrchat.conf"
API="http://127.0.0.1:8080"
CHAIN=VRCHAT_BYPASS
PROBE_HOST=speed.cloudflare.com
PROBE_BYTES=200000

c_reset=$'\033[0m'; c_ok=$'\033[0;32m'; c_err=$'\033[0;31m'; c_dim=$'\033[2m'

[ "$(id -u)" -eq 0 ] || { echo "нужны права root"; exec sudo -- "$BASH_SOURCE" "$@"; }
cd "$ROOT_DIR"

doh_ip() {
  curl -s -m 6 -H "accept: application/dns-json" \
    "https://cloudflare-dns.com/dns-query?name=$1&type=A" |
    python3 -c "import sys,json;d=json.load(sys.stdin);print(' '.join(a['data'] for a in d.get('Answer',[]) if a['type']==1))" 2>/dev/null |
    awk '{print $1}'
}

wait_relay() {
  for _ in $(seq 1 25); do
    ss -ltn 2>/dev/null | grep -q ":18444 " && return 0
    sleep 0.4
  done
  return 1
}

write_conf() {  # write_conf use_relay chunk pause_ms idle_sec
  cat > "$CONF" <<EOF
# Вариант доставки трафика для vrchat. Подбирается scripts/vrchat-probe.sh
use_relay=$1
relay_chunk=$2
relay_pause_ms=$3
relay_idle_sec=$4
EOF
}

restart_plugin() {
  curl -fsS -m 5 -X POST "$API/api/stop?plugin=vrchat" >/dev/null 2>&1 || true
  sleep 0.5
  curl -fsS -m 5 -X POST "$API/api/start?plugin=vrchat" >/dev/null 2>&1 || true
  if [ "$USE_RELAY" = 1 ]; then wait_relay || return 1; fi
  return 0
}

# 1 — ответ пришёл целиком
probe_net() {
  local out size
  out="$(mktemp)"
  size="$(curl -s -o "$out" -m 8 -w '%{size_download}' \
    --resolve "$PROBE_HOST:443:$PROBE_IP" \
    "https://$PROBE_HOST/__down?bytes=$PROBE_BYTES" 2>/dev/null || echo 0)"
  rm -f "$out"
  [ "$size" -eq "$PROBE_BYTES" ] && echo 1 || echo 0
}

probe_config() {   # цельный JSON конфига VRChat
  local out; out="$(mktemp)"
  curl -s -o "$out" -m 8 -A "Mozilla/5.0" \
    "https://api.vrchat.cloud/api/1/config" 2>/dev/null || true
  local ok=0
  python3 -c "import json,sys;json.load(open(sys.argv[1]))" "$out" 2>/dev/null && ok=1
  rm -f "$out"
  echo "$ok"
}

probe_big() {      # крупная страница ~195 КБ, проверяем закрытый </html>
  local out; out="$(mktemp)"
  curl -s -o "$out" -m 10 -A "Mozilla/5.0" \
    "https://docs.vrchat.com/" 2>/dev/null || true
  local ok=0
  if [ -s "$out" ] && tail -c 80 "$out" | grep -q '</html>'; then ok=1; fi
  rm -f "$out"
  echo "$ok"
}

report() {  # report <имя> <config> <big>
  printf '  %-24s конфиг %-8s крупный %s\n' "$1" \
    "$([ "$2" = 1 ] && echo "${c_ok}OK${c_reset}" || echo "${c_err}обрезан${c_reset}")" \
    "$([ "$3" = 1 ] && echo "${c_ok}OK${c_reset}" || echo "${c_err}обрезан${c_reset}")"
}

[ -f "$ROOT_DIR/build/bin/plugs/vrchat.xo" ] || { echo "сначала: ./run.sh build"; exit 1; }
curl -fsS -m 5 "$API/api/info" >/dev/null 2>&1 || {
  echo "веб не работает — сначала: ./run.sh start"; exit 1; }

PROBE_IP="$(doh_ip "$PROBE_HOST")"
[ -n "$PROBE_IP" ] || { echo "не удалось разрешить $PROBE_HOST через DoH"; exit 1; }

echo "Сеть напрямую, без rmf: $PROBE_HOST @ $PROBE_IP"
curl -s -o /dev/null -m 8 -w "  получено %{size_download} байт из $PROBE_BYTES\n" \
  --resolve "$PROBE_HOST:443:$PROBE_IP" \
  "https://$PROBE_HOST/__down?bytes=$PROBE_BYTES" || true
echo ""

printf '  %-24s %-16s %s\n' "вариант" "конфиг" "крупный ответ"
printf '  %-24s %-16s %s\n' "------------------------" "--------------" "--------"

best=""; best_conf=""
try() {  # try <имя> <use_relay> <chunk> <pause_ms> <idle_sec>
  local name="$1"
  USE_RELAY="$2"
  write_conf "$2" "$3" "$4" "$5"
  if ! restart_plugin; then
    report "$name" 0 0
    return 1
  fi
  local ok_cfg ok_big
  ok_cfg="$(probe_config)"
  ok_big="$(probe_big)"
  report "$name" "$ok_cfg" "$ok_big"
  if [ "$ok_cfg" = 1 ] && [ "$ok_big" = 1 ]; then
    best="$name"; best_conf="$(cat "$CONF")"
    printf '  %s<- победитель, перебор остановлен%s\n' "$c_ok" "$c_reset"
    return 0
  fi
  return 1
}

run_all() {
  if [ -z "$best" ]; then try "0 релей выключен"   0 0    0 0 || true; fi
  if [ -z "$best" ]; then try "1 релей как есть"    1 0    0 0 || true; fi
  if [ -z "$best" ]; then try "2 релей чанк 1400"   1 1400 0 0 || true; fi
  if [ -z "$best" ]; then try "3 релей чанк 512"    1 512  1 0 || true; fi
  if [ -z "$best" ]; then try "4 релей idle 120"    1 0    0 120 || true; fi
}
run_all

echo ""
if [ -n "$best" ]; then
  printf '%s\n' "$best_conf" > "$CONF"
  restart_plugin || true
  echo "Применён вариант: $best"
  grep -v '^#' "$CONF" | sed 's/^/  /'
else
  write_conf 0 0 0 0
  restart_plugin || true
  echo "Ни один вариант не прошёл."
fi
