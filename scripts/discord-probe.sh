#!/bin/bash
# Подбор параметров релея для модуля discord.
# Переписывает webui/discord.conf, перезапускает плагин и меряет РЕАЛЬНЫЙ
# результат: цельный ли ответ discord.com/app (проверка на </html>) и жив ли
# API. Каждый вариант меряется три раза, учитывается лучший.
set -uo pipefail

cd "$(dirname "$0")/.."
CONF="webui/discord.conf"
API="http://127.0.0.1:8080"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

# Ключи, которые скрипт меняет. Остальные строки конфига — multi_parts,
# relay_cidr, probe_pins, shift_sni, no_split_hs — раньше терялись: here-doc
# пересоздавал файл целиком из восьми строк. Правим построчно.
set_conf() {
  local key="$1" val="$2" t
  t="$(mktemp)" || return 1
  if grep -q "^${key}=" "$CONF"; then
    awk -v k="$key" -v v="$val" 'BEGIN{FS="="} $1==k{print k "=" v; next} {print}' "$CONF" >"$t"
  else
    cat "$CONF" >"$t"; printf '%s=%s\n' "$key" "$val" >>"$t"
  fi
  mv -f "$t" "$CONF"
}

c_ok=$'\033[0;32m'; c_err=$'\033[0;31m'; c_dim=$'\033[2m'; c_reset=$'\033[0m'

[ "$(id -u)" -eq 0 ] || { echo "нужны права root"; exec sudo -- "$BASH_SOURCE" "$@"; }

apply() {  # apply <split_ch> <frag_delay> <frag_first> <split_data> <split_size> <split_delay> <chunk> <pause>
  set_conf use_relay 1       && set_conf split_ch "$1" &&
  set_conf frag_delay_ms "$2" && set_conf frag_first_seg "$3" &&
  set_conf split_data "$4"    && set_conf split_size "$5" &&
  set_conf split_delay_ms "$6" && set_conf relay_chunk "$7" &&
  set_conf relay_pause_ms "$8"
  curl -fsS -m 5 -X POST "$API/api/stop?plugin=discord" >/dev/null 2>&1
  sleep 0.6
  curl -fsS -m 5 -X POST "$API/api/start?plugin=discord" >/dev/null 2>&1
  sleep 1.2
}

# Меряем доезжание файла целиком, а не «открылась ли страница».
# Прежний критерий — заглушка anti-bot на /app и наличие </html> — не зависел от
# обхода: curl всегда получал ~15 КБ мусора и всегда находил </html>.
# Теперь источник истины — scripts/discord-asset-check.sh (сверка с
# Content-Length), тот же, что и в discord-sweep.sh.
ORACLE="scripts/discord-asset-check.sh"

# Возвращает "<лучший_доставленный> <api_code> <1|0 цельный>"
measure() {
  local best=0 api=000 whole=0 n out got want
  for n in 1 2 3; do
    out="$(TIMEOUT=12 "$ORACLE" --quiet 2>/dev/null)"
    if [ "$out" = "OK" ]; then got=999999999; want=999999999
    else got="${out#FAIL }"; got="${got%% *}"; want="${out##* }"
    fi
    [ "$got" -gt "$best" ] 2>/dev/null && best="$got"
    [ "$want" != "0" ] && [ "$got" = "$want" ] && whole=1
  done
  api="$(curl -s -o /dev/null -m 8 -w '%{http_code}' -A "Mozilla/5.0" \
    "https://discord.com/api/v9/gateway" 2>/dev/null || echo 000)"
  echo "$best $api $whole"
}

printf '  %-32s %-11s %-7s %s\n' "вариант" "app, байт" "api" "итог"
printf '  %-32s %-11s %-7s %s\n' "--------------------------------" "-----------" "-------" "----"

best=0; best_name=""; best_conf=""
try() {  # try <имя> <аргументы apply...>
  local name="$1"; shift
  apply "$@"
  local out app api whole verdict
  out="$(measure)"
  app="${out%% *}"; rest="${out#* }"; api="${rest%% *}"; whole="${rest##* }"
  if [ "$whole" = 1 ]; then
    verdict="${c_ok}/app ЦЕЛЬНЫЙ${c_reset}"
    # Копируем только те строки, которые скрипт меняет. Раньше сюда уходил весь
    # конфиг целиком, и «лучший» вариант затирал ключи, которых скрипт не знает.
    if [ "$app" -gt "$best" ]; then
      best="$app"; best_name="$name"
      best_conf="$(grep -E '^(use_relay|split_ch|frag_delay_ms|frag_first_seg|split_data|split_size|split_delay_ms|relay_chunk|relay_pause_ms)=' "$CONF")"
    fi
  elif [ "$api" = "200" ]; then
    verdict="${c_dim}api жив, /app обрезан${c_reset}"
  else
    verdict="${c_err}api мёртв${c_reset}"
  fi
  printf '  %-32s %-11s %-7s %b\n' "$name" "$app" "$api" "$verdict"
}

try "базовый 30мс/20Б"        1 30  20  0 512 0   0    0
# split_data=1 НЕ ПРОВЕРЯЕТСЯ: дробление записей данных портит поток, клиент
# получает "decryption failed or bad record mac" (измерено 10 из 10 на стенде
# реля без ТСПУ). Раньше эти варианты были в списке и могли выиграть.
# try "данные: 1400Б"            1 30  20  1 1400 0  0    0
# try "данные: 512Б"             1 30  20  1 512  0   0    0
# try "данные: 512Б + 1мс"       1 30  20  1 512  1   0    0
# try "данные: 256Б"             1 30  20  1 256  0   0    0
# try "данные: 128Б + 1мс"       1 30  20  1 128  1   0    0
# try "данные: 64Б + 2мс"        1 30  20  1 64  2    0    0
# try "данные: 1400Б, первый 5Б" 1 30  5   1 1400 0  0    0
try "без разрыва SNI (контроль)" 0 0 20  0 512 0   0    0

echo ""
if [ "$best" -gt 0 ] && [ -n "$best_conf" ]; then
  # Накатываем только сохранённые ключи, остальное в файле не трогаем.
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    set_conf "${line%%=*}" "${line#*=}"
  done <<<"$best_conf"
  curl -fsS -m 5 -X POST "$API/api/stop?plugin=discord" >/dev/null 2>&1; sleep 0.6
  curl -fsS -m 5 -X POST "$API/api/start?plugin=discord" >/dev/null 2>&1
  echo "Лучший: $best_name ($best байт, /app цельный) — оставлен в $CONF"
else
  echo "Ни один вариант не отдал /app целиком — оставляю базовый."
  apply 1 30 20 0 512 0 0 0
fi
