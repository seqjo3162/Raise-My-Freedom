#!/bin/bash
# Перебор вариантов обхода для модуля discord.
#
# Меряет не «открылся ли», а ДОКАЧАЛАСЬ ЛИ СТРАНИЦА: обрыв на середине
# передачи — это отдельный класс отказа, и его видно только по размеру
# скачанного. Соединение, которое «работает», но обрывается на 16 КБ,
# не считается успехом.
#
# Ядро и веб не трогаются: меняется только конфиг модуля и его перезапуск.
#
# Конфиг правится построчно, а не пересоздаётся: раньше here-doc затирал все
# ключи, кроме восьми, и настройки, которых скрипт не знает (multi_parts,
# relay_cidr, probe_pins, shift_sni), молча терялись. Исходник сначала
# копируется в mktemp, и trap возвращает его при любом выходе, включая Ctrl-C.

set -uo pipefail

cd "$(dirname "$0")/.." || { echo "не удалось перейти в корень проекта"; exit 1; }
CONF="webui/discord.conf"
API="http://127.0.0.1:8080"
URL="https://discord.com/"
API_URL="https://discord.com/api/v9/experiments"
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/140.0 Safari/537.36"
BASE_TIMEOUT=12

[ -f "$CONF" ] || { echo "нет файла $CONF — модуль discord его и так не читает"; exit 1; }

BACKUP="$(mktemp)" || { echo "mktemp не сработал"; exit 1; }
cp -a "$CONF" "$BACKUP" || { echo "не удалось сохранить $CONF"; exit 1; }
[ -s "$BACKUP" ] || { echo "backup пустой — не продолжаю, чтобы не затереть конфиг"; exit 1; }

# KEEP=1 означает «найденный вариант оставляем», и тогда trap restore не
# срабатывает. Во всех остальных случаях, включая Ctrl-C, исходник возвращается.
KEEP=0
restore() { [ "$KEEP" = "1" ] && return 0; cp -f "$BACKUP" "$CONF" 2>/dev/null; }
cleanup() { restore; rm -f "$BACKUP"; }
trap cleanup EXIT INT TERM

# set_conf key val — заменить один ключ, остальные строки не трогать.
set_conf() {
    local key="$1" val="$2" tmp
    tmp="$(mktemp)" || return 1
    if grep -q "^${key}=" "$CONF"; then
        awk -v k="$key" -v v="$val" 'BEGIN{FS="="} $1==k{print k "=" v; next} {print}' \
            "$CONF" >"$tmp"
    else
        cat "$CONF" >"$tmp"
        printf '%s=%s\n' "$key" "$val" >>"$tmp"
    fi
    mv -f "$tmp" "$CONF"
}

# apply_conf <split_ch> <frag_delay> <frag_first> <split_data> <split_size>
#            <split_delay> <chunk> <pause> <no_split_hs>
apply_conf() {
    set_conf use_relay 1 &&
    set_conf split_ch "$1" &&
    set_conf frag_delay_ms "$2" &&
    set_conf frag_first_seg "$3" &&
    set_conf split_data "$4" &&
    set_conf split_size "$5" &&
    set_conf split_delay_ms "$6" &&
    set_conf relay_chunk "$7" &&
    set_conf relay_pause_ms "$8" &&
    set_conf no_split_hs "$9"
}

restart_module() {
    curl -fsS -m 15 -X POST "$API/api/stop?plugin=discord" >/dev/null 2>&1
    sleep 2
    curl -fsS -m 40 -X POST "$API/api/start?plugin=discord" >/dev/null 2>&1
    sleep 4
}

# Меряем НЕ «открылась ли страница», а доехал ли файл целиком. Прежний
# критерий (код 200 и размер больше 100 КБ на discord.com/) был ненадёжен:
# обрыв на ~20 КБ давал «успех» на куче нерабочих конфигов, а anti-bot
# заглушка на /app вообще не зависит от обхода. Теперь источник истины один —
# scripts/discord-asset-check.sh, который сверяет размер с Content-Length.
ORACLE="scripts/discord-asset-check.sh"

# Печатает "<доставлено> <ожидалось>" по главному оракулу styles.css.
measure() {
    out="$(TIMEOUT=$BASE_TIMEOUT "$ORACLE" --quiet 2>/dev/null)"
    if [ "$out" = "OK" ]; then echo "OK 0 0"; return 0; fi
    echo "${out#FAIL }"
}

api_ok() {
    curl -s -o /dev/null -m 10 -w "%{http_code}" -A "$UA" "$API_URL" 2>/dev/null
}

echo "=== перебор вариантов discord ==="
echo "    исходный конфиг сохранён, вернётся автоматически"
BEST=""
N=0

# Порядок — от самого вероятного к наименее вероятному.
# split_data=1 (дробление записей данных) ИСКЛЮЧЁН намеренно.
# Измерено 2026-09-27 на стенде реля без ТСПУ: 10 прогонов из 10 дают
# "decryption failed or bad record mac", при split_data=0 — 10 из 10
# побайтово верно. Рель портит поток, а не перекадрирует его. Раньше эти
# варианты стояли в списке и могли быть выбраны как «лучшие».
#
# Варианты с split_ch=0 тоже оставлены: разрыв SNI и целый поток на этой
# сети взаимоисключающи, и свип должен уметь это показать, а не знать заранее.
VARIANTS=(
  "1 30 20 0 512 0 0 0 1"      # текущий рабочий для рукопожатия
  "1 30 1  0 512 0 0 0 1"      # первый сегмент 1 байт
  "1 50 1  0 512 0 0 0 1"      # пауза больше
  "1 10 1  0 512 0 0 0 1"
  "1 0  1  0 512 0 0 0 1"      # без паузы между сегментами
  "1 30 1  0 512 0 1024 0 1"   # мелкие порции данных
  "1 30 1  0 512 0 512 2 1"    # + пауза между порциями
  "1 30 1  0 512 0 0 0 0"      # резать и ответные handshake-записи
  "0 30 20 0 512 0 0 0 1"      # вовсе не рвать SNI (контроль: поток цел, обхода нет)
  "0 30 1  0 512 0 0 0 1"
)

for v in "${VARIANTS[@]}"; do
  set -- $v
  N=$((N+1))
  printf "  %2d/%d  ch=%s d=%3sms seg=%2s data=%s size=%3s dp=%2sms chunk=%4s pause=%s hs=%s" \
    "$N" "${#VARIANTS[@]}" "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9"
  apply_conf "$@" || { echo "  ошибка записи конфига, прерываюсь"; break; }
  restart_module
  A=$(api_ok)
  R=$(measure)
  GOT=$(printf '%s' "$R" | cut -d' ' -f1)
  WANT=$(printf '%s' "$R" | cut -d' ' -f2)
  printf "  → api=%s styles.css %s/%s Б\n" "$A" "$GOT" "$WANT"
  # Успех только когда файл доехал целиком. «Код 200 и что-то скачалось»
  # больше не считается успехом.
  if [ "$GOT" = "$WANT" ] && [ -n "$WANT" ] && [ "$WANT" != "0" ]; then
    echo "  >>> НАЙДЕНО: $v (styles.css доставлен целиком, ${GOT} Б)"
    BEST="$v"
    KEEP=1
    break
  fi
done

[ "$KEEP" = "1" ] || restart_module

echo
if [ -n "$BEST" ]; then
  echo "ИТОГ: рабочий вариант найден и оставлен в $CONF: $BEST"
else
  echo "ИТОГ: ни один вариант не дал полной загрузки страницы."
  echo "Исходный конфиг возвращён."
fi
