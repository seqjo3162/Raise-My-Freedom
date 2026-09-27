#!/bin/bash
# Проверка обхода Discord по настоящим ассетам.
#
# Почему не /app и не /api: curl на /app получает от Discord anti-bot заглушку
# ~15 КБ независимо от того, работает ли обход, и код 200 не значит ничего.
# Ассеты же отдаются всегда, у них известен размер, и обрыв виден однозначно.
#
# Главный оракул — styles.css на 764 КБ. Он бьёт точно по известному феномену:
# после обхода SNI поток к Cloudflare встаёт на ~20 КБ, и мелкие файлы
# (head.js 8.5 КБ, styles.js 3.1 КБ) проходят, а большой — нет. То есть
# «head.js скачался» НЕ означает «обход работает».
#
# Вердикт строгий: размер скачанного == content-length. Любой обрыв —
# провал, даже если код 200.
#
# Ничего не меняет: правила, модули и конфиг не трогает.
set -uo pipefail

# --quiet: машинный режим для свипов. Печатает одну строку:
#   OK                       — все ассеты доставлены целиком
#   FAIL <доставлено> <ожидалось>   — поток оборван
QUIET=0
[ "${1:-}" = "--quiet" ] && QUIET=1

UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/140.0 Safari/537.36"
BASE="https://discord.com/w/assets/3ae7a3b831a56041cc902e92f73907e4e121f31d"
TIMEOUT="${TIMEOUT:-40}"

# url, подпись
ASSETS=(
  "$BASE/styles.css|styles.css (764 КБ, главный оракул)"
  "https://discord.com/webflow-scripts/head.js|head.js (8.5 КБ, контроль малого)"
  "$BASE/styles.js|styles.js (3.1 КБ, контроль малого)"
)

# Content-Length, зафиксированные 2026-09-27. Запасной вариант на случай, когда
# HEAD не доходит: без него оракул молчал бы там, где проверять нечего.
declare -A EXPECTED=(
  ["styles.css (764 КБ, главный оракул)"]=782354
  ["head.js (8.5 КБ, контроль малого)"]=8689
  ["styles.js (3.1 КБ, контроль малого)"]=3244
)

# Цвет только в терминале: в пайпах и логах ESC-последовательности — мусор.
if [ -t 1 ]; then mark=$'\033[0;31m'; okmark=$'\033[0;32m'; dim=$'\033[2m'; reset=$'\033[0m';
else mark=""; okmark=""; dim=""; reset=""; fi
err="$mark"
pass=0; fail=0; total=0
[ "$QUIET" = "1" ] || {
printf '  %-40s %-9s %-9s %-9s %s\n' "ассет" "ожидалось" "пришло" "время" "вердикт"
printf '  %-40s %-9s %-9s %-9s %s\n' "----------------------------------------" "---------" "---------" "---------" "-------"
}

for entry in "${ASSETS[@]}"; do
  url="${entry%%|*}"; name="${entry##*|}"; total=$((total+1))
  [ "$QUIET" = "1" ] && name=""
  # Ожидаемый размер: сперва HEAD, а если он не прошёл (Discord режет и
  # HEAD-запрос, и сам файл) — берём заранее записанный для этого ассета.
  head_out="$(curl -sSI -m 12 -A "$UA" "$url" 2>/dev/null)"
  want="$(printf '%s' "$head_out" | tr -d '\r' | awk 'tolower($1)=="content-length:"{print $2}' | tail -1)"
  if [ -z "$want" ] || [ "$want" = "0" ]; then
    want="${EXPECTED[$name]}"
    [ -n "$want" ] || { [ "$QUIET" = "1" ] || printf '  %-40s %-9s %-9s %-9s %s\n' "$name" "?" "-" "-" "нет эталона, пропуск"; continue; }
  fi
  read -r got tm < <(curl -sS -m "$TIMEOUT" -o /dev/null -A "$UA" \
      -w '%{size_download} %{time_total}\n' "$url" 2>/dev/null | tail -1)
  got="${got:-0}"
  if [ "$got" = "$want" ]; then
    v="ЦЕЛИКОМ"; pass=$((pass+1)); mark="$okmark"
  else
    pct=$(( got * 100 / want ))
    v="ОБРЫВ на ${pct}%"; fail=$((fail+1)); mark="$err"
  fi
  if [ "$QUIET" = "1" ]; then
    [ "$got" = "$want" ] || printf 'FAIL %s %s\n' "$got" "$want"
  else
    printf '  %-40s %-9s %-9s %-9s %b%s%b\n' "$name" "$want" "$got" "${tm:-?}" "$mark" "$v" "$reset"
  fi
done

if [ "$QUIET" = "1" ]; then
  [ "$fail" -eq 0 ] && echo "OK" || true
  exit $([ "$fail" -eq 0 ] && echo 0 || echo 1)
fi

echo
if [ "$fail" -eq 0 ]; then
  printf '  \033[0;32mВСЕ %d АССЕТОВ ДОСТАВЛЕНЫ ЦЕЛИКОМ\033[0m — поток не рвётся.\n' "$total"
else
  printf '  \033[0;31mОБОРВАНЫ: %d из %d\033[0m\n' "$fail" "$total"
  cat <<'EOF'

  Что это значит. Малые ассеты (head.js, styles.js) проходят, большой
  styles.css обрывается ~20 КБ — то есть рукопожатие проходит, а поток
  встаёт. Это и есть known-побочный эффект разрыва SNI, а не отсутствие
  обхода: без модуля styles.css не приходит вообще (0 байт).

  Чего НЕ делать: включать split_data. Дробление записей данных портит
  поток — curl получает "decryption failed or bad record mac".

  Чего НЕ делать: полагаться на shift_sni. Сдвиг регистра первой буквы
  SNI не обходит DPI (тот нечувствителен к регистру) — проверено, Discord
  перестаёт открываться совсем.

  Разрыв SNI и целый поток здесь взаимоисключающи. Если нужен и обход, и
  непрерывная загрузка — смотри слой src/desync: он работает на уровне
  IP/TCP, до сборки TLS, и поток не трогает.
EOF
fi
exit $([ "$fail" -eq 0 ] && echo 0 || echo 1)
