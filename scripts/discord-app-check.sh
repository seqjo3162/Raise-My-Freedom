#!/usr/bin/env bash
# Проверка клиента Discord настоящим браузером.
#
# Почему curl недостаточен: он получает от Discord заглушку anti-bot ~15 КБ
# независимо от того, работает ли обход. Значит «200» от curl ничего не
# говорит о приложении. Настоящий Chrome грузит страницу, выполняет
# JavaScript и показывает, доходит ли дело до логина и списка каналов.
#
# Скрипт НИЧЕГО не меняет в системе: только запускает браузер и читает
# страницу. Модули не перезапускаются, правила не меняются.

set -uo pipefail

CHROME="${CHROME:-/usr/bin/google-chrome}"
PROFILE="$(mktemp -d)"
OUT="$(mktemp)"
URL="${URL:-https://discord.com/app}"
WAIT="${WAIT:-35}"
SHOT="${SHOT:-}"

cleanup() { rm -rf "$PROFILE" "$OUT" 2>/dev/null; }
trap cleanup EXIT

echo "===================================================================="
echo " Настоящий браузер: $URL"
echo "===================================================================="

# Ключевой признак работающего клиента: в разметке есть webpack-бандл
# Discord и присутствует id пользователя. У заглушки anti-bot нет ни того,
# ни другого — отдаётся один большой текст без скриптов приложения.
timeout "$((WAIT + 25))" "$CHROME" \
    --headless=new --disable-gpu --no-sandbox --no-first-run \
    --user-data-dir="$PROFILE" \
    --virtual-time-budget="$((WAIT * 1000))" \
    --dump-dom "$URL" >"$OUT" 2>/dev/null

bytes=$(wc -c <"$OUT")
echo
echo "  размер полученной страницы: $bytes байт"

sni=0; app_id=0; scripts=0; errors=0
grep -q 'window\.Sentry'            "$OUT" && sni=1
grep -qE 'data-react-profilingroot' "$OUT" && app_id=1
grep -qE 'client[0-9a-z]{10,}\.js'  "$OUT" && scripts=1
grep -qiE 'ERR_|error|unavailable'  "$OUT" && errors=1

printf "  %-34s %s\n" "признак бота Sentry:"   "$([[ $sni -eq 1 ]] && echo 'есть' || echo 'нет')"
printf "  %-34s %s\n" "корень приложения React:" "$([[ $app_id -eq 1 ]] && echo 'есть' || echo 'нет')"
printf "  %-34s %s\n" "бандлы Discord найдены:"  "$([[ $scripts -eq 1 ]] && echo 'да' || echo 'нет')"

echo
if [[ $sni -eq 1 && $app_id -eq 0 ]]; then
    echo "  ВЕРДИКТ: anti-bot. Приложение не грузилось, страницу отдал фильтр."
    echo "  Это НЕ показатель работы модуля: так curl отвечает всегда."
elif [[ $app_id -eq 1 || $scripts -eq 1 ]]; then
    echo "  ВЕРДИКТ: приложение загрузилось — разметка и бандлы на месте."
    echo "  Дальше нужен логин, это уже не автоматическая проверка."
else
    echo "  ВЕРДИКТ: приложение не загрузилось."
    echo "  Страница получена, но ни бандлов, ни корня приложения нет."
fi

if [[ -n "$SHOT" ]]; then
    timeout 40 "$CHROME" --headless=new --disable-gpu --no-sandbox \
        --user-data-dir="$PROFILE" --window-size=1280,900 \
        --screenshot="$SHOT" "$URL" 2>/dev/null
    [[ -f "$SHOT" ]] && echo "  снимок сохранён: $SHOT"
fi
echo "===================================================================="
