#!/bin/bash
# Прогон модулей через доктор: старт, решение по SNI, проверка dig.
# Работает через веб-API, sudo не нужен.
set -uo pipefail
cd "$(dirname "$0")/.."
API="http://127.0.0.1:8080"

if ! curl -fsS -m 5 "$API/api/info" >/dev/null 2>&1; then
    echo "веб не отвечает на $API — сначала sudo ./run.sh start" >&2
    exit 1
fi

# Модули на site_bypass — у них есть решение доктора. У остальных своя логика.
# Списки не пересекаются и вместе покрывают все 17 модулей сборки: раньше
# google и vrchat попадали в оба, а x, soundcloud, speedtestbyookla и
# electronicarts не попадали ни в один, и доктор молча их пропускал.
TEMPLATE="activision battlenet electronicarts epicgames github roblox soundcloud spotify steam twitch"
OWN="cloudflaredns discord google speedtestbyookla telegram vrchat x"

# Решение доктора отдаёт сам веб обычным текстом — парсить JSON не нужно.
verdict_of() {  # verdict_of <метка>
    local label="$1" out=""
    for _ in 1 2 3; do
        out="$(curl -fsS -m 5 "$API/api/verdict?plugin=$label" 2>/dev/null)"
        case "$out" in
            ""|"решения пока нет"*) ;;
            *) break ;;
        esac
        sleep 0.4
    done
    printf '%s' "$out" | head -1 | cut -c1-70
}

printf '%-16s %-6s %s\n' "модуль" "старт" "решение"
printf '%-16s %-6s %s\n' "----------------" "------" "----------------------------------------------------------------"

for p in $TEMPLATE; do
  label="$(printf '%s' "$p" | tr '[:lower:]' '[:upper:]')"
  curl -fsS -m 5 -X POST "$API/api/stop?plugin=$p" >/dev/null 2>&1
  sleep 0.3
  # старт с пробами занимает до ~10 с, поэтому таймаут щедрый
  ok="$(curl -fsS -m 60 -X POST "$API/api/start?plugin=$p" 2>/dev/null)"
  case "$ok" in *'"ok":true'*) st="ok" ;; *) st="нет" ;; esac
  printf '%-16s %-6s %s\n' "$p" "$st" "$(verdict_of "$label")"
done

echo ""
echo "модули со своей логикой (доктор не применяется):"
for p in $OWN; do
  curl -fsS -m 5 -X POST "$API/api/stop?plugin=$p" >/dev/null 2>&1
  sleep 0.3
  ok="$(curl -fsS -m 20 -X POST "$API/api/start?plugin=$p" 2>/dev/null)"
  case "$ok" in *'"ok":true'*) st="ok" ;; *) st="нет" ;; esac
  printf '  %-16s %s\n' "$p" "$st"
done
