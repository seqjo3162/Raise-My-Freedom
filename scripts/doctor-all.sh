#!/bin/bash
# Прогон модулей через доктор: старт, решение по SNI, проверка dig.
# Работает через веб-API, sudo не нужен.
set -uo pipefail
cd "$(dirname "$0")/.."
API="http://127.0.0.1:8080"

# Без python3 разбор логов молча возвращал пустоту, и колонка «решение»
# выглядела бы как «всё хорошо» при сломанном выводе.
if ! command -v python3 >/dev/null; then
    echo "нужен python3: sudo apt install python3" >&2
    exit 1
fi
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

verdict_of() {  # verdict_of <метка>
  local label="$1" out=""
  for _ in 1 2 3; do
    out="$(curl -s -m 5 "http://127.0.0.1:8080/api/logs?limit=400" 2>/dev/null ||
           curl -s -m 5 "http://127.0.0.1:8080/api/logs?limit=400" 2>/dev/null)" && \
    out="$(printf '%s' "$out" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
except Exception:
    sys.exit(0)
lines=d if isinstance(d,list) else d.get('lines',[])
for l in lines:
    t=str(l.get('text') if isinstance(l,dict) else l)
    if '[$label]' in t and ('проверка SNI' in t or 'домен ' in t or 'адрес выброшен' in t or 'недоступен' in t):
        print(t.split(']',1)[1].strip())
" 2>/dev/null)"
    [ -n "$out" ] && break
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
