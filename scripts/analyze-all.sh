#!/bin/bash
# Полный анализ модулей: решение доктора, закреплённый адрес и реальная
# загрузка страницы. Работает через веб-API, sudo не нужен.
set -uo pipefail
cd "$(dirname "$0")/.."
API="http://127.0.0.1:8080"
DOMFILE="/tmp/opencode/domains.txt"
[ -f "$DOMFILE" ] || { echo "нет $DOMFILE"; exit 1; }

verdict_of() {
  local label="$1" out=""
  for _ in 1 2 3; do
    out="$(curl -s -m 5 "$API/api/logs?limit=400" 2>/dev/null | python3 -c "
import sys,json
try: d=json.load(sys.stdin)
except Exception: sys.exit(0)
lines=d if isinstance(d,list) else d.get('lines',[])
keep=[]
for l in lines:
    t=str(l.get('text') if isinstance(l,dict) else l)
    if '[$label]' in t and ('проверка SNI' in t or 'домен ' in t or 'недостижим' in t
                            or 'не разрешился' in t or 'недоступен' in t):
        keep.append(t.split(']',1)[1].strip())
print(' | '.join(keep[-3:]))
" 2>/dev/null)"
    [ -n "$out" ] && break
    sleep 0.4
  done
  printf '%s' "$out" | cut -c1-58
}

printf '%-15s %-6s %-16s %-9s %s\n' "модуль" "старт" "закреплено" "загрузка" "вывод"
printf '%-15s %-6s %-16s %-9s %s\n' "---------------" "------" "----------------" "---------" "----------------------------------------"

while IFS='|' read -r mod doms; do
  [ -n "$mod" ] || continue
  label="$(printf '%s' "$mod" | tr '[:lower:]' '[:upper:]')"
  curl -fsS -m 5 -X POST "$API/api/stop?plugin=$mod" >/dev/null 2>&1
  sleep 0.3
  ok="$(curl -fsS -m 60 -X POST "$API/api/start?plugin=$mod" 2>/dev/null)"
  case "$ok" in *'"ok":true'*) st="ok" ;; *) st="нет" ;; esac
  curl -fsS -m 5 -X POST "$API/api/stop?plugin=$mod" >/dev/null 2>&1   # адреса вернём системе
  sleep 0.2

  d1="$(printf '%s' "$doms" | cut -d, -f1)"
  pinned="$(dig +short +time=3 @127.0.0.1 "$d1" A 2>/dev/null | head -1)"
  [ -z "$pinned" ] && pinned="—"

  res="$(curl -s -o /tmp/opencode/page.html -m 10 -w '%{http_code} %{size_download}' \
         -A "Mozilla/5.0" "https://$d1/" 2>/dev/null)"
  code="$(printf '%s' "$res" | cut -d' ' -f1)"; size="$(printf '%s' "$res" | cut -d' ' -f2)"
  if [ "$code" = "200" ] && [ "${size:-0}" -gt 500 ]; then ld="200 ${size}Б"
  elif [ "$code" = "000" ]; then ld="таймаут"
  elif [ "${code:0:1}" = "2" ] || [ "${code:0:1}" = "3" ]; then ld="$code ${size}Б"
  else ld="$code"; fi

  printf '%-15s %-6s %-16s %-9s %s\n' "$mod" "$st" "$pinned" "$ld" "$(verdict_of "$label")"
done < "$DOMFILE"
