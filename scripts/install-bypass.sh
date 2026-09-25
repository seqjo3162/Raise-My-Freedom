#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
API="http://127.0.0.1:8080"
WEB_PID=""
IFACE=""

rollback() {
    if [ -n "$IFACE" ]; then
        resolvectl dns "$IFACE" 8.8.8.8 1.1.1.1 >/dev/null 2>&1 || true
    fi
    if [ -n "$WEB_PID" ] && kill -0 "$WEB_PID" 2>/dev/null; then
        kill "$WEB_PID" 2>/dev/null || true
    fi
}
trap rollback ERR

cd "$ROOT_DIR"
curl -fsS -m 5 -X POST "$API/api/stopall" >/dev/null 2>&1 || true
make -j1 core plugs webui
test -x "$ROOT_DIR/build/bin/minizapret"
test -x "$ROOT_DIR/build/bin/minizapret-web"

for pid in $(ps -eo pid,cmd | awk '/[m]inizapret plugin --/ {print $1}'); do kill "$pid" 2>/dev/null || true; done
for pid in $(ps -eo pid,cmd | awk '/[m]inizapret proxy/ {print $1}'); do kill "$pid" 2>/dev/null || true; done
for pid in $(ps -eo pid,cmd | awk '/[m]inizapret-web/ {print $1}'); do kill "$pid" 2>/dev/null || true; done
pkill -KILL -x minizapret 2>/dev/null || true
pkill -KILL -x minizapret-web 2>/dev/null || true
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if ! pgrep -x minizapret >/dev/null 2>&1; then break; fi
    sleep 1
done

for chain in GITHUB_BYPASS DISCORD_BYPASS VRCHAT_BYPASS GOOGLE_YT_BYPASS XCOM_BYPASS SPEEDTEST_BYPASS ACTIVISION_BYPASS BATTLENET_BYPASS ELECTRONICARTS_BYPASS EPICGAMES_BYPASS ROBLOX_BYPASS SOUNDCLOUD_BYPASS STEAM_BYPASS TWITCH_BYPASS MINIZAPRET_DNS; do
    iptables -t nat -D OUTPUT -j "$chain" 2>/dev/null || true
    iptables -t nat -F "$chain" 2>/dev/null || true
    iptables -t nat -X "$chain" 2>/dev/null || true
done

mkdir -p "$ROOT_DIR/logs"
nohup env MINIZAPRET_ROOT="$ROOT_DIR" "$ROOT_DIR/build/bin/minizapret-web" >"$ROOT_DIR/logs/minizapret-web.log" 2>&1 &
WEB_PID=$!

LOG="$ROOT_DIR/logs/minizapret-web.log"

ready=0
for _ in $(seq 1 30); do
    if curl -fsS "$API/api/info" >/dev/null 2>&1; then
        ready=1
        break
    fi
    if ! kill -0 "$WEB_PID" 2>/dev/null; then
        break
    fi
    sleep 1
done
[ "$ready" -eq 1 ]

for plugin in vrchat google x speedtestbyookla; do
    curl -fsS -X POST "$API/api/start?plugin=$plugin" >/dev/null
 done

ready=0
for _ in $(seq 1 30); do
    status=$(curl -fsS "$API/api/status" 2>/dev/null || true)
    case "$status" in
        *'"proxy":true'*) ready=1; break ;;
    esac
    sleep 1
done
[ "$ready" -eq 1 ]

IFACE=$(ip route show default | awk '{print $5; exit}')
[ -n "$IFACE" ]
resolvectl dns "$IFACE" 127.0.0.1
sleep 1
dig +short +time=2 www.youtube.com
dig +short +time=2 example.com

trap - ERR
printf '%s\n' "DONE"
printf 'Веб:   %s\n' "http://127.0.0.1:8080"
printf 'Лог:   %s\n' "$LOG"
