#!/bin/bash
# cleanup.sh — Удаляет ТОЛЬКО то, что создал rmf
#
# Удаляются родные цепочки проекта (*_BYPASS, RMF_DNS) и jumps на них
# из цепочки OUTPUT. Цепочки OUTPUT в nat/mangle/raw/filter НЕ флашатся —
# посторонние правила (docker, rmf-socks, tproxy и т.п.) остаются.
# Список цепочек взят из webui/server.c (обработчик /api/flush) и install-bypass.sh.

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
LOG_DIR="$ROOT_DIR/logs"

CHAINS=(
    GITHUB_BYPASS DISCORD_BYPASS VRCHAT_BYPASS GOOGLE_YT_BYPASS XCOM_BYPASS SPEEDTEST_BYPASS
    JINXXY_BYPASS NINEGAG_BYPASS INSTAGRAM_BYPASS MYJELLYFIN_BYPASS NETFLIX_BYPASS
    REDDIT_BYPASS SPOTIFY_BYPASS TIKTOK_BYPASS TWITCH_BYPASS VK_BYPASS
    XVIDEOS_BYPASS YEPEDIA_BYPASS ACTIVISION_BYPASS BATTLENET_BYPASS
    ELECTRONICARTS_BYPASS EPICGAMES_BYPASS ROBLOX_BYPASS SOUNDCLOUD_BYPASS
    STEAM_BYPASS RMF_DNS
)

TABLES=(nat mangle filter raw)

if [ "$EUID" -ne 0 ]; then
    echo "❌ Нужен root: sudo $0"
    exit 1
fi

if pgrep -x rmf >/dev/null 2>&1 || pgrep -x rmf-web >/dev/null 2>&1; then
    echo "⚠️  rmf ещё работает — он пересоздаст цепочки сразу после очистки."
    echo "   Остановить:  sudo pkill -TERM -x rmf && sudo pkill -TERM -x rmf-web"
    echo ""
fi

mkdir -p "$LOG_DIR"
SNAPSHOT="$LOG_DIR/iptables-before-cleanup.rules"
iptables-save > "$SNAPSHOT" 2>/dev/null && echo "📄 Снапшот правил сохранён: $SNAPSHOT"

removed=0
for table in "${TABLES[@]}"; do
    iptables -t "$table" -S OUTPUT >/dev/null 2>&1 || continue
    for chain in "${CHAINS[@]}"; do
        iptables -t "$table" -S "$chain" >/dev/null 2>&1 || continue
        while iptables -t "$table" -C OUTPUT -j "$chain" >/dev/null 2>&1; do
            iptables -t "$table" -D OUTPUT -j "$chain" >/dev/null 2>&1 || break
        done
        iptables -t "$table" -F "$chain" >/dev/null 2>&1
        if iptables -t "$table" -X "$chain" >/dev/null 2>&1; then
            echo "  ✓ удалена [$table] $chain"
            removed=$((removed + 1))
        fi
    done
done

echo ""
if [ "$removed" -eq 0 ]; then
    echo "ℹ️  Цепочек rmf не найдено — ничего не менялось."
else
    echo "✅ Удалено цепочек: $removed (посторонние правила не тронуты)"
fi

current_dns=$(resolvectl dns "$(ip route show default | awk '{print $5; exit}')" 2>/dev/null | tr '\n' ' ')
echo ""
echo "DNS на интерфейсе: ${current_dns:-не задан}"
case "$current_dns" in
    *127.0.0.1*)
        echo "⚠️  DNS указывает на 127.0.0.1, а rmf больше не запущен."
        echo "   Вернуть публичные:  sudo resolvectl dns $(ip route show default | awk '{print $5; exit}') 8.8.8.8 1.1.1.1"
        ;;
esac
