#!/bin/bash
# minizapret Start Script — Plugin Architecture v3.0

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="$ROOT_DIR/build/bin/minizapret"
PLUGS_DIR="$ROOT_DIR/build/bin/plugs"
PLUGIN="${1:-discord}"

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "       🚀 minizapret (plugin system)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Проверка прав
echo -e "${YELLOW}[CHECK] ${NC}Проверка прав запуска..."
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}⚠️  minizapret требует sudo для bind порта 53!${NC}"
    echo -e "${RED}Пожалуйста, запустите через: sudo $0${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Вы запущены от root${NC}"

mkdir -p "$ROOT_DIR/logs"

# Проверка бинарника
if [ ! -f "$BIN" ]; then
    echo -e "${RED}❌ Бинарник не найден: $BIN${NC}"
    echo -e "${YELLOW}Соберите: sudo make core${NC}"
    exit 1
fi

# Проверка плагина
PLUGIN_FILE="$PLUGS_DIR/${PLUGIN}.xo"
if [ ! -f "$PLUGIN_FILE" ]; then
    echo -e "${YELLOW}⚠️  Плагин $PLUGIN не найден. Доступные:${NC}"
    if [ -d "$PLUGS_DIR" ]; then
        for f in "$PLUGS_DIR"/*.xo; do
            [ -f "$f" ] && echo "  • $(basename "$f" .xo)"
        done
    else
        echo -e "${RED}  Папка plugins не найдена. Соберите: sudo make plugs${NC}"
    fi
    echo ""
    echo -e "${YELLOW}Соберите плагины: sudo make plugs${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Плагин найден: ${PLUGIN}.xo${NC}"

# Запуск
echo ""
echo -e "${YELLOW}[START] ${NC}Запуск minizapret (plugin: ${PLUGIN})..."

nohup "$BIN" inject --"$PLUGIN" > "$ROOT_DIR/logs/minizapret.log" 2>&1 &
MINIZAPRET_PID=$!

echo ""
echo -e "${GREEN}✅ minizapret запущен!${NC}"
echo -e "    PID: ${GREEN}${MINIZAPRET_PID}${NC}"
echo -e "    Plugin: ${GREEN}${PLUGIN}${NC}"
echo -e "    Порт DNS: ${GREEN}127.0.0.1:53${NC}"
echo ""

sleep 2

if ps -p $MINIZAPRET_PID > /dev/null; then
    echo -e "${GREEN}✅ minizapret активно (PID: $MINIZAPRET_PID)${NC}"
else
    echo -e "${RED}❌ minizapret не запустился! Проверьте logs/minizapret.log${NC}"
    echo ""
    tail -20 "$ROOT_DIR/logs/minizapret.log" 2>/dev/null
    exit 1
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}🎉 minizapret запущен!${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📌 Команды управления:"
echo ""
echo -e "  ${GREEN}sudo $BIN inject --${PLUGIN}${NC}"
echo -e "      (Запустить вручную)"
echo ""
echo -e "  ${GREEN}sudo $BIN list${NC}"
echo -e "      (Список плагинов)"
echo ""
echo -e "  ${YELLOW}sudo kill $MINIZAPRET_PID${NC}"
echo -e "      (Остановить)"
echo ""
echo -e "  ${YELLOW}$ROOT_DIR/logs/minizapret.log${NC}  (Лог)"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

echo $MINIZAPRET_PID > "$ROOT_DIR/logs/minizapret.pid"

stop_all() {
    echo ""
    echo -e "${YELLOW}Остановка...${NC}"
    kill $MINIZAPRET_PID 2>/dev/null || true
    pkill -TERM -x minizapret 2>/dev/null || true
    sleep 1
    pkill -KILL -x minizapret 2>/dev/null || true
}
trap stop_all SIGINT SIGTERM SIGHUP

echo -e "${GREEN}[INFO] Можно закрыть терминал!${NC}"
wait $MINIZAPRET_PID 2>/dev/null
