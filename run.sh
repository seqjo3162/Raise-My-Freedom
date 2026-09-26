#!/bin/bash
# run.sh — единственная точка входа. Запуск/остановка ядра, прокси и веба.
#
#   ./run.sh                 # = start
#   ./run.sh start [плагин…]  # собрать (если надо), поднять веб, стартовать плагины
#   ./run.sh stop            # остановить всё, снять цепочки rmf, вернуть DNS
#   ./run.sh restart         # stop + start
#   ./run.sh status          # что сейчас запущено
#   ./run.sh flush           # снести цепочки *_BYPASS и RMF_DNS
#   ./run.sh logs            # хвост логов
#   ./run.sh clean           # удалить бинарники
#   ./run.sh build           # принудительная пересборка
#   ./run.sh save            # снимок текущего состояния в cache/save
#   ./run.sh restore         # вернуть последний снимок и запустить
#
# Скрипт сам поднимет sudo. Права root нужны для :53 и iptables.

set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$ROOT_DIR/build/bin"
LOG_DIR="$ROOT_DIR/logs"
WEB_BIN="$BIN_DIR/rmf-web"
CORE_BIN="$BIN_DIR/rmf"
API="http://127.0.0.1:8080"
WEB_LOG="$LOG_DIR/web.log"
DEFAULT_IFACE_DNS="8.8.8.8 1.1.1.1"

# Сейв состояния перед перезагрузкой и пересборкой. Лежит ВНУТРИ папки проекта,
# чтобы ничего не писать рядом с ним: путь всегда выводится от расположения
# самого скрипта. Храним последние SAVE_KEEP снимков, старые удаляем.
SAVE_DIR="$ROOT_DIR/cache/save"
SAVE_KEEP=5

# Плагины по умолчанию. Меняй под себя или перечисли на командной строке:
#   ./run.sh start vrchat discord
# Модули по умолчанию. Набор намеренно маленький: резолв ядра делает запрос
# через DoH с fork+curl на каждый, и при большом числе модулей (их DNS-правила
# заворачивают запросы в ядро) он не выдерживает — резолв начинает отдавать
# таймауты и пропадает интернет целиком. Проверено: 4 модуля — резолв 0.0 с,
# 17 модулей — таймауты. Остальные включай по необходимости:
#   ./run.sh start google github vrchat spotify twitch steam
DEFAULT_PLUGINS=(vrchat google github)

# Цепочки rmf в таблице nat. Список один — его используют и flush, и stop.
RMF_CHAINS=(
  GITHUB_BYPASS DISCORD_BYPASS VRCHAT_BYPASS GOOGLE_YT_BYPASS
  NINEGAG_BYPASS NETFLIX_BYPASS REDDIT_BYPASS SPOTIFY_BYPASS
  TWITCH_BYPASS VK_BYPASS ROBLOX_BYPASS STEAM_BYPASS ACTIVISION_BYPASS
  BATTLENET_BYPASS EPICGAMES_BYPASS HF_BYPASS RMF_DNS
)

# Владелец файлов, которые скрипт создаёт: sudo -u $SUDO_USER, иначе текущий.
OWNER="${SUDO_USER:-$(id -un)}"
OWNER_GROUP="$(id -gn "$OWNER" 2>/dev/null || echo root)"

c_reset=$'\033[0m'; c_ok=$'\033[0;32m'; c_err=$'\033[0;31m'; c_dim=$'\033[2m'
say()  { printf '%s\n' "$*"; }
step() { printf '  %s\n' "$*"; }
ok()   { printf '  %s%s%s\n' "$c_ok" "$*" "$c_reset"; }
die()  { printf '%s%s%s\n' "$c_err" "$*" "$c_reset" >&2; exit 1; }

usage() {
  sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^#\{1,\} \{0,1\}//'
}

need_root() {
  [ "$(id -u)" -eq 0 ] && return 0
  local cmd="${1:-start}"
  case "$cmd" in
    # save и status только читают и пишут файлы проекта — sudo не нужен.
    # restore не в списке: он заканчивается start, которому root необходим.
    help|--help|-h|status|save) return 0 ;;
  esac
  say "нужны права root — перезапускаю через sudo"
  exec sudo -- "$BASH_SOURCE" "$@"
}

# chown всего, что создаёт скрипт, на пользователя-инициатора
fix_owner() {
  for d in "$ROOT_DIR/build" "$LOG_DIR" "$ROOT_DIR/webui"; do
    [ -e "$d" ] && chown -R "$OWNER:$OWNER_GROUP" "$d" 2>/dev/null || true
  done
}

# Мусор от старой сборки (minizapret) и старые логи. Идемпотентно.
# .xo модулей, которых больше нет в Makefile. Сборка их не трогает, и веб
# продолжает показывать удалённый модуль в списке — он удалялся, а плагин
# оставался. custom.xo в исключении: его собирает конструктор.
prune_plugins() {
  [ -d "$BIN_DIR/plugs" ] || return 0
  local mods xo name
  # -C печатает "Entering/Leaving directory" и переносит строку: из-за этого
  # первый и последний элементы списка не попадали в " имя " и удалялись.
  mods=" $(make --no-print-directory -C "$ROOT_DIR" list-modules 2>/dev/null | tr '\n' ' ') "
  [ -n "$mods" ] || return 0
  for xo in "$BIN_DIR"/plugs/*.xo; do
    [ -e "$xo" ] || continue
    name="$(basename "$xo" .xo)"
    [ "$name" = custom ] && continue        # его собирает конструктор
    case "$mods" in
      *" $name "*) continue ;;
    esac
    rm -f "$xo" "$BIN_DIR/plugs/${name}_entry.c" 2>/dev/null || true
    printf '  %sудалён осиротевший плагин: %s.xo%s\n' "$c_dim" "$name" "$c_reset"
  done
}

clean_legacy() {
  rm -rf "$ROOT_DIR/build.deploy" 2>/dev/null || true
  rmdir "$ROOT_DIR/backups" 2>/dev/null || true
  rm -f  "$BIN_DIR/minizapret" "$BIN_DIR/minizapret-web" 2>/dev/null || true
  prune_plugins
  rm -f  "$LOG_DIR/minizapret-web.log" "$LOG_DIR/rmf.pid" "$LOG_DIR/rmf.log" \
         "$LOG_DIR/rmf-web.log" "$LOG_DIR/iptables-before-cleanup.rules" 2>/dev/null || true
}

api() { curl -fsS -m 5 "$@" 2>/dev/null || true; }

web_up() { [ -n "$(api "$API/api/info")" ]; }

wait_for() {  # wait_for <секунд> <команда...>
  local n="$1"; shift
  for ((i = 0; i < n; i++)); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  return 1
}

iface() { ip route show default | awk '{print $5; exit}'; }

# Цепочки rmf удаляются по факту наличия, а не по списку: список устаревает
# при добавлении модулей, а остатки от убитого процесса модуля иначе живут
# вечно и перехватывают трафик в порт, где никто не слушает.
drop_chains() {
  local ch line
  for ch in "${RMF_CHAINS[@]}"; do
    iptables -t nat -D OUTPUT -j "$ch" 2>/dev/null || true
    iptables -t nat -F "$ch" 2>/dev/null || true
    iptables -t nat -X "$ch" 2>/dev/null || true
  done
  while read -r line; do
    [ -n "$line" ] || continue
    iptables -t nat -D OUTPUT -j "$line" 2>/dev/null || true
    iptables -t nat -F "$line" 2>/dev/null || true
    iptables -t nat -X "$line" 2>/dev/null || true
  done < <(iptables -t nat -S 2>/dev/null \
    | sed -n 's/^-N \([A-Za-z0-9_]*\)$/\1/p' \
    | grep -E '_BYPASS$|^RMF_DNS$')
}

# Правила модулей в таблице filter живут прямо в OUTPUT, а не в цепочке rmf,
# поэтому drop_chains их не видит. После убийства модуля они остаются и
# молча глушат трафик: например DROP на udp/443 к Cloudflare заставляет
# клиент ждать QUIC-ответа, которого не будет. Снимаем только те, что ставит
# rmf, и печатаем каждую — остальное не трогаем.
drop_filter_rules() {
  local line removed=0
  while read -r line; do
    [ -n "$line" ] || continue
    # shellcheck disable=SC2086
    if iptables -D OUTPUT $line 2>/dev/null; then
      removed=$((removed + 1))
      printf '  %sснят фильтр: -p %s -j DROP%s\n' "$c_dim" "$line" "$c_reset"
    fi
  done < <(iptables -S OUTPUT 2>/dev/null \
    | grep -E '^-A OUTPUT .* -j DROP$' \
    | grep -E -- '-p udp --dport 443 |-p tcp -m multiport --dports 443,853 ' \
    | sed 's/^-A OUTPUT //; s/ -j DROP$//')
  [ "$removed" -gt 0 ] && printf '  снято правил фильтра: %d\n' "$removed"
  return 0
}

stop_all() {
  api -X POST "$API/api/stopall" >/dev/null || true
  # Веб запускает плагин по ОТНОСИТЕЛЬНОМУ пути build/bin/rmf — шаблон должен
  # быть таким же: с абсолютным pkill -f не находится ничего, старые рели
  # остаются жить и держат свои порты, а новый модуль не может их занять.
  # Скобки в шаблоне: иначе pgrep/pkill находят сами себя — у проверяющего
  # bash эта строка есть в командной строке.
  local pat='[b]uild/bin/rmf'
  pkill -TERM -f "$pat" 2>/dev/null || true
  pkill -TERM -x rmf-web 2>/dev/null || true
  if ! wait_for 10 bash -c '! pgrep -f "[b]uild/bin/rmf" >/dev/null && ! pgrep -x rmf-web >/dev/null'; then
    pkill -KILL -f "$pat" 2>/dev/null || true
    pkill -KILL -x rmf-web 2>/dev/null || true
    if ! wait_for 10 bash -c '! pgrep -f "[b]uild/bin/rmf" >/dev/null && ! pgrep -x rmf-web >/dev/null'; then
      say "${c_err}осталось $(pgrep -cf "$pat" 2>/dev/null || echo 0) процессов rmf — нужен sudo: sudo ./run.sh stop${c_reset}"
    fi
  fi
  drop_chains
  drop_filter_rules
  rm -rf /run/rmf 2>/dev/null || true
  local ifc; ifc="$(iface || true)"
  [ -n "$ifc" ] && resolvectl dns "$ifc" $DEFAULT_IFACE_DNS >/dev/null 2>&1 || true
  return 0
}

saved_now=0

# Снимок перед перезагрузкой/пересборкой: собранные бинарники, конфиги веба,
# состояние iptables и исходников. Если новая сборка что-то сломает, есть
# откуда вернуться: ./run.sh restore
save_state() {
  [ "$saved_now" = "1" ] && return 0
  saved_now=1
  local stamp dir
  stamp="$(date +%Y%m%d-%H%M%S)"
  dir="$SAVE_DIR/$stamp"
  mkdir -p "$dir" || return 0

  [ -d "$BIN_DIR" ] && cp -a "$BIN_DIR" "$dir/bin" 2>/dev/null || true
  [ -d "$ROOT_DIR/webui" ] && cp -a "$ROOT_DIR/webui" "$dir/webui" 2>/dev/null || true
  [ -f /etc/hosts ] && cp -a /etc/hosts "$dir/hosts" 2>/dev/null || true
  iptables-save >"$dir/iptables.txt" 2>/dev/null || true
  {
    echo "время:  $stamp"
    echo "проект: $ROOT_DIR"
    echo "плагины: ${DEFAULT_PLUGINS[*]}"
    if git -C "$ROOT_DIR" rev-parse --git-dir >/dev/null 2>&1; then
      echo "коммит: $(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || echo '-')"
      git -C "$ROOT_DIR" status --porcelain 2>/dev/null | head -100
    fi
  } >"$dir/source.txt" 2>/dev/null || true

  # старые снимки не копим
  local old
  while [ "$(find "$SAVE_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)" -gt "$SAVE_KEEP" ]; do
    old="$(find "$SAVE_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort | head -1)"
    [ -n "$old" ] || break
    rm -rf "$old"
  done
  fix_owner
  ok "сейв: cache/save/$stamp"
}

# Вернуть последний снимок: бинарники и конфиги на место, дальше — start.
restore_state() {
  local dir
  dir="$(find "$SAVE_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort | tail -1)"
  [ -n "$dir" ] || die "сейвов нет в $SAVE_DIR"
  say "  восстанавливаю из $(basename "$dir")"
  [ -d "$dir/bin" ] && cp -a "$dir/bin/." "$BIN_DIR/" 2>/dev/null || true
  [ -d "$dir/webui" ] && cp -a "$dir/webui/." "$ROOT_DIR/webui/" 2>/dev/null || true
  fix_owner
  ok "состояние возвращено из $(basename "$dir")"
}

build() {
  save_state
  step "сборка (make core plugs webui)..."
  make -C "$ROOT_DIR" -j1 core plugs webui >/dev/null
  fix_owner
}

need_build() {
  [ -x "$CORE_BIN" ] && [ -x "$WEB_BIN" ] || return 0
  local src newer
  for src in src webui Makefile; do
    newer="$(find "$ROOT_DIR/$src" -newer "$WEB_BIN" -print -quit 2>/dev/null || true)"
    [ -n "$newer" ] && return 0
  done
  return 1
}

start() {
  local plugins=("$@")
  [ ${#plugins[@]} -eq 0 ] && plugins=("${DEFAULT_PLUGINS[@]}")

  clean_legacy
  save_state
  stop_all
  need_build && build
  [ -x "$WEB_BIN" ] || die "нет $WEB_BIN — запусти: ./run.sh build"

  mkdir -p "$LOG_DIR"
  cd "$ROOT_DIR"
  RMF_ROOT="$ROOT_DIR" nohup "$WEB_BIN" >"$WEB_LOG" 2>&1 &
  disown 2>/dev/null || true

  wait_for 30 web_up || { tail -n 20 "$WEB_LOG" >&2; die "веб не поднялся, смотри $WEB_LOG"; }
  ok "веб:    $API"

  local p
  for p in "${plugins[@]}"; do
    if api -X POST "$API/api/start?plugin=$p" >/dev/null; then
      ok "плагин: $p"
    else
      printf '  %s%s не стартовал%s\n' "$c_err" "$p" "$c_reset"
    fi
  done

  wait_for 20 bash -c "curl -fsS -m 3 $API/api/status | grep -q '\"proxy\":true'" \
    || die "прокси не поднялся, смотри $WEB_LOG"
  ok "прокси:  127.0.0.1:53"

  local ifc; ifc="$(iface || true)"
  if [ -n "$ifc" ]; then
    resolvectl dns "$ifc" 127.0.0.1 >/dev/null 2>&1 \
      && ok "DNS:     127.0.0.1 ($ifc)" \
      || printf '  %sDNS переключить не удалось%s\n' "$c_dim" "$c_reset"
  fi

  fix_owner
  say ""
  say "  Открывай:  $API"
  say "  Лог:       $WEB_LOG"
  say "  Остановить: ./run.sh stop"
}

status() {
  if web_up; then
    ok "веб работает — $API"
    api "$API/api/status" | tr ',' '\n' | sed 's/^/  /'
  else
    say "  веб не работает (порт 8080)"
  fi
  step "процессы:"
  pgrep -a -x rmf 2>/dev/null | sed 's/^/  /' || say "  rmf не запущен"
  pgrep -a -x rmf-web 2>/dev/null | sed 's/^/  /' || true
  step "цепочки rmf в nat:"
  if [ "$(id -u)" -ne 0 ]; then
    say "  нужен root: ./run.sh status"
  else
    iptables -t nat -S 2>/dev/null | grep -E '_BYPASS|RMF_DNS' | sed 's/^/  /' || say "  нет"
  fi
}

main() {
  local cmd="${1:-start}"; shift || true
  case "$cmd" in
    start|stop|restart|flush|logs|clean|build|status|save|restore|help|--help|-h)
      need_root "$cmd" "$@" ;;
    *)
      say "неизвестная команда: $cmd"; usage; exit 1 ;;
  esac
  case "$cmd" in
    start)          start "$@" ;;
    stop)           stop_all; ok "остановлено, цепочки сняты, DNS возвращён" ;;
    restart)        start "$@" ;;
    flush)          api -X POST "$API/api/flush" >/dev/null || true
                    drop_chains; ok "цепочки *_BYPASS и RMF_DNS снесены" ;;
    logs)           mkdir -p "$LOG_DIR"; touch "$WEB_LOG"; tail -n 40 -f "$WEB_LOG" ;;
    clean)          make -C "$ROOT_DIR" clean >/dev/null; fix_owner; ok "бинарники удалены" ;;
    build)          build; ok "собрано" ;;
    save)           save_state ;;
    restore)        restore_state; start "$@" ;;
    status)         status ;;
    help|--help|-h) usage ;;
  esac
}

main "$@"
