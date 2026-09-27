#!/usr/bin/env bash
# Сторож: поднимает систему, если веб перестал отвечать или умер модуль.
#
# Зачем: компьютер у пользователя обрубается, и после этого всё останавливается.
# Автозапуск при загрузке это лечит, но если что-то падает уже во время работы
# (модуль уронил процесс, OOM, обрыв) — без сторожа оно лежит до перезагрузки.
#
# Главное, чего не хватало раньше: сторож смотрел только на веб. Веб отвечал,
# а модули уже лежали, и вместе с ними умирали рели. Правила iptables умершего
# модуля при этом оставались: REDIRECT вёл в порт, где никто не слушает, и
# приложение получало «В соединении отказано». Наблюдалось на Discord —
# ConnectionRefused на updates.discord.com, 28 правил в никуда.
#
# Теперь сторож спрашивает /api/status, сверяет с /run/rmf/expected-plugins и
# поднимает систему, если хотя бы один ожидаемый модуль неактивен.
#
# Правило сдержанности: если rmf.service НЕ активен, ничего не делаем. Иначе
# пользователь не смог бы остановить систему намеренно: он остановил, а через
# две минуты всё снова поднялось само и мешало.

set -uo pipefail

# Корень ищем сами, чтобы скрипт не был привязан к домашнему каталогу одного
# человека: лежит рядом с ним run.sh, а в воркtree'е — на уровень выше.
ROOT="${RMF_ROOT:-}"
if [ -z "$ROOT" ]; then
    self_dir=$(cd "$(dirname "$0")" 2>/dev/null && pwd)
    if [ -n "$self_dir" ] && [ -x "$self_dir/../run.sh" ]; then
        ROOT=$(cd "$self_dir/.." && pwd)
    else
        ROOT="/home/seqjo/Raise-My-Freedom-private"
    fi
fi
URL="http://127.0.0.1:8080/api/status"
LOG="/tmp/rmf-watchdog.log"
EXPECTED="/run/rmf/expected-plugins"

# Служба должна быть активна: значит пользователь её не выключал.
if ! systemctl is-active --quiet rmf.service 2>/dev/null; then
    exit 0
fi

# Перезапуск системы.
#
# Раньше здесь вызывался ./run.sh напрямую, и это была ловушка. Сторож — это
# Type=oneshot: его процессы живут в cgroup сторожа, а когда он завершается,
# systemd сносит всю группу. Всё, что успело запуститься, умирало через
# минуту после «успешного» старта. Наблюдалось три перезапуска подряд, каждый
# отчитывался об успехе, и каждый раз через минуту не оставалось ничего.
#
# Правильно — отдать перезапуск службе, которая владеет процессами: у rmf.service
# стоит RemainAfterExit=yes, поэтому её cgroup переживает завершение.
restart_all() {
    if systemctl restart rmf.service >>"$LOG" 2>&1; then
        printf '%s перезапуск выполнен через rmf.service\n' "$(date -Is)" >>"$LOG"
    else
        printf '%s перезапуск НЕ удался, rmf.service вернул ошибку\n' \
            "$(date -Is)" >>"$LOG"
    fi
}

# Веб должен отвечать: без него состояние модулей не узнать.
status=""
if ! status=$(curl -fs -m 6 "$URL" 2>/dev/null); then
    printf '%s веб не отвечает, перезапускаю\n' "$(date -Is)" >>"$LOG"
    restart_all
    exit 0
fi

# Ожидаемый набор модулей. Если файла нет, сверять не с чем: считаем, что всё
# в порядке, и не мешаем системе, запущенной вручную с нестандартным набором.
[ -s "$EXPECTED" ] || exit 0

# Разбираем ответ веба без python: он есть не на каждой машине, а json ответ
# плоский и регуляркой разбирается надёжно. Собираем пары "имя:active".
active_list=$(printf '%s' "$status" \
  | tr '{' '\n' \
  | grep -oE '"name":[[:space:]]*"[a-z0-9_-]+"|"active":[[:space:]]*(true|false)' \
  | tr -d ' "' | paste - - 2>/dev/null | tr ':' ' ')

dead=""
while read -r name; do
    case "$name" in ''|'#'*) continue ;; esac
    got=""
    [ -n "$active_list" ] && got=$(printf '%s' "$active_list" \
        | awk -v n="$name" '$2==n {print $4; exit}')
    if [ "$got" != "true" ]; then
        dead="$dead $name(состояние: ${got:-нет})"
    fi
done <"$EXPECTED"

if [ -n "$dead" ]; then
    printf '%s модули не активны:%s, перезапускаю\n' \
        "$(date -Is)" "$dead" >>"$LOG"
    restart_all
    exit 0
fi

# Проверка релей. Модуль может быть жив, а его рель — нет: рель живёт внутри
# процесса модуля, и при падении процесса умирает вместе с ним, тогда как
# правила REDIRECT в iptables остаются. Приложение получает «В соединении
# отказано», а веб показывает active: true. Именно так сломался Discord:
# процесс жив, 28 правил ведут на 18443, а слушать там некому.
#
# Список портов берём из самих правил, а не из отдельного файла: так проверка
# не может разойтись с тем, что реально установлено.
if ! command -v iptables >/dev/null 2>&1; then
    exit 0
fi

orphans=""
for chain in $(iptables -t nat -S 2>/dev/null \
                 | awk '/^-N .*BYPASS$/ {print $2}'); do
    for port in $(iptables -t nat -S "$chain" 2>/dev/null \
                    | grep -oE '\-j REDIRECT --to-ports [0-9]+' \
                    | grep -oE '[0-9]+$' | sort -u); do
        # Порт занят кем угодно — значит правило не висит в пустоту.
        if ss -tln 2>/dev/null | grep -q "127.0.0.1:${port} "; then
            continue
        fi
        orphans="$orphans $chain->$port"
    done
done

if [ -n "$orphans" ]; then
    printf '%s рель не слушает, а правила на него ведут:%s, перезапускаю\n' \
        "$(date -Is)" "$orphans" >>"$LOG"
    restart_all
fi

