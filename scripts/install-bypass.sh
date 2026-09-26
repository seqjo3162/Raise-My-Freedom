#!/bin/bash
# Обёртка над единой точкой входа. Оставлена для привычки: работает так же,
# как раньше, но вся логика живёт в ./run.sh
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/../run.sh" start "$@"
