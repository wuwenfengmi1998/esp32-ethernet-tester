#!/usr/bin/env bash
set -euo pipefail

if [[ -n "${PLATFORMIO:-}" ]]; then
  PIO="$PLATFORMIO"
elif command -v pio >/dev/null 2>&1; then
  PIO="pio"
elif [[ -x "$HOME/.platformio/penv/bin/pio" ]]; then
  PIO="$HOME/.platformio/penv/bin/pio"
else
  echo "错误: 未找到 PlatformIO (pio)，请先安装。" >&2
  exit 1
fi

"$PIO" run "$@"
