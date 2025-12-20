#!/usr/bin/env bash
set -euo pipefail

BIN="./filter" 
if ! [ -x "$BIN" ]; then
  echo "Binary not found or not executable: $BIN"
  echo "Run: make build"
  exit 1
fi

VETH_HOST="veth-host"
if ! ip link show "$VETH_HOST" >/dev/null 2>&1; then
  echo "Interface $VETH_HOST not found. Run: sudo ./set_veth.sh"
  exit 1
fi

exec sudo "$BIN"
