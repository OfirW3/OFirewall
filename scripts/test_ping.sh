#!/usr/bin/env bash
set -euo pipefail

NS="client"
VETH_CLIENT="veth-client"
HOST_ADDR="10.200.1.1"

echo "Pinging allowed IP ($HOST_ADDR) from client namespace..."
ip netns exec "$NS" ping -I "$VETH_CLIENT" -c 4 "$HOST_ADDR"
