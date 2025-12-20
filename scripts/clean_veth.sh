#!/usr/bin/env bash
set -euo pipefail

NS="client"
VETH_HOST="veth-host"
QUEUE_NUM=0

# remove NFQUEUE rule (ignore errors)
iptables -t raw -D PREROUTING -i "$VETH_HOST" -j NFQUEUE --queue-num "$QUEUE_NUM" 2>/dev/null || true

# delete namespace and host veth (ignore errors)
ip netns del "$NS" 2>/dev/null || true
ip link del "$VETH_HOST" 2>/dev/null || true

echo "Cleaned veth and namespace."
