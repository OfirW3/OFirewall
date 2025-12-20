#!/usr/bin/env bash
set -euo pipefail

NS="client"
VETH_HOST="veth-host"
VETH_CLIENT="veth-client"
HOST_IP="10.200.1.1/24"
CLIENT_IP="10.200.1.2/24"
QUEUE_NUM=0

# ensure required commands
for cmd in ip iptables nft; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "Required: $cmd"; exit 1; }
done

# idempotent cleanup of leftovers
ip netns del "$NS" 2>/dev/null || true
ip link del "$VETH_HOST" 2>/dev/null || true

# create namespace and veth pair
ip netns add "$NS"
ip link add "$VETH_HOST" type veth peer name "$VETH_CLIENT"
ip link set "$VETH_CLIENT" netns "$NS"

# assign addresses and bring up
ip addr add "$HOST_IP" dev "$VETH_HOST" 2>/dev/null || true
ip link set "$VETH_HOST" up
ip netns exec "$NS" ip addr add "$CLIENT_IP" dev "$VETH_CLIENT" 2>/dev/null || true
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip link set "$VETH_CLIENT" up

# ensure a single NFQUEUE rule (raw PREROUTING)
iptables -t raw -D PREROUTING -i "$VETH_HOST" -j NFQUEUE --queue-num "$QUEUE_NUM" 2>/dev/null || true
iptables -t raw -I PREROUTING -i "$VETH_HOST" -j NFQUEUE --queue-num "$QUEUE_NUM"

echo "veth/netns created. Verify with: sudo nft list ruleset"
