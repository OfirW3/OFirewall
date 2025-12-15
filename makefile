# Makefile — project root (sources are in src/)
CC := gcc
CFLAGS := -O2 -Isrc
LIBS := -lnetfilter_queue

SRC := $(wildcard src/*.c)
BIN := filter

VETH_SERVER := veth-server
VETH_CLIENT := veth-client
NS_CLIENT := client
SERVER_ADDR := 10.200.1.1
SERVER_IP_CIDR := 10.200.1.1/24
CLIENT_IP := 10.200.1.2/24
QUEUE_NUM := 0

.PHONY: all build set_veth clean_veth run run_no_build test_ping show_rules clean_bin clean_iptables clean_all

all: build

build:
	@echo ">>> Building $(BIN) from src/"
	$(CC) $(CFLAGS) $(SRC) -o $(BIN) $(LIBS)

# create veth pair and namespace (idempotent)
set_veth:
	@echo ">>> Setting up veth pair and client namespace"
	sudo ip netns del $(NS_CLIENT) 2>/dev/null || true
	sudo ip link del $(VETH_SERVER) 2>/dev/null || true

	sudo ip netns add $(NS_CLIENT)
	sudo ip link add $(VETH_SERVER) type veth peer name $(VETH_CLIENT)
	sudo ip link set $(VETH_CLIENT) netns $(NS_CLIENT)

	sudo ip addr add $(SERVER_IP_CIDR) dev $(VETH_SERVER) 2>/dev/null || true
	sudo ip link set $(VETH_SERVER) up

	sudo ip netns exec $(NS_CLIENT) ip addr add $(CLIENT_IP) dev $(VETH_CLIENT) 2>/dev/null || true
	sudo ip netns exec $(NS_CLIENT) ip link set lo up
	sudo ip netns exec $(NS_CLIENT) ip link set $(VETH_CLIENT) up

	# ensure a single NFQUEUE rule
	sudo iptables -t raw -D PREROUTING -i $(VETH_SERVER) -j NFQUEUE --queue-num $(QUEUE_NUM) 2>/dev/null || true
	sudo iptables -t raw -I PREROUTING -i $(VETH_SERVER) -j NFQUEUE --queue-num $(QUEUE_NUM)
	@echo ">>> Done. Verify with: sudo nft list ruleset"

# Run the filter binary (foreground). Requires root.
run: build
	@echo ">>> Running $(BIN) (Ctrl-C to stop)"
	@echo ">>> Make sure you created the veth/netns with: sudo make set_veth"
	sudo ./$(BIN)

# Run the binary without rebuilding
run_no_build:
	@echo ">>> Running $(BIN) (no build)"
	sudo ./$(BIN)

# Ping from client namespace to server (quick test)
test_ping:
	@echo ">>> Pinging from namespace $(NS_CLIENT) to $(SERVER_ADDR)"
	sudo ip netns exec $(NS_CLIENT) ping -I $(VETH_CLIENT) -c 4 $(SERVER_ADDR)

# Show iptables/nft rules for debugging
show_rules:
	@echo "=== nft list ruleset ==="
	sudo nft list ruleset
	@echo "=== iptables raw table ==="
	sudo iptables -t raw -L -n -v --line-numbers

# Remove veth, namespace and NFQUEUE rule
clean_veth:
	@echo ">>> Cleaning veth, namespace and NFQUEUE rule"
	sudo iptables -t raw -D PREROUTING -i $(VETH_SERVER) -j NFQUEUE --queue-num $(QUEUE_NUM) 2>/dev/null || true
	sudo ip netns del $(NS_CLIENT) 2>/dev/null || true
	sudo ip link del $(VETH_SERVER) 2>/dev/null || true
	@echo ">>> Done."

clean_bin:
	@echo ">>> Removing binary"
	-rm -f $(BIN)

clean_iptables:
	@echo ">>> Flushing iptables and restoring ACCEPT policies (use with care)"
	sudo iptables -P INPUT ACCEPT || true
	sudo iptables -P FORWARD ACCEPT || true
	sudo iptables -P OUTPUT ACCEPT || true
	sudo iptables -t nat -F || true
	sudo iptables -t mangle -F || true
	sudo iptables -F || true
	sudo iptables -X || true
	@echo ">>> Done."

clean_all: clean_veth clean_iptables clean_bin
	@echo ">>> Full cleanup done."
