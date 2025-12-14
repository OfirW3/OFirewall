# **OFirewall – Ofir Firewall**

A simple toy userspace firewall for filtering IPv4 packets using Linux Netfilter hooks and the NFQUEUE.
Packets are sent from the kernel to userspace, filtered using simple ACL rules (IP-based), and a verdict is returned to the kernel: ACCEPT or DROP.

---

## **How It Works (Short Overview)**

- iptables inserts an NFQUEUE target for all packets hitting the PREROUTING hook that arrive on veth-host.
- Packets that match this rule are queued in the kernel’s NFQUEUE and delivered to userspace via a netlink socket.
- The userspace filter binary inspects each packet, maps it to the registered interface by checking the ifindex, and evaluates the ACL rules defined in the main program inside filter.c.
- Based on the ACL decision, the program returns a verdict to the kernel: ACCEPT or DROP.
- For testing, the project creates client and server network namespaces connected via veth interfaces.
- Traffic between the namespaces hits the PREROUTING hook in the kernel networking stack, is enqueued into the NFQUEUE, and then processed by the firewall in the userspace.
- The firewall returns verdicts for packets that arrive on server_veth.

---

## **Some Requirements**

- The project uses the libnetfilter-queue-dev library — make sure it is installed.
- sudo privileges are required to:
- Create network namespaces
- Create veth interfaces
- Insert iptables rules

---

## **Running the Program (With Test Setup)**

### **Build and Run**

sudo make set_veth
make build
sudo make run

Leave the terminal running the program open; the program listens for queued packets and returns verdicts.

## Testing the Firewall

From another terminal, run the simple ping test.

sudo make test_ping

This command pings the allowed address. Pinging other addresses should result in packets being dropped with no replies.

## Cleanup

sudo make clean_all

This removes veth interfaces, network namespaces, and the compiled binary.

## Last thing

Feel free to experiment with the firewall logic by editing the main function inside src/filter.c. The example ACLs used by the program are defined at startup in that file. Ensure veth-host exists before running the binary, and use the provided test netns and veth setup to avoid local-traffic cases that do not traverse PREROUTING.