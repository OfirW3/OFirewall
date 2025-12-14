OFirewall - Ofir Firewall

A simple cool toy userspace firewall for filtering IPv4 packets by using Linux Netfilter -> NFQUEUE for sending the packets from the kernel to the userspace, applying simple ACL rules (IP address based filtering) and returnes a verdict to the kernel - Accept or Drop.

How it works in short:

iptables inserts an NFQUEUE target for all packets hitting the PREROUTING hook and are arriving to veth-host.
Packets that match the rule are queued in the NFQUEUE on the kernel and delivered to the userspace via a netlink socket.
The userspace filter binary inspects the packets, maps the packet to the registered interface by checking the ifindex, checking the ACLs that are defined on the main program inside filter.c, returning a verdict to the kernel of Accept or Drop the packet.
For testing, the program creates a client and server namespaces and veth inside each, links the client_veth and server_veth so the traffic hits the PREROUTING inside the kernel networking stack and enqueued in the NFQUEUE, and then the program returnes verdicts for the packets that arrive at server_veth.

Some requirements:
The project uses libnetfilter-queue-dev library so make sure it's installed.
You will need sudo for making the iptables rules, the namespaces and the veths.

Running the program with testing (by making a veth pair):

Build and run the program:
sudo make set_veth

make build

sudo make run

Test the program by pinging from another terminal:
sudo make test_ping
#This will ping the allowed address
You can also try pinging other addresses and the packets should be drop and you will get no replies.

Cleanup:
sudo make clean_all 
#This will clean the veths, namespaces and the binary

You can play around with the main function in filter.c inside src folder
