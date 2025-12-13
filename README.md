OFirewall - Ofir Firewall

A simple cool firewall for filtering packets based on their IP addresses as determied in the ACLs

The firewall uses the Linux Netfilter Framework for putting PREROUTING and OUTPUT hooks and triggering a callback for each packet that hits the hooks for a filtering based on the ACLs rules.
For all packets that hit the network interface's hooks are sent to the userspace NFQUEUE (Netfilter queue) and are procecced by the firewall that runs on the userspace one by one and the firewall sends a verdict for the kernel to accept or drop the packet by using the netlink sockets for kernel - userspace communication.
A testing for the project was made by creating 2 network namespaces, client and server, for simulating the firewall in process from the client prespective.
All packets from that are sent to the client and server namespaces are going through the iptables and then to the NFQUEUE.
To run the project with the running example you better be root in order to avoid many password prompting from sudo.
Then you need to create those namespaces and set the iptables rules by:
make set_veth
Then build the filter binary by:
make build
Then run the filter from the first terminal by:
make run
Then you can test the filtering from another terminal by:
make test_ping