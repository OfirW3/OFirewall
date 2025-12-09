filter: acl.c network.c config.c firewall.c filter.c
	gcc acl.c network.c config.c firewall.c filter.c -o filter -lnetfilter_queue

firewall: acl.c network.c config.c firewall.c   
	gcc acl.c network.c config.c firewall.c -o firewall

clean:
	rm -f firewall