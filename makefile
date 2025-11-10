firewall: acl.c network.c config.c firewall.c   
	gcc acl.c network.c config.c firewall.c -o firewall

clean:
	rm -f firewall