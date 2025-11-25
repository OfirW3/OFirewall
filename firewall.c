#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "firewall.h"
#include <netinet/ip.h>

void configInit(config *cfg){
    dynInit_interfaces(cfg->interfaces, 4);
    dynInit_users(cfg->accounts, 8);
}


action processPacket(interface *iface, struct iphdr *ip, bool incoming){
    uint32_t srcIP = ntohl(ip->saddr);
    uint32_t dstIP = ntohl(ip->daddr);
    if(incoming){
        if(check_rule(iface->aclin, iface->net, srcIP) == drop){
            return drop;
        }
        else{
            return permit;
        }
    }
    else{
        if(check_rule(iface->aclout, iface->net, dstIP) == drop){
            return drop;
        }
        return permit;
    }
    return drop;
}

int main() {
    return 0;
}
