#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <math.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include "user.h"
#include "config.h"
#include "acl.h"
#include "iface.h"


void configInit(config *cfg){
    dynInit_interfaces(cfg->interfaces, 4);
    dynInit_users(cfg->accounts, 8);
}


action processPacket(interface *iface, bool incoming, uint32_t srcIP, uint32_t dstIP){ //Figure out from what interface the packet came for and get the right action by the packet's IP
    if(incoming){
        if(matchACL(iface->aclin, srcIP) == drop){
            return drop;
        }
        else{
            return permit;
        }
    }
    else{
        if(matchACL(iface->aclout, dstIP) == drop){
            return drop;
        }
        return permit;
    }
    return drop;
}

int main() {
    return 0;
}
