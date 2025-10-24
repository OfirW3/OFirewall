#pragma once
#include "acl.h"
#include <stdint.h>

void add_rule(dynamic_stdacl *acl, network *net, action act){
    stdace insert_entry;
    insert_entry.net = net;
    insert_entry.act = act;
    dynInsertValue_stdacl(insert_entry, acl);
    return;
}

action check_rule(dynamic_stdacl acl, network *net, uint32_t ip){
    for (uint8_t i = 0; i < acl.size; i++)
    {
        stdace entry = acl.data[i];
        uint32_t entry_ip = entry.net->ip;
        if(entry_ip == ip){
            return entry.act;
        }
        uint32_t entry_cidr = 0xFFFFFFFF << (32 - entry.net->subnet); //First subnet size bits are 1 and all the other are 0
        uint32_t network_addr = entry_ip & entry_cidr; //Given IP but zero for each network bit.
        if((ip & entry_cidr) == network_addr){
            return entry.act;
        }
    }
    fprintf(stderr,"Warning: No specified action was found on the ACL. Dropping the packet.");
    return drop;
}