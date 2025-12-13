#pragma once
#include <stdint.h>
#include <netinet/ip.h>
#include <stdbool.h>
#include "dynamic.h"
#include "network.h"

typedef struct s_dynamic_stdacl dynamic_stdacl;
typedef struct s_network network;


enum e_action{
    permit = 1,
    drop = 2
};

typedef enum e_action action;

typedef struct s_stdce{ // standard control entry structure
    action act; //For "Permit" or "Deny"
    network *net; //Contains the network details for inbound packets conatins the src, for outbound contains the dest.
}stdace;

DECLARE_DYNAMIC(stdace,stdacl) //Dynamic array dynamic_stdacl

void add_rule(dynamic_stdacl *acl, network *net, action act);
action check_rule(dynamic_stdacl *acl, struct iphdr *ip_header, bool incoming);