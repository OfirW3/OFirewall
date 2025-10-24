#pragma once
#include "network.h"
#include "firewall.h"
#include <stdint.h>
#define ACL_SIZE 99

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
action matchACL(dynamic_stdacl *acl, uint32_t ip);