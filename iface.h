#pragma once
#include "acl.h"
#include <stdbool.h>
#include <stdint.h>

typedef struct s_network network;
typedef struct s_dynamic_stdacl dynamic_stdacl;
typedef struct s_config config;



typedef enum 
{   low = 1, 
    medium = 5, 
    high = 15
}
sec_level;



typedef struct s_interface {
    uint8_t id; 
    uint8_t mac[6];
    network *net;
    struct {
        bool l1 : 1;
        bool l3 : 1;
    } shutdown; //?
    char zone_name[16];
    sec_level level;
    dynamic_stdacl *aclin; //Make in the future the ACLs dynamic arrays instead of fixed size arrays.
    dynamic_stdacl *aclout;
} interface;

DECLARE_DYNAMIC(interface, interfaces)


