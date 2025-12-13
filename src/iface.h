#pragma once
#include "acl.h"
#include <stdbool.h>
#include <stdint.h>

typedef struct s_network network;
typedef struct s_dynamic_stdacl dynamic_stdacl;
typedef struct s_config config;



typedef enum e_sec_level 
{   low = 1, 
    medium = 5, 
    high = 15
}sec_level;



typedef struct s_interface {
    uint8_t id; 
    uint8_t mac[6];
    network *net;
    struct {
        bool l1 : 1;
        bool l3 : 1;
    } shutdown; //Do I need this?
    char zone_name[16];
    sec_level level;
    dynamic_stdacl *aclin; 
    dynamic_stdacl *aclout;
} interface;

#define max_ifaces 128 //It's very unlikely for a device to have more than 128 network interfaces

typedef struct s_interface_map{
    interface *iface[max_ifaces];
}interface_map;

DECLARE_DYNAMIC(interface, interfaces)


