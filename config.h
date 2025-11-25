#pragma once
#include "iface.h"
#include "user.h"

typedef struct s_dynamic_interfaces dynamic_interfaces;
typedef struct s_dynamic_users dynamic_users;
typedef struct s_rootkey rootkey;

typedef struct s_config{
    interface_map *iface_map; //Key = ifaceID, value = interface with the ifaceID
    dynamic_interfaces *interfaces; //(Might be removed later) The ifaces ID is given by the order in the array
    dynamic_users *accounts; 
    rootkey key;
}config; 

static config *g_config; //Global config

void addInterface(config *cfg, interface iface);
void removeInterface(config *cfg, uint8_t id);
int getUserIndex(config *cfg, const char *username);
uint32_t rotate_left(uint32_t x, uint8_t n);
uint32_t pesudo_hash(const char *data, size_t len, uint32_t rounds);
bool checkKey(config *cfg);
void addUser(config *cfg, const char *username, bool root);
void removeUser(config *cfg, const char *username);
