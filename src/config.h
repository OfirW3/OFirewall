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

typedef enum {
    ADD_USER_SUCCESS = 0,
    ADD_USER_ERR_DUPLICATE = 1,
    ADD_USER_ERR_ALLOCATION = 2
}add_user_status;

bool add_interface(config *cfg, interface iface);
bool remove_interface(config *cfg, uint8_t id);
static int get_user_index(const config *cfg, const char *username);
static uint32_t rotate_left(uint32_t x, uint8_t n);
static void pesudo_hash(const char *data, size_t len, uint32_t rounds, char *out_hex);
static bool check_key(const config *cfg);
add_user_status add_user(config *cfg, const char *username, bool root);
bool remove_user(config *cfg, const char *username);
action process_packet(interface *iface, struct iphdr *ip, bool incoming);