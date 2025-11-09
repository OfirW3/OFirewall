#pragma once
#include <stdint.h>
#include "iface.h"
#include "config.h"

void addInterface(config *cfg, interface iface){
    dynInsertValue_interfaces(iface, cfg->interfaces);
    return;
}

void removeInterface(config *cfg, uint8_t id){
    dynRemoveByIndex_interfaces(id, cfg->interfaces); //ID represents the index - from 0 to interface array's size.
    dynRemoveByIndex_users(id,cfg->accounts);
    return;
}