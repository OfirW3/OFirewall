#pragma once
#include "iface.h"
#include "user.h"

typedef struct s_dynamic_interfaces dynamic_interfaces;
typedef struct s_dynamic_users dynamic_users;
typedef struct s_rootkey rootkey;

typedef struct s_config{
    dynamic_interfaces *interfaces;
    dynamic_users *accounts; 
    rootkey key;
}config; 