#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#define BLOCK_SIZE 10 //Used in Firewall.c program
#include "dynamic.h"                                                                                    
#include "iface.h"
#include "user.h"




typedef struct s_config{
    dynamic_interfaces *interfaces;
    dynamic_users *accounts; 
    rootkey key;
}config;