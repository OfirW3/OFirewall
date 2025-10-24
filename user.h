#pragma once
#include "dynamic.h"
#include <stdint.h>

typedef struct s_user{
    char *username;
    bool root;
}user;

typedef struct s_rootkey{
    char key_str[32];
    uint16_t hashing_rounds;
}rootkey;

DECLARE_DYNAMIC(user, users)