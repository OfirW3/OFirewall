#include <string.h>
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

int getUserIndex(config *cfg, const char *username){
    dynamic_users *arr = cfg->accounts;
    for (size_t i = 0; i < arr->size; i++)
    {
        if(!(strcmp(arr->data[i].username, username))){
            return i;
        }
    }
    return -1;
}

uint32_t rotate_left(uint32_t x, uint8_t n) { //To understand
    return (x << n) | (x >> (32 - n));
}

uint32_t pesudo_hash(const char *data, size_t len, uint32_t rounds) { //To understand
    uint32_t hash = 0xABCDEF01;
    for (uint32_t r = 0; r < rounds; r++) {
        for (size_t i = 0; i < len; i++) {
            hash ^= (data[i] + r * 31);
            hash = rotate_left(hash, 5) * 2654435761u;
        }
    }
    return hash;
}

bool checkKey(config *cfg){ //True if the hashed input key matches the hashed root key. Otherwise, false.
    unsigned int tries = 0;
    wrong_key:
    printf("Enter the root key: \n");
    char buffer[16];
    fscanf(stdin,"%15s",buffer);
    char hashed_key[32];
    pesudo_hash(buffer, strlen(buffer), cfg->key.hashing_rounds); 
    if(!strcmp(hashed_key,cfg->key.key_str)){
        printf("Success! \n");
        return true;
    }
    else{
          tries++;
          fprintf(stderr, "Error: Wrong root key. %d wrong tries. \n",tries);
          if(tries < 5){
               goto wrong_key;
          }
        else{
            fprintf(stderr, "Error: Too many wrong tries, stopping the add user process. \n");
               return false;
           }
     }
    return false;
}

void addUser(config *cfg, const char *username, bool root){
    if(getUserIndex(cfg, username) != -1){
        fprintf(stderr,"Error: Username already exists. \n");
        return;
    }
    user insertUser;
    insertUser.root = checkKey(cfg) && root;
    strcpy(insertUser.username, username);
    dynInsertValue_users(insertUser, cfg->accounts);
    return;
}

void removeUser(config *cfg, const char *username){
    int index = getUserIndex(cfg, username);
    if(index == -1){
        fprintf(stderr, "Error: User not found. \n");
        return;
    }
}

