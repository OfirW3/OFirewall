#include <string.h>
#include "config.h"

bool add_interface(config *cfg, interface iface){
    if(!dynInsertValue_interfaces(iface, cfg->interfaces)){
        return false;
    }
    return true;
}

bool remove_interface(config *cfg, uint8_t id){
     //ID represents the index - from 0 to interface array's size.
    if(!dynRemoveByIndex_interfaces(id, cfg->interfaces) || !dynRemoveByIndex_users(id,cfg->accounts)){
        return false;
    }
    return true;
}

static int get_user_index(const config *cfg, const char *username){
    const dynamic_users *arr = cfg->accounts;
    for (size_t i = 0; i < arr->size; i++)
    {
        if(!(strcmp(arr->data[i].username, username))){
            return i;
        }
    }
    return -1;
}

static uint32_t rotate_left(uint32_t x, uint8_t n) {
    return (x << n) | (x >> (32 - n));
}

static void pesudo_hash(const char *data, size_t len, uint32_t rounds, char *out_hex) {
    uint32_t state[4] = {0xABCDEF01, 0x23456789, 0x98765432, 0xFEDCBA09};

    for (uint32_t r = 0; r < rounds; r++) {
        for (size_t i = 0; i < len; i++) {
            for (int s = 0; s < 4; s++) {
                state[s] ^= (data[i] + r * 31 + s * 17);
                state[s] = rotate_left(state[s], 5) * 2654435761u;
                state[s] ^= state[(s + 1) % 4]; // Mix with neighbor
            }
        }
    }
    //Write to out_hex the hex values of states as characters - doubling the size from 16 bytes hex numbers to 32 bytes char array
    sprintf(out_hex, "%08x%08x%08x%08x", state[0], state[1], state[2], state[3]);
}

static bool check_key(const config *cfg){ //True if the hashed input key matches the hashed root key. Otherwise, false.
    unsigned int tries = 0;
    while(tries < 5){
    printf("Enter the root key: \n");
    char buffer[16];
    fscanf(stdin,"%15s",buffer);
    char hashed_key[33];
    pesudo_hash(buffer, strlen(buffer), cfg->key.hashing_rounds, hashed_key); 
    if(!strcmp(hashed_key,cfg->key.key_str)){
        printf("Success! \n");
        return true;
    }
    else{
          tries++;
          fprintf(stderr, "Error: Wrong root key. %u wrong tries. \n",tries); 
        }
    }
    fprintf(stderr, "Error: Too many wrong tries, stopping the add user process. \n");
    return false;
}

add_user_status add_user(config *cfg, const char *username, bool root){
    if(get_user_index(cfg, username) != -1){
        fprintf(stderr,"Error: Username already exists. \n");
        return ADD_USER_ERR_DUPLICATE;
    }
    user insertUser;
    insertUser.root = check_key(cfg) && root;
    insertUser.username = strdup(username);
    if(!dynInsertValue_users(insertUser, cfg->accounts)){
        fprintf(stderr, "...");
        return ADD_USER_ERR_ALLOCATION;
    }
    return ADD_USER_SUCCESS;
}

bool remove_user(config *cfg, const char *username){
    int index = get_user_index(cfg, username);
    if(index == -1){
        fprintf(stderr, "Error: User not found. \n");
        return false;
    }
    dynRemoveByIndex_users(index, cfg->accounts);
    return true;
}

action process_packet(interface *iface, struct iphdr *ip, bool incoming){
    if(!ip->saddr || !ip->daddr){
        fprintf(stderr,"ProcessPacket: ip struct contains invalid addresses");
    }
    if(incoming){
        if(check_rule(iface->aclin, ip, true) == permit){
            return permit;
        }
        else{
            return drop;
        }
    }
    else{
        if(check_rule(iface->aclout, ip, false) == permit){
            return permit;
        }
        else{
            return drop;
        }
    }
    return drop;
}

