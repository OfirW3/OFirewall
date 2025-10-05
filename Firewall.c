#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include "Firewall.h"
#include <math.h>
#define HASHING_ROUNDS 25

int main(){
    printf("%d",sizeof(unsigned int));
    return 0;
}

void configInit(config *cfg){
    dynInit_interfaces(cfg->interfaces, 4);
    dynInit_users(cfg->accounts, 8);
}

int getUserIndex(config *cfg, const unsigned char *username){
    dynamic_users *arr = cfg->accounts;
    for (size_t i = 0; i < arr->size; i++)
    {
        if(!(strcmp(arr->data[i].username, username))){
            return i;
        }
    }
    return -1;
}

bool checkKey(config *cfg){ //True if the hashed input key matches the hashed root key. Otherwise, false.
    unsigned int tries = 0;
    wrong_key:
    printf("Enter the root key: \n");
    unsigned char buffer[16];
    fscanf(stdin,"%s",buffer);
    unsigned char hashed_key[32];
    SHA256(buffer,strlen(buffer), hashed_key);
    if(!strcmp(hashed_key,cfg->key)){
        printf("Success! \n");
        return true;;
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

void addUser(config *cfg, const char username[16], bool root){
    if(getUser(cfg, username) != -1){
        fprintf(stderr,"Error: Username already exists. \n");
        return;
    }
    user insertUser;
    insertUser.root = checkKey(cfg) && root;
    strcpy(insertUser.username, username);
    dynInsertValue_users(insertUser, cfg->accounts);
    return;
}

void removeUser(config *cfg, const unsigned char username){
    int index = getUser(cfg,username);
    if(index == -1){
        fprintf(stderr, "Error: User not found. \n");
        return;
    }
}

void addInterface(config *cfg, network net, const unsigned char zone[16], uint8_t mac[6], sec_level level){
    interface new_iface =
    {
        cfg->interfaces[cfg->interfaces->size]->id + 1,
        mac,
        net,
        {
            false,
            false
        },
        zone,
        level,
        NULL,
        NULL
    };
    dynInsertValue(new_iface, cfg->interfaces);
    return;
}

void removeInterface(config *cfg, uint8_t id){
    dynRemoveByIndex(id, cfg->interfaces); //ID represents the index - from 0 to interface array's size.
    return;
}

void setACL(config *cfg, uint8_t id, stdacl *inbound, stdacl *outbound){
    interface* iface = dynGetByIndex(id, cfg->interfaces);
    if(iface == NULL){
        fprintf(stderr,"Error: Interface has not found. \n");
        return;
    }
    iface->aclin = inbound;
    iface->aclout = outbound;
    return;
}

action matchACL(stdacl *acl, uint32_t ip){ //Return the specified action for the given IP by the acl. If none action was specified, dropping the packet.
    for (uint8_t i = 0; i < ACL_SIZE; i++)
    {
        stdace *entry = acl[i];
        uint32_t entry_ip = entry->net->ip;
        if(entry_ip == ip){
            return entry->act;
        }
        uint32_t entry_cidr = pow(2, (32 - entry->net->subnet));
        uint32_t network_addr = entry_ip & entry_cidr; //Given IP but zero for each network bit.
        uint32_t broadcast_addr = network_addr | ~entry_cidr; //Network IP but one for each host bit.
        if(ip >= network_addr && ip <= broadcast_addr){
            return entry->act;
        }
    }
    fprintf(stderr,"Warning: No specified action was found on the ACL. Dropping the packet.");
    return drop;
}

action processPacket(interface *iface, bool incoming, uint32_t srcIP, uint32_t dstIP){ //Figure out from what interface the packet came for and get the right action by the packet's IP
    if(incoming){
        if(matchACL(iface->aclin,srcIP) == drop){
            return drop;
        }
        else{
            return permit;
        }
    }
    else{
        if(matchACL(iface->aclout, dstIP) == drop){
            return drop;
        }
        return permit;
    }
    return drop;
}
