#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "Firewall.h"
#include <math.h>


uint32_t make_ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d) { //To understand 
    return ((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | d;
}

void initExampleACLs(stdacl *inbound, stdacl *outbound) {
    // Permit 192.168.10.0/24 inbound
    inbound[0]->act = permit;
    inbound[0]->net = (network*)malloc(sizeof(network));
    inbound[0]->net->ip = make_ip(192,168,10,0);
    inbound[0]->net->subnet = 24;

    // Drop everything else inbound
    inbound[1]->act = drop;
    inbound[1]->net = malloc(sizeof(network));
    inbound[1]->net->ip = 0;
    inbound[1]->net->subnet = 0;

    // Permit outbound all
    outbound[0]->act = permit;
    outbound[0]->net = malloc(sizeof(network));
    outbound[0]->net->ip = make_ip(0,0,0,0);
    outbound[0]->net->subnet = 0;
}

void configInit(config *cfg){
    dynInit_interfaces(cfg->interfaces, 4);
    dynInit_users(cfg->accounts, 8);
}

int getUserIndex(config *cfg,const unsigned char *username){
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

uint32_t pesudo_hash(const unsigned char *data, size_t len, uint32_t rounds) { //To understand
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
    unsigned char buffer[16];
    fscanf(stdin,"%15s",buffer);
    unsigned char hashed_key[32];
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

void addUser(config *cfg, const unsigned char *username, bool root){
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

void removeUser(config *cfg, const unsigned char *username){
    int index = getUserIndex(cfg, username);
    if(index == -1){
        fprintf(stderr, "Error: User not found. \n");
        return;
    }
}

void addInterface(config *cfg, network net, const unsigned char zone[16], uint8_t mac[6], sec_level level){
    interface iface;
    iface.id = cfg->interfaces->size;
    memcpy(iface.mac, mac, 6);
    iface.net = net;
    iface.shutdown.l1 = false;
    iface.shutdown.l3 = false;
    memcpy(iface.zone_name, zone, 16);
    iface.level = level;
    dynInsertValue_interfaces(iface, cfg->interfaces);
    return;
}

void removeInterface(config *cfg, uint8_t id){
    dynRemoveByIndex_interfaces(id, cfg->interfaces); //ID represents the index - from 0 to interface array's size.
    dynRemoveByIndex_users(id,cfg->accounts);
    return;
}

void setACL(config *cfg, uint8_t id, stdacl *inbound, stdacl *outbound){
    interface* iface = dynGetByIndex_interfaces(id, cfg->interfaces);
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

int main() {
    // 1️⃣ Create config
    config cfg;
    dynamic_interfaces interfaces;
    dynamic_users users;

    cfg.interfaces = &interfaces;
    cfg.accounts = &users;

    dynInit_interfaces(cfg.interfaces, 4);
    dynInit_users(cfg.accounts, 8);
    memset(cfg.key.key_str, 0, sizeof(cfg.key.key_str));

    // 2️⃣ Create a network struct for the interface
    network dmz_net;
    dmz_net.ip = make_ip(192,168,10,1); // DMZ interface IP
    dmz_net.subnet = 24;                // 255.255.255.0

    // 3️⃣ Zone name and MAC address
    unsigned char zone_name[16] = "DMZ";
    uint8_t mac[6] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};

    // 4️⃣ Add interface to config
    addInterface(&cfg, dmz_net, zone_name, mac, medium);

    // 5️⃣ Assign example ACLs
    stdacl *inACL = malloc(sizeof(stdacl));
    stdacl *outACL = malloc(sizeof(stdacl));
    initExampleACLs(inACL, outACL);

    setACL(&cfg, 0, inACL, outACL);

    // 6️⃣ Print summary
    interface *iface = dynGetByIndex_interfaces(0, cfg.interfaces);
    if (iface) {
        printf("Interface ID: %u\n", iface->id);
        printf("Zone name: %s\n", iface->zone_name);
        printf("MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
               iface->mac[0], iface->mac[1], iface->mac[2],
               iface->mac[3], iface->mac[4], iface->mac[5]);
        printf("IP: %u.%u.%u.%u/%u\n",
               (iface->net.ip >> 24) & 0xFF, (iface->net.ip >> 16) & 0xFF,
               (iface->net.ip >> 8) & 0xFF, iface->net.ip & 0xFF,
               iface->net.subnet);
        printf("Security level: %d\n", iface->level);
        printf("Shutdown L1: %d, L3: %d\n", iface->shutdown.l1, iface->shutdown.l3);
    }
    else{
        printf("Interface is a null value");
    }
    dynFree_interfaces(cfg.interfaces);
    dynFree_users(cfg.accounts);
    free(inACL);
    free(outACL);

    return 0;
}