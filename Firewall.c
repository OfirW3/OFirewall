#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "Firewall.h"
#include <math.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <netinet/in.h>

uint32_t make_ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d) { //To understand 
    return ((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | d;
}

void initExampleACLs(stdacl *inbound, stdacl *outbound) {
    // Rule 0: Drop 10.0.0.0/8 (Private LANs)
    (*inbound)[0].act = drop;
    (*inbound)[0].net = malloc(sizeof(network));
    (*inbound)[0].net->ip = make_ip(10,0,0,0);
    (*inbound)[0].net->subnet = 8;

        // --- INBOUND ACL ---
    // Rule 1: Permit 192.168.10.0/24 (DMZ network)
    (*inbound)[1].act = permit;
    (*inbound)[1].net = malloc(sizeof(network));
    (*inbound)[1].net->ip = make_ip(192,168,10,0);
    (*inbound)[1].net->subnet = 24;

    // --- OUTBOUND ACL ---
    // Rule 0: Permit to 8.8.8.0/24 (Google DNS range)
    (*outbound)[0].act = permit;
    (*outbound)[0].net = malloc(sizeof(network));
    (*outbound)[0].net->ip = make_ip(8,8,8,0);
    (*outbound)[0].net->subnet = 24;

    // Rule 1: Drop 172.16.0.0/12 (Private network)
    (*outbound)[1].act = drop;
    (*outbound)[1].net = malloc(sizeof(network));
    (*outbound)[1].net->ip = make_ip(172,16,0,0);
    (*outbound)[1].net->subnet = 12;
}




void configInit(config *cfg){
    dynInit_interfaces(cfg->interfaces, 4);
    dynInit_users(cfg->accounts, 8);
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

void addInterface(config *cfg, network net, const char zone[16], uint8_t mac[6], sec_level level){
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
        stdace entry = (*acl)[i];
        uint32_t entry_ip = entry.net->ip;
        if(entry_ip == ip){
            return entry.act;
        }
        uint32_t entry_cidr = 0xFFFFFFFF << (32 - entry.net->subnet); //First subnet size bits are 1 and all the other are 0
        uint32_t network_addr = entry_ip & entry_cidr; //Given IP but zero for each network bit.
        if((ip & entry_cidr) == network_addr){
            return entry.act;
        }
    }
    fprintf(stderr,"Warning: No specified action was found on the ACL. Dropping the packet.");
    return drop;
}

action processPacket(interface *iface, bool incoming, uint32_t srcIP, uint32_t dstIP){ //Figure out from what interface the packet came for and get the right action by the packet's IP
    if(incoming){
        if(matchACL(iface->aclin, srcIP) == drop){
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
    // 1️⃣ Setup config
    config cfg;
    dynamic_interfaces interfaces;
    dynamic_users users;

    cfg.interfaces = &interfaces;
    cfg.accounts = &users;

    dynInit_interfaces(cfg.interfaces, 4);
    dynInit_users(cfg.accounts, 8);

    memset(cfg.key.key_str, 0, sizeof(cfg.key.key_str));
    cfg.key.hashing_rounds = 3;

    // 2️⃣ Create a DMZ interface
    network dmz_net;
    dmz_net.ip = make_ip(192,168,10,1); // DMZ gateway IP
    dmz_net.subnet = 24;

    char zone_name[16] = "DMZ";
    uint8_t mac[6] = {0x00, 0x10, 0x22, 0x33, 0x44, 0x55};

    addInterface(&cfg, dmz_net, zone_name, mac, medium);

    // 3️⃣ Initialize ACLs
    stdacl *inACL = malloc(sizeof(stdacl));
    stdacl *outACL = malloc(sizeof(stdacl));
    initExampleACLs(inACL, outACL);

    setACL(&cfg, 0, inACL, outACL);

    // 4️⃣ Print interface summary
    interface *iface = dynGetByIndex_interfaces(0, cfg.interfaces);
    printf("\n=== Interface Info ===\n");
    printf("ID: %d | Zone: %s | Level: %d\n", iface->id, iface->zone_name, iface->level);
    printf("IP: %u.%u.%u.%u/%d\n",
           (iface->net.ip >> 24) & 0xFF, (iface->net.ip >> 16) & 0xFF,
           (iface->net.ip >> 8) & 0xFF, iface->net.ip & 0xFF,
           iface->net.subnet);

    // 5️⃣ Simulate packets

    printf("\n--- Packet Tests ---\n");

    // Packet 1: from 192.168.10.25 (should be PERMIT)
    uint32_t ip1 = make_ip(192,168,10,25);
    action result1 = processPacket(iface, true, ip1, make_ip(8,8,8,8));
    printf("Packet 1 (192.168.10.25) → Action: %s\n", result1 == permit ? "PERMIT" : "DROP");

    // Packet 2: from 10.0.0.50 (should be DROP by rule, not default)
    uint32_t ip2 = make_ip(10,0,0,50);
    action result2 = processPacket(iface, true, ip2, make_ip(8,8,8,8));
    printf("Packet 2 (10.0.0.50) → Action: %s\n", result2 == permit ? "PERMIT" : "DROP");

    dynFree_interfaces(cfg.interfaces);
    dynFree_users(cfg.accounts);
    return 0;
}
