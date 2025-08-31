#include <stdio.h>

/*
interface e0/0 --
interface number
name: insider/dmz/outsider
MAC address of the interface
IP address of the interface 
security level 0 - e(Hexadecimal, 0 - 16 decimal)

*/

typedef unsigned long long int uint64;
typedef unsigned long int uint32;
typedef unsigned char uint8;
typedef unsigned short uint16;

typedef uint8 inter_num;
typedef uint64 mac_address;
typedef uint32 ip_address;
typedef uint8 CIDR;
typedef uint8 level; 
typedef uint16 pincode;
typedef uint8 subkey;//?
typedef uint32 rounds; //?

typedef enum e_action{
    permit = 1,
    drop = 2
}action;

typedef struct s_network
{
    ip_address ip : 32; // 32 bits for IP address
    CIDR subnet : 5; // 5 bits for CIDR (0-32)
}network;

typedef struct s_user{
    uint8 username[16]; // Username up to 31 characters + null terminator
    pincode pin : 14; // 10 bits for pincode (0-10000)
    bool root : 1; // 1 bit for root status
}user;

typedef struct s_stdce{ // standard control entry structure
    action act : 3 // 3 bits for action
    network net; // network structure

}stdace;

typedef stdace[100] acl; // access control list with max 100 entries

typedef struct s_rootkey{
    subkey key : 10; // 10 bits for rootkey
    rounds n : 23; // 23 bits for rounds (0-8000000)
}rootkey;

typedef struct s_interface
{
    inter_num id : 3; //3 bits - 8 interfaces
    mac_address mac : 48; //48 bits for mac_address
    network net; //network structure
    strcut {
        bool l1 : 1;
        bool l3 : 1;
    }shutdown : 2; //2 bits for shutdown status
    uint8 zone_name[16]; // Zone name up to 15 characters + null terminator
    level sec_level : 4; //4 bits for security level (0-16)
    user account; //user structure
    rootkey key; //rootkey structure ?
    acl access_list; //access control list
}interface;
