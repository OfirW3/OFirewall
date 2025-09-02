#include <stdio.h>
#include <stdbool.h>
#define ACL_SIZE 99
#define BLOCK_SIZE 10

typedef unsigned char int8;
typedef unsigned short int int16;
typedef unsigned int int32;
typedef unsigned long long int int64;

/*
interface e0/0 --
interface number
name: insider/dmz/outsider
MAC address of the interface
IP address of the interface 
security level 0 - e(Hexadecimal, 0 - 16 decimal)

*/

enum e_action{
    permit = 1,
    drop = 2
};

typedef enum e_action action;

typedef struct s_network
{
    unsigned int ip : 32; // 32 bits for IP address
    unsigned char subnet : 5; // 5 bits for CIDR (0-32)
}network;

typedef struct s_user{
    unsigned char username[16]; // Username up to 31 characters + null terminator
    unsigned int pin : 14; // 10 bits for pincode (0-10000)
    bool root : 1; // 1 bit for root status
}user;

typedef struct s_stdce{ // standard control entry structure
    unsigned char act : 3; // 3 bits for action
    network net; // network structure

}stdace;

typedef stdace stdacl[ACL_SIZE]; // access control list with max 100 entries

typedef struct s_rootkey{
    unsigned int key : 10; // 10 bits for rootkey
    unsigned long int n : 23; // 23 bits for rounds (0-8000000)
}rootkey;

typedef struct s_interface
{
    unsigned char id : 3; //3 bits - 8 interfaces
    unsigned long long int mac : 48; //48 bits for mac_address
    network net; //network structure
    struct {
        bool l1 : 1;
        bool l3 : 1;
    };
    unsigned char zone_name[16]; // Zone name up to 15 characters + null terminator
    unsigned char sec_level : 4; //4 bits for security level (0-16)
    stdacl *aclin; //Inbound ACL - ACL for incoming packets
    stdacl *aclout; //Outbound ACL - ACL for outcoming packets
}interface;

typedef struct s_config{
    interface *iface[7];
    user account;
    rootkey key;
    stdacl *acl[ACL_SIZE];
}config;


typedef struct s_dynamic{
    unsigned int count;// Number of values
    unsigned int size; // Actual size of the dynamic array
    unsigned int capacity; // The capacity the array can hold for now
    unsigned int *data; // The data stored in the array - can be at any type
}dynamic;

dynamic* dynMake_(unsigned int);



void dynAdd(dynamic* arr, void* val);


