#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#define ACL_SIZE 99
#define BLOCK_SIZE 10

enum e_action{
    permit = 1,
    drop = 2
};

typedef enum e_action action;

typedef struct s_network
{
    uint32_t ip; // 32 bits for IP address
    uint8_t subnet; // 5 bits for CIDR (0-32)

}network;

typedef struct s_user{
    unsigned char username[16]; // Username up to 16 characters + null terminator
    uint16_t pin; // * Give only 10 bits for the pin by checking the input
    bool root : 1; // 1 bit for root status
}user;

typedef struct s_stdce{ // standard control entry structure
    unsigned char act : 3; // 3 bits for action
    network net; // network structure

}stdace;

typedef stdace stdacl[ACL_SIZE]; // access control list with max 100 entries

typedef struct s_rootkey{
    uint32_t key; // 10 bits for rootkey
    uint32_t n : 23; // 23 bits for hashing rounds (0-8000000)
}rootkey;

typedef enum 
{   low = 1, 
    medium = 5, 
    high = 15
}
sec_level;

typedef struct s_interface
{
    unsigned char id : 3; //3 bits - 8 interfaces
    uint64_t mac; //* To check the input for 48 bits instead of 64
    network net; //network structure
    struct {
        bool l1 : 1;
        bool l3 : 1;
    };
    unsigned char zone_name[16]; // Zone name up to 15 characters + null terminator
    sec_level level; //security level as enum 
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
    uint32_t count;// Number of values
    uint32_t size; // Actual size of the dynamic array
    uint32_t capacity; // The capacity the array can hold for now - DYNAMIC
    uint32_t *data; // The data stored in a dynamic array - can be at any type
}dynamic;

dynamic* dynMake_(unsigned int);


void dynAdd(dynamic* arr, void* val);
