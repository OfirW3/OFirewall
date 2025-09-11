#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#define ACL_SIZE 99
#define BLOCK_SIZE 10 //Used in Firewall.c program

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
    unsigned char username[16];
    uint16_t pin; // * Give only 10 bits for the pin by checking the input
    bool root : 1;
}user;

typedef struct s_stdce{ // standard control entry structure
    unsigned char act : 3; // 3 bits for action
    network net;

}stdace;

typedef stdace stdacl[ACL_SIZE]; // access control list with max 100 entries

typedef struct s_rootkey{
    uint32_t key;
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
    uint8_t id : 3;
    uint8_t mac[6];
    network net;
    struct {
        bool l1 : 1;
        bool l3 : 1;
    };
    unsigned char zone_name[16];
    sec_level level;
    stdacl *aclin; //ACL for incoming packets
    stdacl *aclout; //ACL for outcoming packets
}interface;

typedef struct s_config{
    interface *iface[7];
    dynamic account; // A dynamic array of users where void *data is user typed
    rootkey key;
}config;


typedef struct s_dynamic{
    void *data; // The data stored in a dynamic array - can be at any type
    uint32_t size; // Number of values in the array
    uint32_t capacity; // Total capacity of the array
}dynamic;

dynamic* dynMake_(unsigned int);


void dynAdd(dynamic* arr, void* val);
