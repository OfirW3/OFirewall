#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#define ACL_SIZE 99
#define BLOCK_SIZE 10 //Used in Firewall.c program
#define DECLARE_DYNAMIC(type, name)                                                          \
typedef struct {                                                                             \
    type *data;                                                                              \
    uint32_t size;                                                                           \
    uint32_t capacity;                                                                       \
} dynamic_##name;                                                                            \
                                                                                             \
static void dynInit_##name(dynamic_##name *arr, unsigned int capacity) {                     \
    arr->data = NULL;                                                                        \
    arr->size = 0;                                                                           \
    arr->capacity = capacity;                                                                \
}            


#define static void dynInsertValue(type value, dynamic_##name *arr){                                \
    if(arr->size == arr->capacity){                                                          \
            arr->capacity = arr->capacity * 2;  \
    } \
    if(arr->capacity == 0){ \
        arr->capacity = 8;  \
    }\
    arr->data = realloc(arr->data, sizeof(value) + sizeof(arr->data));\
    if(data == null){ \
        printf("Allocation failed");\
    }\
    //Need more progress still \
}\

enum e_action{
    permit = 1,
    drop = 2
};

typedef enum e_action action;

typedef struct s_network
{
    uint32_t ip; // To convert to MSB by htonl function when writing and convert back to LSB while readin with ntonl
    uint8_t subnet;

}network;

typedef struct s_user{
    unsigned char username[16];
    uint16_t pin; // * Give only 10 bits for the pin by checking the input
    bool root : 1;
}user;

typedef struct s_stdce{ // standard control entry structure
    unsigned char act; //For "Permit" or "Deny"
    network net;

}stdace;

typedef stdace stdacl[ACL_SIZE]; // access control list with max 100 entries

typedef struct s_rootkey{
    uint32_t key;
    uint32_t n; //hashing rounds
}rootkey;

typedef enum 
{   low = 1, 
    medium = 5, 
    high = 15
}
sec_level;

typedef struct s_interface
{
    uint8_t id;
    uint8_t mac[6];
    network net;
    struct {
        bool l1 : 1;
        bool l3 : 1;
    };
    unsigned char zone_name[16];
    sec_level level;
    stdacl *aclin; //ACL for incoming packets
    stdacl *aclout; //ACL for outgoing packets
}interface;

//typedef struct s_config{//Might be removed later
    //dynamic *iface;
    //dynamic *account; // A dynamic array of users where void *data is user typed
    //rootkey key;
//}config;

