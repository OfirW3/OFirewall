#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#define ACL_SIZE 99
#define BLOCK_SIZE 10 //Used in Firewall.c program
#define DECLARE_DYNAMIC(type, name) \
typedef struct { \
    type *data; \
    uint32_t size; \
    uint32_t capacity; \
} dynamic_##name; \
\
static void dynInit_##name(dynamic_##name *arr, unsigned int capacity) { \
    arr->data = NULL; \
    arr->size = 0; \
    arr->capacity = capacity; \
} \
\
static void dynInsertValue_##name(type value, dynamic_##name *arr) { \
    if (arr->size == arr->capacity) { \
        arr->capacity = arr->capacity * 2; \
    } \
    if (arr->capacity == 0) { \
        arr->capacity = 8; \
    } \
    arr->data = (type*)realloc(arr->data, sizeof(type) * arr->capacity); \
    if (arr->data == NULL) { \
        printf("Allocation failed"); \
        exit(1); \
    } \
    arr->data[arr->size] = value; \
    arr->size++; \
} \
\
static void dynRemoveByIndex_##name(unsigned int index, dynamic_##name *arr) { \
    if (index >= arr->size) return; \
    for (unsigned int i = index; i < arr->size - 1; i++) { \
        arr->data[i] = arr->data[i + 1]; \
    } \
    arr->size--; \
} \
\
static type *dynGetByIndex_##name(uint16_t index, dynamic_##name *arr) { \
    if (index < arr->size) return &arr->data[index]; \
    return NULL; \
} \
\
static void dynFree_##name(dynamic_##name *arr) { \
    free(arr->data); \
    arr->data = NULL; \
    arr->size = 0; \
    arr->capacity = 0; \
}
                                                                                         

enum e_action{
    permit = 1,
    drop = 2
};

typedef enum e_action action;

// To convert IP, PIN, KEY, MAC to MSB by htonl function when writing and convert back to LSB while readin with ntonl
typedef struct s_network
{
    uint32_t ip;
    uint8_t subnet;
}network;

typedef struct s_user{
    unsigned char *username;
    bool root;
}user;

typedef struct s_stdce{ // standard control entry structure
    action act; //For "Permit" or "Deny"
    network *net;
}stdace;

typedef stdace stdacl[ACL_SIZE]; // access control list with max 100 entries

typedef struct s_rootkey{
    unsigned char key_str[16];
    uint16_t hashing_rounds;
}rootkey;

typedef enum 
{   low = 1, 
    medium = 5, 
    high = 15
}
sec_level;

typedef struct s_interface {
    uint8_t id; 
    uint8_t mac[6];
    network net;
    struct {
        bool l1 : 1;
        bool l3 : 1;
    } shutdown;
    unsigned char zone_name[16];
    sec_level level;
    stdacl *aclin;
    stdacl *aclout;
} interface;

// Dynamic array declarations for interfaces and users. Now the functions declared inside the DYNAMIC_DECLARED are pasted here for each of the arrays.
DECLARE_DYNAMIC(interface, interfaces);
DECLARE_DYNAMIC(user, users);


typedef struct s_config{
    dynamic_interfaces *interfaces;
    dynamic_users *accounts; 
    rootkey key;
}config;



