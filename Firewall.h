#include <stdio.h>

/*
interface e0/0 --
interface number
name: insider/dmz/outsider
MAC address of the interface
IP address of the interface 
security level 0 - e(Hexadecimal, 0 - 16 decimal)

*/

typedef unsigned int inter_num;
typedef unsigned long long mac_address;
typedef unsigned long int ip_address;
typedef unsigned long int CIDR;

struct s_network
{
    ip_address ip;
    CIDR subnet : 24;
}network;



//0000.0000.0000.0000
//0000.0000
struct s_interface
{
    inter_num id : 3; //3 bits - 8 interfaces
    mac_address : 48; //48 bits for mac_address
    
};
