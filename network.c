#include <stdio.h>
#include <stdint.h>
#include "network.h"

uint32_t make_ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d) { //To understand 
    return ((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | d;
}

void print_ip(uint32_t ip) {
    printf("%u.%u.%u.%u",
           (ip >> 24) & 0xFF,
           (ip >> 16) & 0xFF,
           (ip >> 8) & 0xFF,
           ip & 0xFF);
}
