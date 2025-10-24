#pragma once

// To convert IP, PIN, KEY, MAC to MSB by htonl function when writing and convert back to LSB while readin with ntonl
typedef struct s_network
{
    uint32_t ip;
    uint8_t subnet;
}network;

uint32_t make_ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d);
void print_ip(uint32_t ip);