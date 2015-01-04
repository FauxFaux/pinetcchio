#include <stdio.h>
#include <stdint.h>

#include <arpa/inet.h>

#include "app.h"

void print_packet(const char *prefix, char *buf, ssize_t len) {
    int ip_header_length = (*buf & 0x0f) * 4;
    const char *tcp = buf + ip_header_length;
    printf("%s: %4ld %2d (%5d -> %5d)\n", prefix, len,
            *(buf+9),                     // ip protocol
            ntohs(*(uint16_t*)tcp),       // src port
            ntohs(*(((uint16_t*)tcp)+4))  // dest port
            );
}

