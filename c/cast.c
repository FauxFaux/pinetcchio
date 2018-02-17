#include <stdint.h>
#include <string.h>

uint16_t one(const char *const c) {
    return *((uint16_t*)c);
}

uint16_t two(const char *const c) {
    return (uint8_t)*c + 256 * (uint8_t)*(c+1);
}

uint16_t three(const char *const c) {
    union {
        uint16_t ints;
        char chars[2];
    } x;

    x.chars[0] = c[0];
    x.chars[1] = c[1];
    return x.ints;
}

uint16_t four(const char* c)
{
    uint16_t u;
    memcpy(&u, c, 2);
    return u;
}

#if TEST
#include <stdio.h>
int main() {
    printf("%d %d %d\n",
            one("ab"),
            two("ab"),
            three("ab"));
}
#endif

