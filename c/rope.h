#ifndef PINETCCHIO_ROPE_H
#define PINETCCHIO_ROPE_H

#include <stdint.h>

typedef struct rope rope;

struct rope {
    rope *next;
    char *buf;
    uint16_t off;
    uint16_t len;
};

rope *rope_new_empty(void);
void rope_free(rope *what);
void rope_append(rope *what, char *buf, uint16_t len);
size_t rope_consume(rope **from, char *restrict into, size_t how_much);

size_t rope_len(rope *what);

#endif //PINETCCHIO_ROPE_H
