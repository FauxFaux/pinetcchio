#include <stdlib.h>
#include <string.h>

#include "rope.h"

rope *rope_new_empty() {
    return calloc(sizeof(rope), 1);
}

/** the number of available bytes in this rope, regardless of how it's stored */
size_t rope_len(rope *what) {
    if (!what) {
        return 0;
    }
    return what->len - what->off + rope_len(what->next);
}

/** O(items in rope); takes ownership of buf */
void rope_append(rope *what, char *buf, uint16_t len) {
    while (what->next) {
        what = what->next;
    }
    what->next = rope_new_empty();
    what->next->buf = buf;
    what->next->len = len;
}

static void free_chunk(rope *what) {
    free(what->buf);
    free(what);
}

rope *rope_consume_internal(rope *from, char *restrict into, size_t left_to_read, size_t *read_so_far) {
    const uint16_t chunk_available = from->len - from->off;
    uint8_t *const chunk_start = from->buf + from->off;

    if (chunk_available >= left_to_read) {
        // we can fulfil it all from here
        memcpy(into, chunk_start, left_to_read);
        from->off += left_to_read;
        *read_so_far += left_to_read;
        return from;
    }

    rope *next = from->next;

    memcpy(into, chunk_start, chunk_available);
    free_chunk(from);
    *read_so_far += chunk_available;

    if (!next) {
        return rope_new_empty();
    }

    return rope_consume_internal(next, into + chunk_available, left_to_read - chunk_available, read_so_far);
}

size_t rope_consume(rope **from, char *restrict into, size_t how_much) {
    size_t so_far = 0;
    *from = rope_consume_internal(*from, into, how_much, &so_far);
    return so_far;
}

/** frees the passed in object, its descendants and all held buffers */
void rope_free(rope *what) {
    if (!what) {
        return;
    }

    rope *next = what->next;
    free_chunk(what);
    rope_free(next);
}
