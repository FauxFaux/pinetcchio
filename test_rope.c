#include <tap.h>
#include <string.h>
#include "rope.h"

static void empty_rope_is_empty() {
    rope *r = rope_new_empty();
    ok(0 == rope_len(r));
    rope_free(r);
}

static void append_to_empty_rope() {
    rope *r = rope_new_empty();
    rope_append(r, strdup("foo"), 3);
    ok(3 == rope_len(r));
    rope_free(r);
}

static void append_to_non_empty_rope() {
    rope *r = rope_new_empty();
    rope_append(r, strdup("foo"), 3);
    rope_append(r, strdup("space"), 5);
    ok(8 == rope_len(r));
    rope_free(r);
}

static void consume_from_partitioned_rope() {
    rope *r = rope_new_empty();
    rope_append(r, strdup("foo"), 3);
    rope_append(r, strdup("space"), 5);
    char buf[6];
    ok(2 == rope_consume(&r, buf, 2));
    ok(buf[0] == 'f');
    ok(buf[1] == 'o');

    ok(2 == rope_consume(&r, buf, 2));
    ok(buf[0] == 'o');
    ok(buf[1] == 's');

    ok(4 == rope_consume(&r, buf, 4));
    ok(buf[0] == 'p');
    ok(buf[1] == 'a');
    ok(buf[2] == 'c');
    ok(buf[3] == 'e');

    ok(0 == rope_consume(&r, buf, 4));
    ok(0 == rope_consume(&r, buf, 4));

    rope_free(r);
}


int main() {
    plan(16);

    empty_rope_is_empty();
    append_to_empty_rope();
    append_to_non_empty_rope();
    consume_from_partitioned_rope();

    done_testing();
}
