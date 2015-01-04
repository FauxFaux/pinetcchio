#include <stdint.h>

enum direction { DIR_OUT, DIR_IN };
struct modifier;

struct modifier *modifier_alloc(void);
void modifier_free(struct modifier *modifier);
void packet_seen(
        struct modifier *modifier,
        enum direction direction,
        char *buf,
        ssize_t len);

