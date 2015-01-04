#include <stdint.h>

struct modifier;

struct modifier *modifier_alloc(void);
void modifier_free(struct modifier *modifier);
void packet_seen(struct modifier *modifier, const char *prefix, char *buf, ssize_t len);

