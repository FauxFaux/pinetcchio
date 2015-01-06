// unistd needed for ssize_t
#include <unistd.h>

int do_a_send(int to, const char *buf, size_t found);

enum direction { DIR_OUT, DIR_IN };
struct modifier;

struct modifier *modifier_alloc(int in_fd, int out_fd);
void modifier_free(struct modifier *modifier);
void packet_seen(
        struct modifier *modifier,
        enum direction direction,
        char *buf,
        ssize_t len);


struct tcb;
struct tcb *tcp_alloc(void);
void tcp_consume(struct tcb *tcb, const char *buf, size_t len);
void tcp_free(struct tcb *tcb);

