typedef struct nl_sock nl_sock;
typedef struct nl_cache nl_cache;

int make_nl(nl_sock **sk, struct nl_cache **cache);
void free_nl(nl_sock *sk, struct nl_cache *cache);
int add_route(nl_sock *sk, int ifindex, const char *gateway);
int set_addr(
    nl_sock *sk,
    nl_cache *cache,
    char *dev,
    const char *address,
    const char *via
);

int tun_alloc(char *out_if_name);
