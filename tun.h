int make_nl(struct nl_sock **sk, struct nl_cache **cache);
void free_nl(struct nl_sock *sk, struct nl_cache *cache);
int add_route(struct nl_sock *sk, int ifindex, const char *gateway);
int set_addr(
    struct nl_sock *sk,
    struct nl_cache *cache,
    char *dev,
    const char *address,
    const char *via
);

int tun_alloc(char *out_if_name);
