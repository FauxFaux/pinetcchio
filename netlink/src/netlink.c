#include <errno.h>

#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/route/route.h>

/** @return 0 on success, <0 if no errno, >0 if errno */
int32_t make_nl(
        struct nl_sock **sk,
        struct nl_cache **cache
        ) {
    *sk = nl_socket_alloc();

    if (!*sk) {
        if (!errno) {
            return -1;
        }

        return errno;
    }

    if (nl_connect(*sk, NETLINK_ROUTE)) {
        int ret = errno;
        perror("nl_connect");
        nl_socket_free(*sk);
        *sk = NULL;
        if (!ret) {
            return -2;
        }
        return ret;
    }

    *cache = NULL;
    if (rtnl_link_alloc_cache(*sk, AF_UNSPEC, cache)) {
        int ret = errno;
        perror("alloc_cache");
        nl_close(*sk);
        nl_socket_free(*sk);
        *sk = NULL;
        *cache = NULL;
        if (!ret) {
            return -3;
        }
        return errno;
    }

    return 0;
}

void free_nl(
        struct nl_sock *sk,
        struct nl_cache *cache
        ) {
    if (sk) {
        nl_close(sk);
        nl_socket_free(sk);
    }
    if (cache) {
        nl_cache_free(cache);
    }
}

int32_t link_name_index(struct nl_cache *cache, const char *name) {
    return rtnl_link_name2i(cache, name);
}

int32_t add_route(
        int family,
        struct nl_sock *sk,
        int ifindex,
        struct nl_addr *gateway_addr
        ) {

    int ret = -7;

    struct rtnl_route *route = rtnl_route_alloc();
    struct rtnl_nexthop *next_hop = rtnl_route_nh_alloc();
    struct nl_addr *default_addr = nl_addr_build(family, NULL, 0);

    if (!route || !next_hop || !default_addr) {
        goto done;
    }

    rtnl_route_nh_set_ifindex(next_hop, ifindex);
    rtnl_route_nh_set_gateway(next_hop, gateway_addr);

    ret = rtnl_route_set_dst(route, default_addr);
    if (0 != ret) {
        nl_perror(ret, "rtnl_route_set_dst(default)");
        goto done;
    }

    rtnl_route_add_nexthop(route, next_hop);

    ret = rtnl_route_add(sk, route, 0);
    if (0 != ret) {
        nl_perror(ret, "route_add");
        goto done;
    }

done:
    if (default_addr) {
        nl_addr_put(default_addr);
    }
    if (gateway_addr) {
        nl_addr_put(gateway_addr);
    }
    if (route) {
        rtnl_route_put(route);
    }

    return ret;
}

/**
 * @param hint AF_INET, AF_INET6
 * @return NULL on error, but possibly also for fun?
 */
struct nl_addr *parse_inet_address(int family, const char *text) {
    struct nl_addr *addr = NULL;
    if (nl_addr_parse(text, family, &addr)) {
        return NULL;
    }
    return addr;
}

/**
 * @param hint AF_INET, AF_INET6
 * @return NULL on error
 */
struct nl_addr *build_inet_address(int family, const char *buf, size_t len) {
    return nl_addr_build(family, buf, len);
}
