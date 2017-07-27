#include <errno.h>

#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/route/route.h>

/** @return 0 on success, <0 if no errno, >0 if errno */
int make_nl(
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
