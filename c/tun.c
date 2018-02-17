#define _GNU_SOURCE 1

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <memory.h>

#include <getopt.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <linux/if.h>
#include <linux/if_tun.h>
#include <sched.h>

#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/route/route.h>

#include "tun.h"

int make_nl(
        struct nl_sock **sk,
        struct nl_cache **cache
        ) {
    *sk = nl_socket_alloc();
    assert(*sk);

    if (nl_connect(*sk, NETLINK_ROUTE)) {
        perror("nl_connect");
        nl_socket_free(*sk);
        *sk = NULL;
        return -1;
    }

    *cache = NULL;
    if (rtnl_link_alloc_cache(*sk, AF_UNSPEC, cache)) {
        perror("alloc_cache");
        nl_close(*sk);
        nl_socket_free(*sk);
        *sk = NULL;
        *cache = NULL;
        return -2;
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

int add_route(
        struct nl_sock *sk,
        int ifindex,
        const char *gateway
        ) {
    int ret = -1;

    struct rtnl_route *route = rtnl_route_alloc();
    assert(route);

    struct rtnl_nexthop *next_hop = rtnl_route_nh_alloc();
    assert(next_hop);

    struct nl_addr *default_addr = nl_addr_build(AF_INET, NULL, 0);
    assert(default_addr);

    struct nl_addr *gateway_addr = NULL;
    if (nl_addr_parse(gateway, AF_INET, &gateway_addr)) {
        perror("gateway parse");
        goto done;
    }

    rtnl_route_nh_set_ifindex(next_hop, ifindex);
    rtnl_route_nh_set_gateway(next_hop, gateway_addr);

    rtnl_route_set_dst(route, default_addr);
    rtnl_route_add_nexthop(route, next_hop);

    if (rtnl_route_add(sk, route, 0) < 0) {
        perror("route add");
        goto done;
    }

    ret = 0;
done:
    nl_addr_put(default_addr);
    nl_addr_put(gateway_addr);
    rtnl_route_put(route);
    return ret;
}

int set_addr(
        struct nl_sock *sk,
        struct nl_cache *cache,
        char *dev,
        const char *address,
        const char *via
        ) {
    int ret = -1;
    struct rtnl_addr *addr = rtnl_addr_alloc();
    assert(addr);

    const int ifindex = rtnl_link_name2i(cache, dev);
    if (!ifindex) {
        fprintf(stderr, "error: name2i couldn't find new device '%s'\n", dev);
        goto done;
    }

    rtnl_addr_set_ifindex(addr, ifindex);

    struct nl_addr *local_addr = NULL;
    if (nl_addr_parse(address, AF_INET, &local_addr)) {
        perror("local parse");
        goto done;
    }

    if (rtnl_addr_set_local(addr, local_addr)) {
        perror("set local");
        goto done;
    }

    rtnl_addr_set_prefixlen(addr, 24);

    if (rtnl_addr_add(sk, addr, 0)) {
        perror("addr add");
        goto done;
    }

    if (via && add_route(sk, ifindex, via) < 0) {
        goto done;
    }

    ret = 0;
done:
    rtnl_addr_put(addr);
    return ret;
}

int tun_alloc(char *out_if_name) {
    const char *clone_from = "/dev/net/tun";

    int fd = open(clone_from, O_RDWR);
    if (fd < 0) {
        return fd;
    }

    int sock = 0;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(struct ifreq));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        perror("creating tun device (set iff)");
        goto fail;
    }

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("create socket");
        goto fail;
    }

    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        perror("get status");
        goto fail;
    }

    ifr.ifr_flags |= IFF_UP;

    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        perror("set status");
        goto fail;
    }

    if (out_if_name) {
        strcpy(out_if_name, ifr.ifr_name);
    }

    goto done;
fail:
    close(fd);
    fd = -1;

done:
    close(sock);
    return fd;
}

