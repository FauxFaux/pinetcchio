#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <memory.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#include <netlink/route/addr.h>
#include <netlink/route/link.h>

static int set_addr(char *dev) {
    struct nl_sock *sk = nl_socket_alloc();
    assert(sk);

    if (nl_connect(sk, NETLINK_ROUTE)) {
        perror("nl_connect");
        nl_close(sk);
        return -1;
    }

    int ret = -1;
    struct rtnl_addr *addr = rtnl_addr_alloc();
    assert(addr);

    struct nl_cache *cache = NULL;
    if (rtnl_link_alloc_cache(sk, AF_UNSPEC, &cache)) {
        perror("alloc_cache");
        goto done;
    }

    const int ifindex = rtnl_link_name2i(cache, dev);
    if (!ifindex) {
        perror("name2i");
        goto done;
    }

    rtnl_addr_set_ifindex(addr, ifindex);

    struct nl_addr *local_addr = NULL;
    if (nl_addr_parse("192.168.211.2", AF_INET, &local_addr)) {
        perror("local parse");
        goto done;
    }

    if (rtnl_addr_set_local(addr, local_addr)) {
        perror("set local");
        goto done;
    }

    if (rtnl_addr_add(sk, addr, 0)) {
        perror("addr add");
        goto done;
    }

    ret = 0;
done:
    rtnl_addr_put(addr);
    nl_cache_free(cache);
    nl_close(sk);
    nl_socket_free(sk);

    return ret;
}

static int tun_alloc() {
    const char *clone_from = "/dev/net/tun";

    int fd = open(clone_from, O_RDWR);
    if (fd < 0) {
        return fd;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(struct ifreq));

    ifr.ifr_flags = IFF_TAP;

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        goto fail;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        goto fail;
    }

    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        goto sockfail;
    }

    ifr.ifr_flags |= IFF_UP;

    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        goto sockfail;
    }

    set_addr(ifr.ifr_name);

    close(sock);
    return fd;

sockfail:
    close(sock);
fail:
    close(fd);
    return -1;
}

int main() {
    int tun = tun_alloc();
    if (tun < 0) {
        fprintf(stderr, "couldn't create tunnel: %s\n", strerror(errno));
        return 1;
    }
    sleep(10000);
    close(tun);
    return 0;
}

