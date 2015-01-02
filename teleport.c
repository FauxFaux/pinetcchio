#define _GNU_SOURCE 1

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
#include <sys/wait.h>

#include <linux/if.h>
#include <linux/if_tun.h>
#include <sched.h>

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
    struct rtnl_link *link = NULL;
    struct rtnl_link *link_update = NULL;

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

    link = rtnl_link_get_by_name(cache, "eth0");
    assert(link);

    link_update = rtnl_link_alloc();

    rtnl_link_set_ns_pid(link_update, getpid());

    printf("trying to move link %s into pid %d", rtnl_link_get_name(link), getpid());
    int change_ret = rtnl_link_change(sk, link, link_update, 0);
    if (change_ret < 0) {
        fprintf(stderr, "teleporting failed: %s\n", nl_geterror(change_ret));
        goto done;
    }

    ret = 0;
done:
    rtnl_link_put(link_update);
    rtnl_link_put(link);
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
        perror("set iff");
        goto fail;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("create socket");
        goto fail;
    }

    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        perror("get status");
        goto sockfail;
    }

    ifr.ifr_flags |= IFF_UP;

    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        perror("set status");
        goto sockfail;
    }

    if (set_addr(ifr.ifr_name) < 0) {
        goto sockfail;
    }

    close(sock);
    return fd;

sockfail:
    close(sock);
fail:
    close(fd);
    return -1;
}

static int child_main(void *arg) {
    int tun = *(int*)arg;
    printf("%d\n", tun);
    system("ip r");
    system("ip a");
    sleep(10000);
    return 0;
}

int main() {
    int tun = tun_alloc();
    if (tun < 0) {
        return 1;
    }

    const int stack_size = 1024*1024;

    char *child_stack = malloc(stack_size);
    pid_t child = clone(child_main, child_stack + stack_size,
            SIGCHLD | CLONE_NEWNET | CLONE_FILES,
            &tun);
    if (child == -1) {
        perror("clone");
        return 2;
    }
    printf("launched child %d\n", child);
    waitpid(child, NULL, 0);
    close(tun);
    return 0;
}

