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

static int max (int left, int right) {
    return left > right ? left : right;
}

static int make_nl(
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

static void free_nl(
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

static int teleport_if(
        struct nl_sock *sk,
        struct nl_cache *cache,
        const char *dev,
        pid_t target_pid) {
    struct rtnl_link *link = NULL;
    struct rtnl_link *link_update = NULL;
    int ret = -1;

    link = rtnl_link_get_by_name(cache, dev);
    assert(link);

    link_update = rtnl_link_alloc();
    assert(link_update);

    rtnl_link_set_ns_pid(link_update, target_pid);

    int change_ret = rtnl_link_change(sk, link, link_update, 0);
    if (change_ret < 0) {
        fprintf(stderr, "teleporting failed: %s\n", nl_geterror(change_ret));
        goto done;
    }

    ret = 0;
done:
    rtnl_link_put(link_update);
    rtnl_link_put(link);
    return ret;
}

static int set_addr(
        struct nl_sock *sk,
        struct nl_cache *cache,
        char *dev,
        char *address
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

    ret = 0;
done:
    rtnl_addr_put(addr);
    return ret;
}

static int tun_alloc(char *out_if_name) {
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
        perror("set iff");
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

static int do_a_copy(int from, int to) {
#define buf_size 9000
    char buf[buf_size];

    ssize_t found = read(from, buf, buf_size);
    printf("found %ld bytes\n", found);
    if (found < 0) {
        perror("read from source");
        return -1;
    }
    ssize_t sent = write(to, buf, (size_t)found);
    if (sent != found) {
        perror("write to target");
        return -2;
    }

    return 0;
#undef buf_size
}

static int system_s(char **argv) {
    pid_t pid;
    switch (pid = fork()) {
        case -1:
            perror("fork");
            return -1;
        case 0: // child
            execv(argv[0], argv);
            fprintf(stderr, "child couldn't execve");
            return -2;
        default:
            if (waitpid(pid, NULL, 0) < 0) {
                perror("waitpid");
                return -3;
            }
            return 0;
    }
}

static int child_main(void *arg) {
    int ret = -1;
    struct nl_cache *cache = NULL;
    struct nl_sock *sk = NULL;

    int tun_host = *(int*)arg;

    char child_tun_name[IFNAMSIZ] = "";
    int tun_child = tun_alloc(child_tun_name);

    if (tun_child < 0) {
        goto done;
    }

    if (make_nl(&sk, &cache) < 0) {
        goto done;
    }

    if (set_addr(sk, cache, child_tun_name, "192.168.212.19") < 0) {
        goto done;
    }

    system_s((char *[]) { "/sbin/dhclient", "-v", "eth0", NULL });

    const int max_fd = max(tun_child, tun_host);

    while (1) {
        fd_set rd_set;
        FD_ZERO(&rd_set);
        FD_SET(tun_host, &rd_set);
        FD_SET(tun_child, &rd_set);

        int sel = select(max_fd + 1, &rd_set, NULL, NULL, NULL);

        if (sel < 0) {
            if (EINTR == errno) {
                continue;
            }
            perror("select");
            goto done;
        }

        if (FD_ISSET(tun_child, &rd_set)) {
            if (do_a_copy(tun_child, tun_host) < 0) {
                goto done;
            }
        }

        if (FD_ISSET(tun_host, &rd_set)) {
            if (do_a_copy(tun_host, tun_child) < 0) {
                goto done;
            }
        }
    }

#if 0
    while (1) {
        printf("route:\n");
        system("ip r");
        system("ip a");
        sleep(10);
    }
#endif


    ret = 0;
done:
    free_nl(sk, cache);
    return ret;
}

int main() {
    int ret = 1;
    struct nl_cache *cache = NULL;
    struct nl_sock *sk = NULL;
    int tun = -1;
    char host_tun_name[IFNAMSIZ] = "";

    tun = tun_alloc(host_tun_name);
    if (tun < 0) {
        goto done;
    }

    if (make_nl(&sk, &cache) < 0) {
        goto done;
    }

    if (set_addr(sk, cache, host_tun_name, "192.168.212.50") < 0) {
        goto done;
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

    if (teleport_if(sk, cache, "eth0", child) < 0) {
        return 3;
    }

    printf("launched child %d\n", child);
    waitpid(child, NULL, 0);

    ret = 0;
done:
    close(tun);

    nl_cache_free(cache);
    nl_close(sk);
    nl_socket_free(sk);


    return 0;
}

