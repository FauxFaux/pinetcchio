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

#include "app.h"
#include "tun.h"

static int max (int left, int right) {
    return left > right ? left : right;
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

int do_a_send(int to, const char *buf, size_t found) {
    ssize_t sent = write(to, buf, found);
    if (sent != found) {
        perror("write to target");
        return -2;
    }
    return 0;
}

static int do_a_copy(
        struct modifier *modifier,
        enum direction direction,
        int from, int to) {
#define mtu_guess 9198
#define buf_size (mtu_guess + 1 + sizeof(uint16_t))
    char buf[buf_size];

    ssize_t found = read(from, buf + sizeof(uint16_t), buf_size);
    if (found < 0 || found > mtu_guess) {
        perror("read from source");
        return -1;
    }

    *((uint16_t*)buf) = (uint16_t)found;

    packet_seen(modifier, direction, buf, found);

    return 0;
#undef buf_size
#undef mtu_guess
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

struct child_arg {
    const char *gw_ip;
    const char *phys_if;
    int tun_host;
    int flags;
};

static int child_main(void *void_arg) {
    int ret = -1;
    struct nl_cache *cache = NULL;
    struct nl_sock *sk = NULL;
    struct modifier *modifier = NULL;
    struct tcb *tcb = NULL;

    struct child_arg *arg = void_arg;

    const int tun_host = arg->tun_host;
    const char *gw_ip = arg->gw_ip;
    const char *phys_if = arg->phys_if;

    char child_tun_name[IFNAMSIZ] = "";
    int tun_child = tun_alloc(child_tun_name);

    if (tun_child < 0) {
        goto done;
    }

    if (make_nl(&sk, &cache) < 0) {
        goto done;
    }

    if (set_addr(sk, cache, child_tun_name, gw_ip, NULL) < 0) {
        goto done;
    }

    char *phys_if_dup[] = { strdup(phys_if), strdup(phys_if) };
    assert(phys_if_dup[0]);
    assert(phys_if_dup[1]);

    system_s((char *[]) { "/sbin/dhclient", "-v", phys_if_dup[0], NULL });
    system_s((char *[]) { "/sbin/iptables",
            "-t", "nat",
            "-A", "POSTROUTING",
            "-o", phys_if_dup[1],
            "-j", "MASQUERADE",
            NULL });

    free(phys_if_dup[0]);
    free(phys_if_dup[1]);

    modifier = modifier_alloc(tun_child, tun_host);
    assert(modifier);

    tcb = tcp_alloc();
    assert(tcb);

    const int max_fd = max(tun_child, tun_host);

    while (1) {
        fd_set rd_set, wr_set;
        FD_ZERO(&rd_set);
        FD_ZERO(&wr_set);
        FD_SET(tun_host, &rd_set);
        FD_SET(tun_child, &rd_set);

        tcp_fd_set(tcb, &rd_set, &wr_set);

        int sel = select(max_fd + 1, &rd_set, NULL, NULL, NULL);

        if (sel < 0) {
            if (EINTR == errno) {
                continue;
            }
            perror("select");
            goto done;
        }

        if (FD_ISSET(tun_child, &rd_set)) {
            if (do_a_copy(modifier, DIR_IN, tun_child, tun_host) < 0) {
                goto done;
            }
        }

        if (FD_ISSET(tun_host, &rd_set)) {
            if (do_a_copy(modifier, DIR_OUT, tun_host, tun_child) < 0) {
                goto done;
            }
        }

        tcp_fd_consume(tcb, &rd_set, &wr_set);
    }

    ret = 0;
done:
    free_nl(sk, cache);
    modifier_free(modifier);
    tcp_free(tcb);
    return ret;
}

int main(int argc, char **argv) {
    int ret = 1;
    struct nl_cache *cache = NULL;
    struct nl_sock *sk = NULL;
    int tun = -1;
    char host_tun_name[IFNAMSIZ] = "";

    char *host_ip = strdup("192.168.212.50");
    char *gw_ip = strdup("192.168.212.1");
    char *phys_if = strdup("em1");

    static struct option long_options[] = {
        {"interface", required_argument, 0,  'i' },
        {0,           0,                 0,   0  }
    };

    int long_index = 0;
    int opt;
    while ((opt = getopt_long(argc, argv, "i:",
                    long_options, &long_index )) != -1) {
        switch (opt) {
            case -1:
                break;
            case 'i':
                free(phys_if);
                phys_if = strdup(optarg);
                break;
            default:
                fprintf(stderr, "Usage: %s [-i em1]\n", argv[0]);
                goto done;
        }
    }

    tun = tun_alloc(host_tun_name);
    if (tun < 0) {
        goto done;
    }

    if (make_nl(&sk, &cache) < 0) {
        goto done;
    }

    if (set_addr(sk, cache, host_tun_name,
                host_ip, gw_ip) < 0) {
        goto done;
    }

    const int stack_size = 1024*1024;

    struct child_arg child_arg = { gw_ip, phys_if, tun, 0 };
    char *child_stack = malloc(stack_size);
    pid_t child = clone(child_main, child_stack + stack_size,
            SIGCHLD | CLONE_NEWNET | CLONE_FILES,
            &child_arg);
    if (child == -1) {
        perror("clone");
        return 2;
    }

    if (teleport_if(sk, cache, phys_if, child) < 0) {
        return 3;
    }


    printf("launched child %d\n", child);
    waitpid(child, NULL, 0);

    ret = 0;
done:
    close(tun);

    free_nl(sk, cache);

    return 0;
}

