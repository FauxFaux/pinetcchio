#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <unistd.h>

#include <getopt.h>

#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <linux/if.h>

#include "tun.h"

static int drop_setgroups() {
    const char *deny = "deny";
    FILE *fd = fopen("/proc/self/setgroups", "w");

    if (NULL == fd) {
        if (errno == ENOENT) {
            return 0;
        }
        perror("couldn't deny setgroups, no file");
        return 2;
    }

    if (!fputs("deny", fd)) {
        perror("couldn't deny setgroups, write error");
        fclose(fd);
        return 3;
    }

    fclose(fd);

    return 0;
}

static int map_id(const char *file, uint32_t from, uint32_t to) {

    FILE *fd = fopen(file, "w");
    if (NULL == fd) {
        perror("opening map_id file");
        return 4;
    }

    char buf[10 + 10 + 1 + 2 + 1];
    sprintf(buf, "%u %u 1", from, to);
    if (!fputs(buf, fd)) {
        perror("couldn't write map_id file");
        fclose(fd);
        return 3;
    }

    fclose(fd);
    return 0;
}

static int worker(int tun) {
    int forked = fork();

    if (forked < 0) {
        return forked;
    }

    if (forked > 0) {
        return 0;
    }

    //prctl(PR_SET_PDEATHSIG, SIGQUIT);

    while (true) {
        const int mtu_guess = 9188;
        const int buf_size = mtu_guess+1;
        unsigned char buf[buf_size];
        ssize_t found = read(tun, buf, buf_size);
        if (found < 0 || found > mtu_guess) {
            perror("read from source");
            return 1;
        }

        for (ssize_t i = 0; i < found; ++i) {
            if (i % 16 == 0) {
                printf("\nhurr durr imma snek: ");
            }
            printf("%02x ", buf[i]);
        }
        printf("\n");
    }
}

static int enter_namespace(bool become_fake_root) {
    uid_t real_euid = geteuid();
    gid_t real_egid = getegid();

    if (-1 == unshare(CLONE_NEWNET | CLONE_NEWUSER)) {
        perror("unshare failed");
        return 1;
    }

    if (become_fake_root) {
        /* according to util-linux' source,
        * since Linux 3.19 unprivileged writing of /proc/self/gid_map
        * has been disabled unless /proc/self/setgroups is written
        * first to permanently disable the ability to call setgroups
        * in that user namespace. */
        int err;
        if ((err = drop_setgroups())) {
            return err;
        }
        if ((err = map_id("/proc/self/uid_map", 0, real_euid))) {
            return err;
        }
        if ((err = map_id("/proc/self/gid_map", 0, real_egid))) {
            return err;
        }
    }

    struct nl_sock *sk = NULL;
    struct nl_cache *cache = NULL;

    char child_tun_name[IFNAMSIZ] = "";
    int tun_child = tun_alloc(child_tun_name);

    int err = 0;
    if (tun_child < 0) {
        err = 2;
        goto done;
    }

    if (make_nl(&sk, &cache) < 0) {
        err = 3;
        goto done;
    }

    if (set_addr(sk, cache, child_tun_name, "192.168.33.2", "192.168.33.1") < 0) {
        err = 4;
        goto done;
    }

    err = worker(tun_child);

done:
    free_nl(sk, cache);
    return err;
}

int main(int argc, char *argv[]) {
    static struct option long_options[] = {
        { "root", no_argument, 0, 'r' },
        { 0,      0,           0, 0 }
    };

    bool become_fake_root = false;

    int long_index = 0;
    int opt;
    while ((opt = getopt_long(argc, argv, "+r",
                    long_options, &long_index)) != -1) {
        switch (opt) {
            case 'r':
                become_fake_root = true;
                break;
            default:
                fprintf(stderr, "usage: %s [-r] -- command\n", argv[0]);
                return 5;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "command is required\n");
        return 6;
    }

    int err;
    if ((err = enter_namespace(become_fake_root))) {
        return err;
    }

    execvp(argv[optind], argv + optind);
    perror("couldn't execve");
}

