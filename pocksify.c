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

#include <sys/types.h>
#include <sys/mount.h>
#include <sys/wait.h>

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

int main(int argc, char *argv[]) {
    uid_t real_euid = geteuid();
    gid_t real_egid = getegid();;

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
    execvp(argv[optind], argv + optind);
    perror("couldn't execve");
}

