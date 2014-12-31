#include <stdio.h>
#include <string.h>
#include <memory.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <netinet/in.h>
#include <sys/ioctl.h>

#include <linux/if.h>
#include <linux/if_tun.h>


static int tun_alloc() {
    const char *clone_from = "/dev/net/tun";

    int fd = open(clone_from, O_RDWR);
    if (fd < 0) {
        return fd;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(struct ifreq));

    ifr.ifr_flags = IFF_TAP;

    int err = ioctl(fd, TUNSETIFF, &ifr);
    if (err < 0) {
        close(fd);
        return err;
    }

    return fd;
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

