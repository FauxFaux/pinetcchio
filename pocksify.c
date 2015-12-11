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

#include <uv.h>
#include <assert.h>
#include <string.h>

#include "tun.h"
#include "app.h"

static void tmpdir(char *buf) {
    char *sock_dir = strdup("/tmp/pocksify.XXXXXX");
    assert(mkdtemp(sock_dir));
    strcpy(buf, sock_dir);
    free(sock_dir);
}

static int drop_setgroups() {
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

void hex_dump(const char *buf, const ssize_t len) {
    for (ssize_t i = 0; i < len; ++i) {
        if (i % 16 == 0) {
            printf("\nhurr durr imma snek: ");
        }
        printf("%02x ", (uint8_t) buf[i]);
    }
    printf("\n");
}

uint8_t protocol_of(char *base) {
    return (uint8_t) base[9];
}

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    *buf = uv_buf_init((char*) malloc(suggested_size), suggested_size);
}

struct pending_dns_query {
    uv_buf_t buf;
    uint16_t sport;
};

void on_write(uv_write_t* req, int status) {
}

void on_read(uv_stream_t* tcp, ssize_t nread, uv_buf_t *buf) {
    printf("a response %zd\n", nread);
    if (nread < 0) {
        printf("%s\n", uv_strerror(nread));
    }
    hex_dump(buf->base, nread);
}

void on_connect(uv_connect_t* connection, int status) {
    uv_stream_t* stream = connection->handle;

    uv_write_t request;

    struct pending_dns_query *pending = (struct pending_dns_query*)connection->data;
    printf("connected, writing %p, %lu\n", pending, pending->buf.len);
    uv_write(&request, stream, &pending->buf, 1, on_write);
    uv_read_start(stream, alloc_buffer, on_read);
}

void tun_to_escape_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    if (nread < 0) {
        if (nread == UV_EOF) {
            // TODO: end of file
//            uv_close((uv_handle_t *)&stdin_pipe, NULL);
        }
        return;
    }
    if (nread == 0) {
        return;
    }

    uv_write_t req;
    uv_write(&req, stream->data, buf, 1, NULL);
}

char *memdup(const char *udp, size_t len) {
    char *ret = malloc(len);
    assert(ret);
    memcpy(ret, udp, len);
    return ret;
}

void read_tcp(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    if (nread < 0){
        if (nread == UV_EOF){
            // TODO: end of file
//            uv_close((uv_handle_t *)&stdin_pipe, NULL);
        }
        return;
    }
    if (nread == 0) {
        return;
    }

    assert(nread > 20);
    
    switch (protocol_of(buf->base)) {
        case IPPROTO_UDP: {
            uint16_t sport, dport, len;
            const char *udp = extract_udp(buf->base, nread, &sport, &dport, &len);
            printf("udp: %d %d %d\n", sport, dport, len);

            switch (dport) {
                case 53: { // DNS yolo
                    uv_tcp_t* socket = malloc(sizeof(uv_tcp_t));
                    assert(socket);
                    uv_tcp_init(uv_default_loop(), socket);

                    uv_connect_t* connect = malloc(sizeof(uv_connect_t));
                    struct sockaddr_in dest;
                    uv_ip4_addr("8.8.4.4", 53, &dest);

                    struct pending_dns_query *pending = calloc(sizeof(struct pending_dns_query), 1);
                    pending->buf.base = malloc(2 + len); // over-allocated
                    assert(pending->buf.base);
                    pending->buf.base[0] = 0; // TODO: YOLO
                    pending->buf.base[1] = (uint8_t) (len - 8);
                    memcpy(pending->buf.base + 2, udp, len - 8 + 2);

                    pending->buf.len = len - 8 + 2;
                    pending->sport = sport;
                    // whatevs
                    connect->data = pending;

                    uv_tcp_connect(connect, socket, (const struct sockaddr*)&dest, on_connect);
                } break;
                default:
                    printf("unknown udp traffic\n");
                    hex_dump(udp, len);
                    break;
            }
        } break;
        default:
            printf("unknown traffic type\n");
            hex_dump(buf->base, nread);
            break;
    }


    if (buf->base) {
        free(buf->base);
    }
}


static uv_pipe_t *pipe_to_fd(int fd) {
    uv_pipe_t *pipe = malloc(sizeof(uv_pipe_t));
    assert(pipe);
    uv_pipe_init(uv_default_loop(), pipe, false);
    uv_pipe_open(pipe, fd);
    return pipe;
}

static int worker(int tun_fd, int escape_namespace_fd) {
    int forked = fork();

    if (forked < 0) {
        return forked;
    }

    if (forked > 0) {
        return 0;
    }

    //prctl(PR_SET_PDEATHSIG, SIGQUIT);
    fclose(stdin);

    uv_loop_t *loop = malloc(sizeof(uv_loop_t));
    assert(loop);
    uv_loop_init(loop);

    uv_pipe_t *tun_pipe = pipe_to_fd(tun_fd);
    uv_pipe_t *escape_pipe = pipe_to_fd(escape_namespace_fd);

    tun_pipe->data = escape_pipe;
    uv_read_start(tun_pipe, alloc_buffer, tun_to_escape_read);

    uv_run(uv_default_loop(), UV_RUN_DEFAULT);

    uv_loop_close(uv_default_loop());
    free(loop);

    return 0;
}

static int enter_namespace(bool become_fake_root, int escape_namespace_fd) {
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
    printf("child tun: %s\n", child_tun_name);

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

    err = worker(tun_child, escape_namespace_fd);

done:
    free_nl(sk, cache);
    return err;
}

static int copy_out_of_namespace(int escape_namespace_fd) {
    pid_t worker = fork();
    if (worker > 0) {
        // parent
        return 0;
    }

    if (worker < 0) {
        // error
        return worker;
    }

    fclose(stdin);

    uv_loop_t *loop = malloc(sizeof(uv_loop_t));
    assert(loop);
    uv_loop_init(loop);

    uv_pipe_t *pipe = pipe_to_fd(escape_namespace_fd);
    uv_read_start(pipe, alloc_buffer, read_tcp);

    uv_run(uv_default_loop(), UV_RUN_DEFAULT);

    uv_loop_close(uv_default_loop());
    free(loop);

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

    char buf[64];
    tmpdir(buf);
    strcat(buf, "/escape");
    assert(!mkfifo(buf, 0700));
    int escape_namespace_fd = open(buf, O_RDWR);
    assert(escape_namespace_fd >= 0);

    int err;
    if ((err = copy_out_of_namespace(escape_namespace_fd))) {
        return err;
    }

    if ((err = enter_namespace(become_fake_root, escape_namespace_fd))) {
        return err;
    }

    execvp(argv[optind], argv + optind);
    perror("couldn't execve");
}
