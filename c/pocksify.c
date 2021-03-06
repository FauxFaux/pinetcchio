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

#include <pcap/pcap.h>

#include "tun.h"
#include "app.h"

static const uint64_t TAG = 0x1234567890;

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
            printf("\nhexdump: ");
        }
        printf("%02x ", (uint8_t) buf[i]);
    }
    printf("\n");
}

uint8_t protocol_of(char *base) {
    return (uint8_t) base[9];
}

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    *buf = uv_buf_init((char*) calloc(1, suggested_size), suggested_size);
}

struct pending_dns_query {
    uv_buf_t buf;
    uint16_t sport;
    char source_address[4];
    char dest_address[4];
};

void on_write(uv_write_t* req, int status) {
}

void on_read_tcp_response(uv_stream_t *tcp, ssize_t nread, uv_buf_t *buf) {
    printf("outside-worker: a response of %zd bytes being sent back to the captive\n", nread);

    if (nread < 0) {
        if (UV_EOF == nread) {
            uv_close((uv_handle_t*) tcp, NULL);
            return;
        }

        printf("%s\n", uv_strerror(nread));
        return;
    }
//    rope *r = rope_new_empty();
//    rope_append(r, buf->base, buf->len);
//    rope_consume()
    assert(0 == buf->base[0]);
    uint8_t len = buf->base[1];

    assert(len == (nread - 2));

    hex_dump(buf->base, nread);

    uv_stream_t *to_captive = uv_default_loop()->data;
    uv_buf_t resp = { calloc(len + 20 + 8, 1), len + 20 + 8};
    struct pending_dns_query *pending = (struct pending_dns_query*)tcp->data;
    make_udp(resp.base,
             pending->dest_address,
             pending->source_address,
             53, pending->sport, buf->base + 2, nread - 2);
    uv_write_t request = {};

    assert(to_captive);
    assert(resp.base);
    assert(resp.len);
    uv_write(&request, to_captive, &resp, 1, NULL);

//    hex_dump(buf->base, nread);
}

void on_connect(uv_connect_t* connection, int status) {
    uv_stream_t* stream = connection->handle;

    uv_write_t request = {};

    struct pending_dns_query *pending = (struct pending_dns_query*)stream->data;
    printf("connected, writing %p, %lu\n", pending, pending->buf.len);
    uv_write(&request, stream, &pending->buf, 1, on_write);
    uv_read_start(stream, alloc_buffer, on_read_tcp_response);
}

struct dumpable_pipe {
    uint64_t tag;
    uv_pipe_t *pipe;
    pcap_dumper_t *dumper;
};

void uread_copy_to_data(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    struct dumpable_pipe *dumpable = stream->data;
    printf("outside-worker: %zd bytes are being bridged from %p to %p\n", nread, stream, dumpable->pipe);

    if (nread < 0) {
        if (nread == UV_EOF) {
//            uv_close((uv_handle_t *)stream, NULL);
        }
        return;
    }

    if (nread == 0) {
        return;
    }


    assert(buf->base);

    printf("outside-worker: data == %p\n", dumpable);
    printf("outside-worker: data->tag == %lu\n", dumpable->tag);

    hex_dump(buf->base, nread);

    struct timeval now;
    gettimeofday(&now, NULL);
    uint32_t include_capture;
    if (nread < UINT32_MAX) {
        include_capture = (uint32_t) nread;
    } else {
        include_capture = UINT32_MAX;
    }
    struct pcap_pkthdr header = {.caplen = include_capture, .len = include_capture, .ts= now};
    printf("outside-worker: pcap_dump(%p, %p, %p);\n", dumpable->dumper, &header, buf->base);
    pcap_dump(dumpable->dumper, &header, buf->base);

    printf("outside-worker: dumping\n");

    pcap_dump_flush(dumpable->dumper);

    printf("outside-worker: dumped\n");

    uv_write_t req = {};
    uv_write(&req, dumpable->pipe, buf, 1, NULL);
    printf("outside-worker: written\n");
}

char *memdup(const char *udp, size_t len) {
    char *ret = malloc(len);
    assert(ret);
    memcpy(ret, udp, len);
    return ret;
}

void read_tcp(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    printf("%zd bytes in a %zu buffer arrived for destructing\n", nread, buf->len);
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

//    hex_dump(buf->base, nread);

    assert(nread > 20);

    switch (protocol_of(buf->base)) {
        case IPPROTO_UDP: {
            uint16_t sport, dport, len;
            char source_address[4], dest_address[4];
            const char *udp = extract_udp(buf->base, nread, &sport, &dport, &len, source_address, dest_address);
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
                    memcpy(pending->source_address, source_address, 4);
                    memcpy(pending->dest_address, dest_address, 4);

                    socket->data = pending;

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

    uv_pipe_t *tun_pipe = pipe_to_fd(tun_fd);
    uv_pipe_t *escape_pipe = pipe_to_fd(escape_namespace_fd);

    printf("tun: %p escape: %p\n", tun_pipe, escape_pipe);

    pcap_t *pcap = pcap_open_dead(DLT_RAW, 65536);
    assert(pcap);
    pcap_dumper_t *pdumper = pcap_dump_open(pcap, "/tmp/capture.pcap");
    assert(pdumper);

    struct dumpable_pipe *tun_dump = malloc(sizeof(struct dumpable_pipe));
    tun_dump->tag = TAG;
    tun_dump->pipe = tun_pipe;
    tun_dump->dumper = pdumper;

    struct dumpable_pipe *escape_dump = malloc(sizeof(struct dumpable_pipe));
    escape_dump->tag = TAG;
    escape_dump->pipe = escape_pipe;
    escape_dump->dumper = pdumper;

    tun_pipe->data = escape_dump;
    printf("tun_pipe->data == %p\n", tun_pipe->data);
    uv_read_start(tun_pipe, alloc_buffer, uread_copy_to_data);

    escape_pipe->data = tun_dump;
    printf("escape_pipe->data == %p\n", escape_pipe->data);
    uv_read_start(escape_pipe, alloc_buffer, uread_copy_to_data);

    uv_run(uv_default_loop(), UV_RUN_DEFAULT);

    uv_loop_close(uv_default_loop());

    pcap_close(pcap);
    pcap_dump_close(pdumper);

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


    uv_pipe_t *pipe = pipe_to_fd(escape_namespace_fd);
    uv_default_loop()->data = pipe;
    uv_read_start(pipe, alloc_buffer, read_tcp);

    uv_run(uv_default_loop(), UV_RUN_DEFAULT);

    uv_loop_close(uv_default_loop());

    return 0;
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

    int escape_fds[2];
    assert(0 == socketpair(AF_UNIX, SOCK_SEQPACKET, AF_UNIX, escape_fds));

    int err;
    if ((err = copy_out_of_namespace(escape_fds[0]))) {
        return err;
    }

    if ((err = enter_namespace(become_fake_root, escape_fds[1]))) {
        return err;
    }

    execvp(argv[optind], argv + optind);
    perror("couldn't execve");
}
