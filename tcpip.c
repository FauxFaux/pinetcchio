#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>

#include "app.h"

#define tcp_assert assert
static const uint8_t IP_PROTOCOL_TCP = 6;
static const uint8_t IP_PROTOCOL_UDP = 17;
static const uint8_t IP_FLAG_DONT_FRAGMENT = 1 << 6;
static const uint8_t IP_FLAG_MORE_FRAGMENTS = 1 << 5;

static const uint8_t TCP_FLAG_ACK = 1 << 4;
static const uint8_t TCP_FLAG_RST = 1 << 2;
static const uint8_t TCP_FLAG_SYN = 1 << 1;
static const uint8_t TCP_FLAG_FIN = 1 << 0;


#define MAX_PORT 65535

static uint8_t top_4_bits(char byte) {
    return (byte & 0xf0) >> 4;
}

static uint16_t read_uint16_t(const char *buf) {
    return (uint8_t) buf[0] * 0x100
           + (uint8_t) buf[1];
}

static void write_uint32_t(char *buf, uint32_t val) {
    buf[0] = (char) (val >> 24) & 0xff;
    buf[1] = (char) (val >> 16) & 0xff;
    buf[2] = (char) (val >> 8) & 0xff;
    buf[3] = (char) (val) & 0xff;
}


static void write_uint16_t(char *buf, uint16_t val) {
    buf[0] = (char) (val >> 8) & 0xff;
    buf[1] = (char) (val) & 0xff;
}

static uint32_t read_uint32_t(const char *buf) {
    return (uint8_t) buf[0] * 0x1000000
           + (uint8_t) buf[1] * 0x10000
           + (uint8_t) buf[2] * 0x100
           + (uint8_t) buf[3];
}

enum conn_state {
    CONN_LISTENING,
    CONN_SYN_RECEIVED,
};

struct port_data {
    char *buf;
    int seq_from_client;
    int seq_to_client;
    int offset;
    int socks_socket;
    char dest[4];
    uint16_t dest_port;
    uint32_t sequence_out;
    enum conn_state conn_state;
};

struct tcb {
    struct port_data ports[MAX_PORT];
    struct waiting_port *waiting;
    char source[4];
};

struct tcb *tcp_alloc() {
    return calloc(sizeof(struct tcb), 1);
}

struct waiting_port {
    struct waiting_port *next;
    struct port_data *value;
    uint16_t source_port;
};

char *make_packet(char source_address[4],
                  uint16_t source_port,
                  char dest_address[4],
                  uint16_t dest_port,
                  uint32_t sequence_out);

void tcp_free(struct tcb *tcb) {
    if (!tcb) {
        return;
    }
    free(tcb);
}

static void insert_waiting_for_upstream_port(struct tcb *tcb, struct port_data *port) {
    struct waiting_port *head = tcb->waiting;
    tcb->waiting = malloc(sizeof(struct waiting_port));
    tcb->waiting->next = head;
    tcb->waiting->value = port;
}

void tcp_fd_set(struct tcb *tcb, fd_set *rd_set, fd_set *wr_set) {
    for (struct waiting_port *curr = tcb->waiting;
         NULL != curr;
         curr = curr->next) {
        // TODO read or write or whatever?
        FD_SET(curr->value->socks_socket, rd_set);
        FD_SET(curr->value->socks_socket, wr_set);
    }
}

void make_ip(char *ip,
             const char *source_address, const char *dest_address,
             const uint16_t total_size, uint8_t protocol_number) {
    const uint8_t IPV4 = 0x40;
    const uint8_t NO_EXTRA_HEADERS = 0x05;
    const uint8_t MAX_TTL = 0xff;

    ip[0] = IPV4 | NO_EXTRA_HEADERS;// Version concat IHL: number of extra headers
                                    // DSCP concat ECN: unused
    write_uint16_t(ip + 2, total_size);
    write_uint16_t(ip + 4, rand()); // identification: unclear what this is supposed to be
    ip[6] = IP_FLAG_DONT_FRAGMENT;  // flags: disable fragmentation, which I believe is impossible on tun anyway,
    // and mush the start of "fragmentation offset"
    // 6 (last bits) and 7: fragmentation offset: 0
    ip[8] = MAX_TTL;                // TTL
    ip[9] = protocol_number;        // Protocol number

    memcpy(ip + 12, source_address, 4);
    memcpy(ip + 16, dest_address, 4);

    set_ip_checksum(ip);
}

char *make_packet(char source_address[4],
                  uint16_t source_port,
                  char dest_address[4],
                  uint16_t dest_port,
                  uint32_t sequence_out) {

    const size_t ip_size = 20;
    const size_t tcp_size = 20;
    const size_t total_size = ip_size + tcp_size;
    char *ip = calloc(total_size, 1);

    make_ip(ip, source_address, dest_address, total_size, IP_PROTOCOL_TCP);

    char *tcp = ip + ip_size;

    write_uint16_t(tcp + 0, source_port);
    write_uint16_t(tcp + 2, dest_port);
    write_uint32_t(tcp + 4, sequence_out);
    write_uint32_t(tcp + 8, 0);      // Sequence number we're ACKing.  TODO: unimplemented
    tcp[12] = 0x50;                  // TCP header size concat reserved: Minimum 5: no options
    tcp[13] = TCP_FLAG_SYN | TCP_FLAG_ACK; // Flags.
    write_uint16_t(tcp + 14, 1460);  // window size; we're ignoring window scaling
    // 16: TODO: checksum
    // 18: urgent pointer (unused)

    return ip;
}

void tcp_fd_consume(struct tcb *tcb, fd_set *rd_set, fd_set *wr_set) {
    for (struct waiting_port *curr = tcb->waiting;
         NULL != curr;
         curr = curr->next) {
        int writable = FD_ISSET(curr->value->socks_socket, wr_set);
        if (writable && CONN_SYN_RECEIVED == curr->value->conn_state) {
            // TODO connection accepted, time to ACK the client
            char *ack = make_packet(tcb->source, curr->source_port,
                                    curr->value->dest, curr->value->dest_port,
                                    ++curr->value->sequence_out);

            // TODO: send it somewhere

            free(ack);
        }
    }
}

int header_length(const char *buf) { return (buf[0] & 0x0f) * 32 / 8; }

void tcp_consume(struct tcb *tcb, const char *buf, size_t len) {
    assert(len > 20);
    tcp_assert(top_4_bits(buf[0]) == 4);
    const uint16_t ip_header_length = header_length(buf);
    tcp_assert(ip_header_length == 20);

    // buf[1]: DSCP / ECN: unsupported
    const uint16_t ip_total_length = read_uint16_t(buf + 2);
    const uint16_t identifcation = read_uint16_t(buf + 4);

    // buf[6:7]: flags / fragmentation
            tcp_assert(buf[6] & IP_FLAG_DONT_FRAGMENT);

    // buf[8]: ttl (ignored)
    const uint8_t protocol = (uint8_t) buf[9];
    if (protocol != IP_PROTOCOL_TCP) {
        return;
    }
    assert(len > 40);

    // buf[10:11]: checksum (ignored)
    const char *source_ip = buf + 12;
    const char *dest_ip = buf + 16;

    // tcp time, yeah

    buf += ip_header_length;

    const uint16_t source_port = read_uint16_t(buf + 0);
    const uint16_t dest_port = read_uint16_t(buf + 2);
    const uint32_t sequence_number = read_uint32_t(buf + 4);
    const uint32_t ack_number = read_uint32_t(buf + 8);
    const uint32_t tcp_header_length = top_4_bits(buf[12]) * 32 / 8;
    const uint8_t main_flags = (uint8_t) buf[13];
    const uint16_t window_size = read_uint16_t(buf + 14);
    // buf[16:17]: checksum (ignored)
    // buf[18:19]: urgent pointer (ignored)
    // .. and I think we can ignore all the options

    struct port_data *const port = &tcb->ports[source_port];

    if (main_flags & TCP_FLAG_SYN) {
                tcp_assert(CONN_LISTENING == port->conn_state);
        port->socks_socket = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        assert(port->socks_socket > 0);

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(struct sockaddr_in));
        if (connect(port->socks_socket,
                    (struct sockaddr *) &addr,
                    sizeof(struct sockaddr_in))) {
                    tcp_assert(EINPROGRESS == errno);
        }

        insert_waiting_for_upstream_port(tcb, port);
        port->conn_state = CONN_SYN_RECEIVED;
        memcpy(port->dest, dest_ip, 4);
        port->dest_port = dest_port;
    }

    const char *data = buf + tcp_header_length;
}

const char *extract_udp(const char *buf, size_t len, uint16_t *sport, uint16_t *dport, uint16_t *length,
                        char *source_address, char *dest_address) {
    tcp_assert(len > 20);
    tcp_assert(top_4_bits(buf[0]) == 4);
    const uint16_t ip_header_length = header_length(buf);
    tcp_assert(ip_header_length == 20);

    memcpy(source_address, buf+12, 4);
    memcpy(dest_address,   buf+16, 4);

    // ignore the whole ip header

    buf += ip_header_length;
    *sport = read_uint16_t(buf+0);
    *dport = read_uint16_t(buf+2);
    *length = read_uint16_t(buf+4);

    buf += 8;
    return buf;
}

void set_ip_checksum(char *buf) {
    uint64_t sum = 0;
    uint16_t *as_words = (uint16_t *)buf;

    as_words[5] = 0;

    int hdr_len = 20;
    while (hdr_len > 1) {
        sum += *as_words++;
        if (sum & 0x80000000) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        hdr_len -= 2;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    ((uint16_t*)buf)[5] = (uint16_t) ~sum;
}

void set_udp_checksum_on_ip(char *buf) {
    uint64_t sum = 0;
    uint16_t *as_words = (uint16_t *)buf;

    // TODO
}

void make_udp(char *buf,
              const char *source_address, const char *dest_address,
              uint16_t sport, uint16_t dport,
              const char *data, size_t data_len) {
    assert(data_len < 65507);

    make_ip(buf, source_address, dest_address, 40 + data_len, IP_PROTOCOL_UDP);
    buf += 20;
    write_uint16_t(buf + 0, sport);
    write_uint16_t(buf + 2, dport);
    write_uint16_t(buf + 4, data_len + 8);
    write_uint16_t(buf + 6, 0); // checksum

    memcpy(buf + 8, data, data_len);
    set_udp_checksum_on_ip(buf);
}
