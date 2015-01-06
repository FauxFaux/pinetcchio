#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include <arpa/inet.h>

#include "app.h"

#define tcp_assert assert
static const uint8_t IP_PROTOCOL_TCP = 6;
static const uint8_t IP_FLAG_DONT_FRAGMENT  = 1 << 6;
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
    return (uint8_t)buf[0] * 0x100
         + (uint8_t)buf[1];
}

static uint32_t read_uint32_t(const char *buf) {
    return (uint8_t)buf[0] * 0x1000000
         + (uint8_t)buf[1] * 0x10000
         + (uint8_t)buf[2] * 0x100
         + (uint8_t)buf[3];
}

enum conn_state {
    CONN_LISTENING,
    CONN_SYN_RECIEVED,
};

struct port_data {
    char *buf;
    int seq_from_client;
    int seq_to_client;
    int offset;
    enum conn_state conn_state;
};

struct tcb {
    struct port_data ports[MAX_PORT];
};

struct tcb *tcp_alloc() {
    return calloc(sizeof(struct tcb), 1);
}

void tcp_free(struct tcb *tcb) {
    if (!tcb) {
        return;
    }
    free(tcb);
}

void tcp_consume(struct tcb *tcb, const char *buf, size_t len) {
    tcp_assert(top_4_bits(buf[0]) == 4);
    const uint16_t ip_header_length = (buf[0] & 0x0f) * 32 / 8;
    tcp_assert(ip_header_length == 20);
    assert(len > 20);

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
        // TODO: send syn/ack
        port->conn_state = CONN_SYN_RECIEVED;
    }

    const char *data = buf + tcp_header_length;
}

