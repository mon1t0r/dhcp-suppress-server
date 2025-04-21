#ifndef DHCP_SUP_SERVER_DHCP_H
#define DHCP_SUP_SERVER_DHCP_H

#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

enum {
    dhcp_chaddr_len   = 16,
    dhcp_sname_len    = 64,
    dhcp_filename_len = 128,
    dhcp_options_len  = 312
};

/* Hardware address data type */
/* Type size can be greater, than is needed to store hardware address */
typedef uint64_t hw_addr_t;
/* Network address data type */
typedef uint32_t net_addr_t;
/* DHCP options filling offset */
typedef ssize_t dhcp_opt_off_t;

/* Macro for converting octets of network address to net_addr_t
 * (octets to number) in host byte order */
#define otonnet(i1, i2, i3, i4) \
    ((net_addr_t) i4        | (net_addr_t) (i3 << 8 ) | \
    ((net_addr_t) i2 << 16) | (net_addr_t) (i1 << 24))

/* Macro for converting octets of hardware address to hw_addr_t
 * (octets to number) in host byte order */
#define otonmac(m1, m2, m3, m4, m5, m6) \
    ((hw_addr_t) m6        | ((hw_addr_t) m5 << 8 ) | \
    ((hw_addr_t) m4 << 16) | ((hw_addr_t) m3 << 24) | \
    ((hw_addr_t) m2 << 32) | ((hw_addr_t) m1 << 40))

/* Macro for getting octet value from address (number to octets)
 * in network byte order */
#define ntoo(addr, octet) \
    ((char) ((addr >> 8 * octet) & 0xFF))

struct dhcp_msg {
    uint8_t opcode;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    net_addr_t ciaddr;
    net_addr_t yiaddr;
    net_addr_t siaddr;
    net_addr_t giaddr;
    uint8_t chaddr[dhcp_chaddr_len];
    char sname[dhcp_sname_len];
    char filename[dhcp_filename_len];
    uint32_t cookie;
    uint8_t options[dhcp_options_len];
} __attribute__((__packed__));

enum dhcp_opcode {
    dhcp_opcode_request = 1,
    dhcp_opcode_reply   = 2
};

enum dhcp_opt {
    dhcp_opt_subnet_mask       = 1,
    dhcp_opt_router            = 3,
    dhcp_opt_dns               = 6,
    dhcp_opt_broadcast_address = 28,
    dhcp_opt_address_time      = 51,
    dhcp_opt_msg_type          = 53,
    dhcp_opt_srv_id            = 54,
    dhcp_opt_err_msg           = 56,
    dhcp_opt_renewal_time      = 58,
    dhcp_opt_rebinding_time    = 59,
    dhcp_opt_break             = 255
};

enum dhcp_msg_type {
    dhcp_msg_type_discover = 1,
    dhcp_msg_type_offer,
    dhcp_msg_type_request,
    dhcp_msg_type_decline,
    dhcp_msg_type_ack,
    dhcp_msg_type_nak,
    dhcp_msg_type_release,
    dhcp_msg_type_inform
};

void dhcp_opt_begin(struct dhcp_msg *msg, dhcp_opt_off_t *offset);

void dhcp_opt(struct dhcp_msg *msg, dhcp_opt_off_t *offset, enum dhcp_opt opt,
              const void *opt_data, size_t opt_data_len);

void dhcp_opt_end(struct dhcp_msg *msg, dhcp_opt_off_t *offset);

ssize_t dhcp_opt_get(struct dhcp_msg *msg, enum dhcp_opt opt,
                     uint8_t **opt_data_ptr);

#endif
