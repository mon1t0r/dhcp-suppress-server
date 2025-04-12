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

struct dhcp_msg {
    uint8_t opcode;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
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

typedef ssize_t dhcp_opt_offset;

void dhcp_opt_begin(struct dhcp_msg *msg, dhcp_opt_offset *offset);
void dhcp_opt(struct dhcp_msg *msg, dhcp_opt_offset *offset, enum dhcp_opt opt,
              const void *opt_data, size_t opt_data_len);
void dhcp_opt_end(struct dhcp_msg *msg, dhcp_opt_offset *offset);
ssize_t dhcp_opt_get(struct dhcp_msg *msg, enum dhcp_opt opt,
                     uint8_t **opt_data_ptr);

#endif
