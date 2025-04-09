#ifndef DHCP_SUP_SERVER_DHCP_H
#define DHCP_SUP_SERVER_DHCP_H

#include <stdint.h>

enum {
    dhcp_chaddr_len =   16,
    dhcp_sname_len =    64,
    dhcp_filename_len = 128,
    dhcp_options_len =  312
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


#endif
