#ifndef DHCP_SUP_SERVER_OPTIONS_H
#define DHCP_SUP_SERVER_OPTIONS_H

#include <stdint.h>

#include "dhcp.h"

struct dhcp_server_options {
    uint16_t dhcp_server_port;
    uint16_t dhcp_client_port;
    net_addr_t orig_dhcp_ip;
    hw_addr_t orig_dhcp_mac;
    net_addr_t my_dhcp_ip;
    hw_addr_t my_dhcp_mac;
    net_addr_t conf_client_ip;
    net_addr_t conf_network_mask;
    net_addr_t conf_router_ip;
    net_addr_t conf_broadcast_ip;
    net_addr_t conf_dns_ip;
};

struct dhcp_server_options options_dhcp_parse(int argc, char *argv[]);

#endif
