#ifndef DHCP_SUP_SERVER_OPTIONS_H
#define DHCP_SUP_SERVER_OPTIONS_H

#include <stdint.h>
#include <linux/if.h>

#include "dhcp.h"

struct srv_opts {
    char interface_name[IFNAMSIZ];
    uint16_t dhcp_server_port;
    uint16_t dhcp_client_port;
    net_addr_t orig_net_addr;
    hw_addr_t orig_hw_addr;
    net_addr_t my_net_addr;
    hw_addr_t my_hw_addr;
    net_addr_t conf_client_addr;
    net_addr_t conf_network_mask;
    net_addr_t conf_router_addr;
    net_addr_t conf_broadcast_addr;
    net_addr_t conf_dns_addr;
    uint32_t conf_time_address;
    uint32_t conf_time_renewal;
    uint32_t conf_time_rebinding;
};

struct srv_opts options_parse(int argc, char *argv[]);

void options_print(const struct srv_opts *options);

#endif
