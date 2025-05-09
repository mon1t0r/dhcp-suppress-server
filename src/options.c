#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <arpa/inet.h>

#include "options.h"

static const char error_msg[] =
    "Usage: %s [OPTION]... [MY_ADDR] [MY_MAC]\n(%s)\n";

static const struct option longopts[] = {
    { "interface",           required_argument, NULL, 'I' },
    { "server-port",         required_argument, NULL, 'S' },
    { "client-port",         required_argument, NULL, 'C' },
    { "mac-table-size",      required_argument, NULL, 's' },
    { "mac-table-max-cnt",   required_argument, NULL, 't' },
    { "conf-client-addr",    required_argument, NULL, 'i' },
    { "conf-broadcast-addr", required_argument, NULL, 'b' },
    { "conf-network-mask",   required_argument, NULL, 'm' },
    { "conf-router-addr",    required_argument, NULL, 'r' },
    { "conf-dns-addr",       required_argument, NULL, 'd' },
    { "conf-time-address",   required_argument, NULL, 'a' },
    { "conf-time-renewal",   required_argument, NULL, 'n' },
    { "conf-time-rebinding", required_argument, NULL, 'e' },
    { 0,                     0,                 0,    0   }
};

static const char optstring[] = "I:S:C:s:t:i:b:m:r:d:a:n:e:";

void options_error(const char *exec_name, const char *reason) {
    fprintf(stderr, error_msg, exec_name, reason);
    exit(EXIT_FAILURE);
}

bool options_parse_time(const char *arg, uint32_t *time) {
    return sscanf(arg, "%ud", time) == 1;
}

bool options_parse_num(const char *arg, uint16_t *port) {
    return sscanf(arg, "%hu", port) == 1;
}

bool options_parse_net_addr(const char *arg, net_addr_t *addr) {
    if(inet_pton(AF_INET, arg, addr) != 1) {
        return false;
    }

    *addr = ntohl(*addr);

    return true;
}

bool options_parse_hw_addr(const char *arg, hw_addr_t *addr) {
    uint16_t addr_bytes[6];
    int i;

    if(sscanf(arg, "%hx:%hx:%hx:%hx:%hx:%hx", &addr_bytes[0],
              &addr_bytes[1], &addr_bytes[2], &addr_bytes[3], &addr_bytes[4],
              &addr_bytes[5]) != 6) {
        return false;
    }

    for(i = 0; i < sizeof(addr_bytes) / sizeof(addr_bytes[0]); i++) {
        if(addr_bytes[i] > 255) {
            return false;
        }
    }

    *addr = otonmac(addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3],
                    addr_bytes[4], addr_bytes[5]);

    return true;
}

void options_set_default(struct srv_opts *options) {
    memset(options, 0, sizeof(*options));

    strcpy(options->interface_name, "eth0");
    options->dhcp_server_port    = 67;
    options->dhcp_client_port    = 68;
    options->mac_table_size      = 5;
    options->mac_table_max_cnt   = 5;
    options->conf_client_addr    = otonnet(1, 2, 3, 4);
    options->conf_broadcast_addr = otonnet(1, 2, 3, 255);
    options->conf_subnet_mask    = otonnet(255, 255, 255, 0);
    options->conf_router_addr    = otonnet(1, 2, 3, 1);
    options->conf_dns_addr       = otonnet(1, 2, 3, 1);
    options->conf_time_address   = 0xFFFFFF;
    options->conf_time_renewal   = 0xFFFFFF;
    options->conf_time_rebinding = 0xFFFFFF;
}

struct srv_opts options_parse(int argc, char *argv[]) {
    extern int optind;
    extern char *optarg;

    struct srv_opts options;
    char c;

    options_set_default(&options);

    if(argc <= 0) {
        options_error("dhcp_server", "argc <= 0");
    }

    do {
        c = getopt_long(argc, argv, optstring, longopts, NULL);

        switch(c) {
            case -1:
                break;
            case 'I':
                strncpy(options.interface_name, optarg, IFNAMSIZ);
                options.interface_name[IFNAMSIZ - 1] = '\0';
                break;
            case 'S':
                if(!options_parse_num(optarg, &options.dhcp_server_port)) {
                    options_error(argv[0], "server-port - invalid value");
                }
                break;
            case 'C':
                if(!options_parse_num(optarg, &options.dhcp_client_port)) {
                    options_error(argv[0], "client-port - invalid value");
                }
                break;
            case 's':
                if(!options_parse_num(optarg, &options.mac_table_size)) {
                    options_error(argv[0], "mac-table-size - invalid value");
                }
                break;
            case 't':
                if(!options_parse_num(optarg, &options.mac_table_max_cnt)) {
                    options_error(argv[0],
                                  "mac-table-max-cnt - invalid value");
                }
                break;
            case 'i':
                if(!options_parse_net_addr(optarg,
                                           &options.conf_client_addr)) {
                    options_error(argv[0], "conf-client-addr - invalid value");
                }
                break;
            case 'b':
                if(!options_parse_net_addr(optarg,
                                           &options.conf_broadcast_addr)) {
                    options_error(argv[0],
                                  "conf-broadcast-addr - invalid value");
                }
                break;
            case 'm':
                if(!options_parse_net_addr(optarg,
                                           &options.conf_subnet_mask)) {
                    options_error(argv[0],
                                  "conf-network-mask - invalid value");
                }
                break;
            case 'r':
                if(!options_parse_net_addr(optarg,
                                           &options.conf_router_addr)) {
                    options_error(argv[0], "conf-router-addr - invalid value");
                }
                break;
            case 'd':
                if(!options_parse_net_addr(optarg, &options.conf_dns_addr)) {
                    options_error(argv[0], "conf-dns-addr - invalid value");
                }
                break;
            case 'a':
                if(!options_parse_time(optarg, &options.conf_time_address)) {
                    options_error(argv[0],
                                  "conf-time-address - invalid value");
                }
                break;
            case 'n':
                if(!options_parse_time(optarg, &options.conf_time_renewal)) {
                    options_error(argv[0],
                                  "conf-time-renewal - invalid value");
                }
                break;
            case 'e':
                if(!options_parse_time(optarg, &options.conf_time_rebinding)) {
                    options_error(argv[0],
                                  "conf-time-rebinding - invalid value");
                }
                break;
            default:
                options_error(argv[0], "unknown option");
        }
    } while(c != -1);

    if(optind + 2 != argc) {
        options_error(argv[0], "missing required parameters");
    }

    if(!options_parse_net_addr(argv[optind], &options.my_net_addr)) {
        options_error(argv[0], "MY_ADDR - invalid value");
    }

    if(!options_parse_hw_addr(argv[optind + 1], &options.my_hw_addr)) {
        options_error(argv[0], "MY_MAC - invalid value");
    }

    return options;
}

void options_print(const struct srv_opts *options) {
    struct in_addr addr;

    printf("Options\n");
    printf("|-interface              %s\n", options->interface_name);
    printf("|-server port            %hu\n", options->dhcp_server_port);
    printf("|-client port            %hu\n", options->dhcp_client_port);
    printf("|-MAC table size         %hu\n", options->mac_table_size);
    printf("|-MAC table max count    %hu\n", options->mac_table_max_cnt);

    addr.s_addr = htonl(options->my_net_addr);
    printf("|-my IPv4                %s\n", inet_ntoa(addr));
    printf("|-my MAC                 %hx:%hx:%hx:%hx:%hx:%hx\n",
           ntoo(options->my_hw_addr, 5), ntoo(options->my_hw_addr, 4),
           ntoo(options->my_hw_addr, 3), ntoo(options->my_hw_addr, 2),
           ntoo(options->my_hw_addr, 1), ntoo(options->my_hw_addr, 0));

    addr.s_addr = htonl(options->conf_client_addr);
    printf("|-config client IPv4     %s\n", inet_ntoa(addr));
    addr.s_addr = htonl(options->conf_broadcast_addr);
    printf("|-config broadcast IPV4  %s\n", inet_ntoa(addr));
    addr.s_addr = htonl(options->conf_subnet_mask);
    printf("|-config network mask    %s\n", inet_ntoa(addr));
    addr.s_addr = htonl(options->conf_router_addr);
    printf("|-config router IPV4     %s\n", inet_ntoa(addr));
    addr.s_addr = htonl(options->conf_dns_addr);
    printf("|-config dns IPV4        %s\n", inet_ntoa(addr));
    printf("|-config time address    %d\n", options->conf_time_address);
    printf("|-config time renewal    %d\n", options->conf_time_renewal);
    printf("|-config time rebinding  %d\n", options->conf_time_rebinding);
}

