#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>

#include "options.h"

static const char error_msg[] = "Usage: %s [OPTION]... \n(%s)\n";

static const struct option longopts[] = {
    { "srvport",   required_argument, NULL, 'S' },
    { "clport",    required_argument, NULL, 'C' },
    { "odhcpip",   required_argument, NULL, 'I' },
    { "odhcpmac",  required_argument, NULL, 'M' },
    { "mdhcpip",   required_argument, NULL, 'i' },
    { "mdhcpmac",  required_argument, NULL, 'm' },
    { "confclip",  required_argument, NULL, 'a' },
    { "confmask",  required_argument, NULL, 'n' },
    { "confroip",  required_argument, NULL, 'r' },
    { "confbrip",  required_argument, NULL, 'b' },
    { "confdnsip", required_argument, NULL, 'd' },
    { 0,           0,                 0,    0   }
};

static const char optstring[] = "S:C:I:M:i:m:a:n:r:b:d:";

void options_error(const char *exec_name, const char *reason) {
    fprintf(stderr, error_msg, exec_name, reason);
    exit(EXIT_FAILURE);
}

bool options_parse_port(const char *arg, uint16_t *port) {
    return false;
}

bool options_parse_net_addr(const char *arg, net_addr_t *addr) {
    return false;
}

bool options_parse_hw_addr(const char *arg, hw_addr_t *addr) {
    return false;
}

struct dhcp_server_options options_dhcp_parse(int argc, char *argv[]) {
    extern int optind;
    extern char *optarg;

    struct dhcp_server_options options;

    char c;

    memset(&options, 0, sizeof(options));

    if(argc <= 0) {
        options_error("dhcp_server", "argc <= 0");
    }

    do {
        c = getopt_long(argc, argv, optstring, longopts, NULL);

        switch(c) {
            case 'S':
                if(!options_parse_port(optarg, &options.dhcp_server_port)) {
                    options_error(argv[0], "srvport - invalid value");
                }
                break;
            case 'C':
                if(!options_parse_port(optarg, &options.dhcp_client_port)) {
                    options_error(argv[0], "clport - invalid value");
                }
                break;
            case 'I':
                if(!options_parse_net_addr(optarg, &options.orig_dhcp_ip)) {
                    options_error(argv[0], "odhcpip - invalid value");
                }
                break;
            case 'M':
                if(!options_parse_hw_addr(optarg, &options.orig_dhcp_mac)) {
                    options_error(argv[0], "odhcpmac - invalid value");
                }
                break;
            case 'i':
                if(!options_parse_net_addr(optarg, &options.my_dhcp_ip)) {
                    options_error(argv[0], "mdhcpip - invalid value");
                }
                break;
            case 'm':
                if(!options_parse_hw_addr(optarg, &options.my_dhcp_mac)) {
                    options_error(argv[0], "mdhcpmac - invalid value");
                }
                break;
            case 'a':
                if(!options_parse_net_addr(optarg, &options.conf_client_ip)) {
                    options_error(argv[0], "confclip - invalid value");
                }
                break;
            case 'n':
                if(!options_parse_net_addr(optarg, &options.conf_network_mask)) {
                    options_error(argv[0], "confmask - invalid value");
                }
                break;
            case 'r':
                if(!options_parse_net_addr(optarg, &options.conf_router_ip)) {
                    options_error(argv[0], "confroip - invalid value");
                }
                break;
            case 'b':
                if(!options_parse_net_addr(optarg, &options.conf_broadcast_ip)) {
                    options_error(argv[0], "confbrip - invalid value");
                }
                break;
            case 'd':
                if(!options_parse_net_addr(optarg, &options.conf_dns_ip)) {
                    options_error(argv[0], "confdnsip - invalid value");
                }
                break;
            default:
                options_error(argv[0], "unknown option");
        }
    } while(c != -1);

    return options;
}

