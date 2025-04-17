#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <arpa/inet.h>

#include "options.h"

static const char error_msg[] =
    "Usage: %s [OPTION]... ORIG_IP ORIG_MAC MY_IP MY_MAC \n(%s)\n";

static const struct option longopts[] = {
    { "srvport",   required_argument, NULL, 'S' },
    { "clport",    required_argument, NULL, 'C' },
    { "confclip",  required_argument, NULL, 'i' },
    { "confmask",  required_argument, NULL, 'm' },
    { "confroip",  required_argument, NULL, 'r' },
    { "confbrip",  required_argument, NULL, 'b' },
    { "confdnsip", required_argument, NULL, 'd' },
    { 0,           0,                 0,    0   }
};

static const char optstring[] = "S:C:i:m:r:b:d:";

void options_error(const char *exec_name, const char *reason) {
    fprintf(stderr, error_msg, exec_name, reason);
    exit(EXIT_FAILURE);
}

bool options_parse_port(const char *arg, uint16_t *port) {
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
    uint8_t addr_bytes[6];
    if(sscanf(arg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &addr_bytes[0],
              &addr_bytes[1], &addr_bytes[2], &addr_bytes[3], &addr_bytes[4],
              &addr_bytes[5]) != 6) {
        return false;
    }

    *addr = otonmac(addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3],
                    addr_bytes[4], addr_bytes[5]);

    return true;
}

void options_set_default(struct dhcp_server_options *options) {
    memset(options, 0, sizeof(*options));

    options->dhcp_server_port = 67;
    options->dhcp_client_port = 68;
    options->conf_client_ip = otonnet(1, 2, 3, 4);
    options->conf_network_mask = otonnet(255, 255, 255, 0);
    options->conf_router_ip = otonnet(1, 2, 3, 1);
    options->conf_broadcast_ip = otonnet(1, 2, 3, 255);
    options->conf_dns_ip = otonnet(1, 2, 3, 1);
}

struct dhcp_server_options options_dhcp_parse(int argc, char *argv[]) {
    extern int optind;
    extern char *optarg;

    struct dhcp_server_options options;
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
            case 'i':
                if(!options_parse_net_addr(optarg, &options.conf_client_ip)) {
                    options_error(argv[0], "confclip - invalid value");
                }
                break;
            case 'm':
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
                options_error(argv[0], "");
        }
    } while(c != -1);

    if(optind + 4 != argc) {
        options_error(argv[0], "missing required parameters");
    }

    if(!options_parse_net_addr(argv[optind], &options.orig_ip)) {
        options_error(argv[0], "ORIG_IP - invalid value");
    }

    if(!options_parse_hw_addr(argv[optind + 1], &options.orig_mac)) {
        options_error(argv[0], "ORIG_MAC - invalid value");
    }

    if(!options_parse_net_addr(argv[optind + 2], &options.my_ip)) {
        options_error(argv[0], "MY_IP - invalid value");
    }

    if(!options_parse_hw_addr(argv[optind + 3], &options.my_mac)) {
        options_error(argv[0], "MY_MAC - invalid value");
    }

    return options;
}

void options_print(const struct dhcp_server_options *options) {
    struct in_addr addr;

    printf("Options\n");
    printf("|-server port %d\n", options->dhcp_server_port);
    printf("|-client port %d\n", options->dhcp_client_port);

    addr.s_addr = htonl(options->orig_ip);
    printf("|-orig IPv4 %s\n", inet_ntoa(addr));
    printf("|-orig MAC %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n",
           ntoo(options->orig_mac, 5), ntoo(options->orig_mac, 4),
           ntoo(options->orig_mac, 3), ntoo(options->orig_mac, 2),
           ntoo(options->orig_mac, 1), ntoo(options->orig_mac, 0));

    addr.s_addr = htonl(options->my_ip);
    printf("|-my IPv4: %s\n", inet_ntoa(addr));
    printf("|-my MAC %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n",
           ntoo(options->my_mac, 5), ntoo(options->my_mac, 4),
           ntoo(options->my_mac, 3), ntoo(options->my_mac, 2),
           ntoo(options->my_mac, 1), ntoo(options->my_mac, 0));

    addr.s_addr = htonl(options->conf_client_ip);
    printf("|-config client IPv4 %s\n", inet_ntoa(addr));
    addr.s_addr = htonl(options->conf_network_mask);
    printf("|-config network mask %s\n", inet_ntoa(addr));
    addr.s_addr = htonl(options->conf_router_ip);
    printf("|-config router IPV4 %s\n", inet_ntoa(addr));
    addr.s_addr = htonl(options->conf_broadcast_ip);
    printf("|-config broadcast IPV4 %s\n", inet_ntoa(addr));
    addr.s_addr = htonl(options->conf_dns_ip);
    printf("|-config dns IPV4 %s\n", inet_ntoa(addr));
}

