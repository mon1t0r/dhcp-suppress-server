#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netpacket/packet.h>

#include "options.h"
#include "dhcp.h"
#include "if_utils.h"
#include "checksum.h"
#include "mac_table.h"

enum {
    packet_buf_size = 65536
};

void dhcp_set_reply_header(struct dhcp_msg *msg) {
    msg->opcode = dhcp_opcode_reply;
    msg->hops = 0;
    msg->secs = 0;
    msg->flags = htons(0x8000);
    msg->ciaddr = 0;
    msg->yiaddr = 0;
    msg->siaddr = 0;
    msg->giaddr = 0;
}

void dhcp_add_reply_options(struct dhcp_msg *msg,
                            const struct srv_opts *options,
                            dhcp_opt_off_t *offset) {
    uint32_t opt_data;

    opt_data = htonl(options->conf_time_address);
    dhcp_opt(msg, offset, dhcp_opt_address_time, &opt_data, 4);

    opt_data = htonl(options->conf_time_renewal);
    dhcp_opt(msg, offset, dhcp_opt_renewal_time, &opt_data, 4);

    opt_data = htonl(options->conf_time_rebinding);
    dhcp_opt(msg, offset, dhcp_opt_rebinding_time, &opt_data, 4);

    opt_data = htonl(options->conf_subnet_mask);
    dhcp_opt(msg, offset, dhcp_opt_subnet_mask, &opt_data, 4);

    opt_data = htonl(options->conf_broadcast_addr);
    dhcp_opt(msg, offset, dhcp_opt_broadcast_address, &opt_data, 4);

    opt_data = htonl(options->conf_router_addr);
    dhcp_opt(msg, offset, dhcp_opt_router, &opt_data, 4);

    opt_data = htonl(options->conf_dns_addr);
    dhcp_opt(msg, offset, dhcp_opt_dns, &opt_data, 4);
}

size_t dhcp_reply_ack(struct dhcp_msg *msg, const struct srv_opts *options,
                      enum dhcp_msg_type msg_type_ack,
                      net_addr_t srv_net_addr) {
    uint32_t opt_data;
    dhcp_opt_off_t offset;

    /* Init DHCP reply header */
    dhcp_set_reply_header(msg);
    /* If this is ACK message, set yiaddr to configured client address */
    if(msg_type_ack == dhcp_msg_type_ack) {
        msg->yiaddr = htonl(options->conf_client_addr);
    }
    msg->siaddr = htonl(options->my_net_addr);

    dhcp_opt_begin(msg, &offset);

    opt_data = msg_type_ack;
    dhcp_opt(msg, &offset, dhcp_opt_msg_type, &opt_data, 1);

    /* Set server identification option, if present */
    if(srv_net_addr != 0) {
        opt_data = htonl(srv_net_addr);
        dhcp_opt(msg, &offset, dhcp_opt_srv_id, &opt_data, 4);
    }

    /* If this is ACK message, also add configuration options */
    if(msg_type_ack == dhcp_msg_type_ack) {
        dhcp_add_reply_options(msg, options, &offset);
    }

    dhcp_opt_end(msg, &offset);

    return sizeof(struct dhcp_msg) - sizeof(msg->options) +
    offset * sizeof(uint8_t);
}

size_t dhcp_reply_offer(struct dhcp_msg *msg, const struct srv_opts *options) {
    uint32_t opt_data;
    dhcp_opt_off_t offset;

    /* Init DHCP reply header */
    dhcp_set_reply_header(msg);
    msg->yiaddr = htonl(options->conf_client_addr);
    msg->siaddr = htonl(options->my_net_addr);

    dhcp_opt_begin(msg, &offset);

    opt_data = dhcp_msg_type_offer;
    dhcp_opt(msg, &offset, dhcp_opt_msg_type, &opt_data, 1);

    opt_data = htonl(options->my_net_addr);
    dhcp_opt(msg, &offset, dhcp_opt_srv_id, &opt_data, 4);

    dhcp_add_reply_options(msg, options, &offset);

    dhcp_opt_end(msg, &offset);

    return sizeof(struct dhcp_msg) - sizeof(msg->options) +
    offset * sizeof(uint8_t);
}

size_t dhcp_handle_request(struct dhcp_msg *msg,
                           const struct srv_opts *options,
                           net_addr_t *sender_net_addr) {
    uint8_t *opt_data_ptr;
    net_addr_t srv_net_addr;

    /* Check server identification option in request packet */
    if(dhcp_opt_get(msg, dhcp_opt_srv_id, &opt_data_ptr) == 4) {
        memcpy(&srv_net_addr, opt_data_ptr, sizeof(srv_net_addr));
        srv_net_addr = ntohl(srv_net_addr);
    } else {
        opt_data_ptr = NULL;
        srv_net_addr = 0;
    }

    /* If the request is for us, reply with ACK and set sender network address
     * to our address */
    if(opt_data_ptr != NULL && srv_net_addr == options->my_net_addr) {
        *sender_net_addr = options->my_net_addr;
        return dhcp_reply_ack(msg, options, dhcp_msg_type_ack, srv_net_addr);
    }

    /* The request is not for us, so send NAK with the sender address of
     * the requested server (or 0, if there was no srv_id option).
     * This is the part, where other DHCP server suppression happens */
    *sender_net_addr = srv_net_addr;
    return dhcp_reply_ack(msg, options, dhcp_msg_type_nak, srv_net_addr);
}

ssize_t dhcp_msg_handle(struct dhcp_msg *msg, const struct srv_opts *options,
                        bool *cache_src_addr, net_addr_t *sender_net_addr) {
    uint8_t *opt_data_ptr;

    if(dhcp_opt_get(msg, dhcp_opt_msg_type, &opt_data_ptr) != 1) {
        return -1;
    }

    /* Do not cache source address by default */
    *cache_src_addr = 0;
    /* Sender network address is unspecified by default */
    *sender_net_addr = 0;

    switch(*opt_data_ptr) {
        case dhcp_msg_type_discover:
            /* Set sender network address to our address */
            *sender_net_addr = options->my_net_addr;

            /* Reply to discover with offer */
            return dhcp_reply_offer(msg, options);

        case dhcp_msg_type_offer:
            /* Set chache source address flag to 1, as this is probably
             * an offer from another DHCP server in the network, and we should
             * save it's MAC in order to use it in future */
            *cache_src_addr = 1;
            return 0;

        case dhcp_msg_type_request:
            return dhcp_handle_request(msg, options, sender_net_addr);
    }

    return -1;
}

ssize_t dhcp_msg_pack(const struct dhcp_msg *msg, ssize_t msg_len,
                      const struct srv_opts *options, uint8_t *buf,
                      net_addr_t net_addr, hw_addr_t hw_addr) {
    size_t offset;
    struct ethhdr *eth_hdr;
    struct iphdr *ip_hdr;
    struct udphdr *udp_hdr;

    memset(buf, 0, packet_buf_size * sizeof(uint8_t));

    offset = 0;

    eth_hdr = (struct ethhdr *) (buf + offset);
    eth_hdr->h_source[0] = ntoo(hw_addr, 5);
    eth_hdr->h_source[1] = ntoo(hw_addr, 4);
    eth_hdr->h_source[2] = ntoo(hw_addr, 3);
    eth_hdr->h_source[3] = ntoo(hw_addr, 2);
    eth_hdr->h_source[4] = ntoo(hw_addr, 1);
    eth_hdr->h_source[5] = ntoo(hw_addr, 0);
    memset(&eth_hdr->h_dest, 255, 6);
    eth_hdr->h_proto = htons(ETH_P_IP);
    offset += sizeof(struct ethhdr);

    ip_hdr = (struct iphdr *) (buf + offset);
    ip_hdr->ihl = 5;
    ip_hdr->version = 4;
    ip_hdr->tos = 192;
    ip_hdr->id = 0;
    ip_hdr->ttl = 64;
    ip_hdr->protocol = 17;
    ip_hdr->saddr = htonl(net_addr);
    ip_hdr->daddr = htonl(INADDR_BROADCAST);
    ip_hdr->tot_len = htons(msg_len + sizeof(struct udphdr) +
                            sizeof(struct iphdr));
    ip_hdr->check = 0;
    ip_hdr->check = compute_ip_checksum((uint16_t *) ip_hdr, ip_hdr->ihl << 2);
    offset += sizeof(struct iphdr);

    udp_hdr = (struct udphdr *) (buf + offset);
    udp_hdr->source = htons(options->dhcp_server_port);
    udp_hdr->dest = htons(options->dhcp_client_port);
    udp_hdr->check = 0;
    udp_hdr->len = htons(msg_len + sizeof(struct udphdr));
    offset += sizeof(struct udphdr);

    memcpy(buf + offset, msg, msg_len);

    offset += msg_len;

    return offset;
}

bool dhcp_msg_unpack(struct dhcp_msg *msg, const struct srv_opts *options,
                     const uint8_t *buf, ssize_t buf_len,
                     net_addr_t *net_addr, hw_addr_t *hw_addr) {
    size_t offset;
    struct ethhdr *eth_hdr;
    struct iphdr *ip_hdr;
    struct udphdr *udp_hdr;
    ssize_t msg_len;

    offset = 0;

    eth_hdr = (struct ethhdr *) (buf + offset);
    /* Check if Ethernet frame is intended for us or is broadcast */
    if(((
        eth_hdr->h_dest[0] != 255 ||
        eth_hdr->h_dest[1] != 255 ||
        eth_hdr->h_dest[2] != 255 ||
        eth_hdr->h_dest[3] != 255 ||
        eth_hdr->h_dest[4] != 255 ||
        eth_hdr->h_dest[5] != 255
    ) && (
        eth_hdr->h_dest[0] != ntoo(options->my_hw_addr, 0) ||
        eth_hdr->h_dest[1] != ntoo(options->my_hw_addr, 1) ||
        eth_hdr->h_dest[2] != ntoo(options->my_hw_addr, 2) ||
        eth_hdr->h_dest[3] != ntoo(options->my_hw_addr, 3) ||
        eth_hdr->h_dest[4] != ntoo(options->my_hw_addr, 4) ||
        eth_hdr->h_dest[5] != ntoo(options->my_hw_addr, 5) 
    )) || ntohs(eth_hdr->h_proto) != ETH_P_IP) {
        return false;
    }
    offset += sizeof(struct ethhdr);
    *hw_addr = otonmac(
        eth_hdr->h_source[0],
        eth_hdr->h_source[1],
        eth_hdr->h_source[2],
        eth_hdr->h_source[3],
        eth_hdr->h_source[4],
        eth_hdr->h_source[5]
    );

    ip_hdr = (struct iphdr *) (buf + offset);
    /* Check if IP packet is intended for us or is broadcast */
    if((ip_hdr->daddr != htonl(INADDR_BROADCAST) &&
        ip_hdr->daddr != htonl(options->my_net_addr)) || 
        ip_hdr->protocol != 17) {
        return false;
    }
    offset += ip_hdr->ihl * 4;
    *net_addr = ntohl(ip_hdr->saddr);

    /* Check if UDP datagram is intended for us */
    udp_hdr = (struct udphdr *) (buf + offset);
    if(udp_hdr->dest != htons(options->dhcp_server_port) ||
        udp_hdr->source != htons(options->dhcp_client_port)) {
        return false;
    }
    offset += sizeof(struct udphdr);

    msg_len = buf_len - offset;
    if(msg_len < sizeof(struct dhcp_msg) - sizeof(msg->options)) {
        return false;
    }

    if(msg_len > sizeof(struct dhcp_msg)) {
        msg_len = sizeof(struct dhcp_msg);
    }

    memset(&msg->options, 0, sizeof(msg->options));
    memcpy(msg, buf + offset, msg_len);

    return true;
}

int create_socket(void) {
    int socket_fd;

    if((socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    return socket_fd;
}

void bind_socket(int socket_fd, int if_index) {
    struct sockaddr_ll addr;

    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_IP);
    addr.sll_ifindex = if_index;

    if(bind(socket_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("bind()");
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char *argv[]) {
    struct srv_opts options;

    int socket_fd;
    int if_index;

    uint8_t *buf;
    ssize_t buf_len;

    struct mac_table *mac_table;

    struct dhcp_msg msg;
    ssize_t msg_len;

    struct sockaddr_ll addr;
    net_addr_t src_net_addr;
    hw_addr_t src_hw_addr;
    bool cache_src_addr;
    net_addr_t sender_net_addr;

    options = options_parse(argc, argv);
    options_print(&options);
    printf("\n");

    socket_fd = create_socket();
    if_index = get_interface_index(socket_fd, options.interface_name);
    bind_socket(socket_fd, if_index);

    buf = malloc(packet_buf_size * sizeof(uint8_t));
    if(buf == NULL) {
        perror("malloc()");
        exit(EXIT_FAILURE);
    }

    mac_table = mt_create(options.mac_table_size);

    printf("Initialized successfully\n");
    printf("Listening for incoming DHCP requests\n\n");

    /* Main receive loop */
    while((buf_len = recv(socket_fd, buf,
                          packet_buf_size * sizeof(uint8_t), 0) > 0)) {
        /* Unpack raw packet */
        /* src_net_addr - network address of packet sender */
        /* src_hw_addr - MAC address of packet sender */
        if(!dhcp_msg_unpack(&msg, &options, buf, buf_len,
                            &src_net_addr, &src_hw_addr)) {
            continue;
        }

        /* Handle DHCP message */
        /* After call, cache_src_addr will indicate if packet sender network
         * and MAC addresses should be cached; sender_net_addr will contain
         * network address, which will be used as source in outgoing packet */
        if((msg_len = dhcp_msg_handle(&msg, &options, &cache_src_addr,
                                      &sender_net_addr)) < 0) {
            continue;
        }

        /* If cache source network and MAC address flag is set */
        if(cache_src_addr) {
            /* If table entry count will become greater than max limit */
            if(mac_table->size_cur + 1 > options.mac_table_max_cnt) {
                mt_clear(mac_table);
            }
            /* Add network and MAC address pair */
            mt_add(mac_table, src_net_addr, src_hw_addr);
        }

        if(msg_len == 0) {
            continue;
        }

        /* Set source network address to address provided by dhcp_msg_handle */
        src_net_addr = sender_net_addr;

        /* If source address should be the program's (our) server address */
        if(sender_net_addr == options.my_net_addr) {
            src_hw_addr = options.my_hw_addr;
        /* Else if source address is not specified */
        } else if(sender_net_addr == 0) {
            src_hw_addr = 0;
        /* Else look for MAC in MAC address table */
        } else {
            src_hw_addr = mt_get(mac_table, sender_net_addr);
        }

        /* Pack raw packet */
        if((buf_len = dhcp_msg_pack(&msg, msg_len, &options, buf, src_net_addr,
                                    src_hw_addr)) < 0) {
            continue;
        }

        memset(&addr, 0, sizeof(addr));
        addr.sll_ifindex = if_index;
        addr.sll_halen = ETH_ALEN;
        /* Set destination MAC address to broadcast */
        memset(&addr.sll_addr, 255, 6);

        /* Send packet */
        if(sendto(socket_fd, buf, buf_len, 0, (const struct sockaddr *) &addr,
                  sizeof(addr)) < 0) {
            perror("sendto()");
            exit(EXIT_FAILURE);
        }
    }

    mt_free(mac_table);
    close(socket_fd);
    free(buf);

    return EXIT_SUCCESS;
}
