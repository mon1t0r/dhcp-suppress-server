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

#define INTERFACE_NAME "eno1"

enum {
    packet_buf_size = 65536
};

void dhcp_add_reply_options(struct dhcp_msg *msg, const struct dhcp_server_options *options,
                            dhcp_opt_off_t *offset) {
    uint32_t opt_data;

    opt_data = htonl(0xFFFFFF);
    dhcp_opt(msg, offset, dhcp_opt_address_time, &opt_data, 4);
    dhcp_opt(msg, offset, dhcp_opt_renewal_time, &opt_data, 4);
    dhcp_opt(msg, offset, dhcp_opt_rebinding_time, &opt_data, 4);

    opt_data = htonl(options->conf_network_mask);
    dhcp_opt(msg, offset, dhcp_opt_subnet_mask, &opt_data, 4);

    opt_data = htonl(options->conf_broadcast_ip);
    dhcp_opt(msg, offset, dhcp_opt_broadcast_address, &opt_data, 4);

    opt_data = htonl(options->conf_router_ip);
    dhcp_opt(msg, offset, dhcp_opt_router, &opt_data, 4);

    opt_data = htonl(options->conf_dns_ip);
    dhcp_opt(msg, offset, dhcp_opt_dns, &opt_data, 4);
}

size_t dhcp_reply_ack(struct dhcp_msg *msg, const struct dhcp_server_options *options,
                      enum dhcp_msg_type msg_type_ack, net_addr_t srv_ip) {
    uint32_t opt_data;
    dhcp_opt_off_t offset;

    msg->opcode = dhcp_opcode_reply;
    msg->hops = 0;
    msg->secs = 0;
    msg->flags = htons(0x8000);
    msg->ciaddr = 0;
    if(msg_type_ack == dhcp_msg_type_ack) {
        msg->yiaddr = htonl(options->conf_client_ip);
    } else {
        msg->yiaddr = 0;
    }
    msg->siaddr = htonl(options->my_ip);
    msg->giaddr = 0;

    dhcp_opt_begin(msg, &offset);

    opt_data = msg_type_ack;
    dhcp_opt(msg, &offset, dhcp_opt_msg_type, &opt_data, 1);

    if(srv_ip != 0) {
        opt_data = htonl(srv_ip);
        dhcp_opt(msg, &offset, dhcp_opt_srv_id, &opt_data, 4);
    }

    if(msg_type_ack == dhcp_msg_type_ack) {
        dhcp_add_reply_options(msg, options, &offset);
    }

    dhcp_opt_end(msg, &offset);

    return sizeof(struct dhcp_msg) - sizeof(msg->options) + offset * sizeof(uint8_t);
}

size_t dhcp_reply_offer(struct dhcp_msg *msg, const struct dhcp_server_options *options) {
    uint32_t opt_data;
    dhcp_opt_off_t offset;

    msg->opcode = dhcp_opcode_reply;
    msg->hops = 0;
    msg->secs = 0;
    msg->flags = htons(0x8000);
    msg->ciaddr = 0;
    msg->yiaddr = htonl(options->conf_client_ip);
    msg->siaddr = htonl(options->my_ip);
    msg->giaddr = 0;

    dhcp_opt_begin(msg, &offset);

    opt_data = dhcp_msg_type_offer;
    dhcp_opt(msg, &offset, dhcp_opt_msg_type, &opt_data, 1);

    opt_data = htonl(options->my_ip);
    dhcp_opt(msg, &offset, dhcp_opt_srv_id, &opt_data, 4);

    dhcp_add_reply_options(msg, options, &offset);

    dhcp_opt_end(msg, &offset);

    return sizeof(struct dhcp_msg) - sizeof(msg->options) + offset * sizeof(uint8_t);
}

size_t dhcp_handle_request(struct dhcp_msg *msg, const struct dhcp_server_options *options,
                           net_addr_t *netw_addr, hw_addr_t *hw_addr) {
    uint8_t *opt_data_ptr;
    net_addr_t srv_ip;

    if(dhcp_opt_get(msg, dhcp_opt_srv_id, &opt_data_ptr) == 4) {
        memcpy(&srv_ip, opt_data_ptr, sizeof(srv_ip));
        srv_ip = ntohl(srv_ip);
    } else {
        opt_data_ptr = NULL;
        srv_ip = 0;
    }

    if(opt_data_ptr != NULL && srv_ip == options->my_ip) {
        return dhcp_reply_ack(msg, options, dhcp_msg_type_ack, srv_ip);
    }

    *netw_addr = options->orig_ip;
    *hw_addr = options->orig_mac;

    return dhcp_reply_ack(msg, options, dhcp_msg_type_nak, srv_ip);
}

ssize_t dhcp_handle_msg(struct dhcp_msg *msg, const struct dhcp_server_options *options,
                        net_addr_t *netw_addr, hw_addr_t *hw_addr) {
    uint8_t *opt_data_ptr;

    if(dhcp_opt_get(msg, dhcp_opt_msg_type, &opt_data_ptr) != 1) {
        return -1;
    }

    switch(*opt_data_ptr) {
        case dhcp_msg_type_request:
            return dhcp_handle_request(msg, options, netw_addr, hw_addr);

        case dhcp_msg_type_discover:
            return dhcp_reply_offer(msg, options);
    }

    return -1;
}

uint16_t compute_ip_checksum(uint16_t* ptr, size_t cnt) {
    uint32_t sum;

    sum = 0;

    while(cnt > 1) {
        sum += *ptr;
        ptr++;
        cnt -= 2;
    }

    if(cnt > 0) {
        sum += (*ptr) & htons(0xFF00);
    }

    while(sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    sum = ~sum;

    return (uint16_t) sum;
}

ssize_t dhcp_pack_msg(const struct dhcp_msg *msg, const struct dhcp_server_options *options,
                      ssize_t msg_len, uint8_t *buf, net_addr_t netw_addr, hw_addr_t hw_addr) {
    size_t offset;
    struct ethhdr *eth_hdr;
    struct iphdr *ip_hdr;
    struct udphdr *udp_hdr;

    if(netw_addr == 0) {
        netw_addr = options->my_ip;
    }
    if(hw_addr == 0) {
        hw_addr = options->my_mac;
    }

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
    ip_hdr->saddr = htonl(netw_addr);
    ip_hdr->daddr = htonl(INADDR_BROADCAST);
    ip_hdr->tot_len = htons(msg_len + sizeof(struct udphdr) + sizeof(struct iphdr));
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

bool dhcp_unpack_msg(struct dhcp_msg *msg, const struct dhcp_server_options *options,
                     const uint8_t *buf, ssize_t buf_len) {
    size_t offset;
    struct ethhdr *eth_hdr;
    struct iphdr *ip_hdr;
    struct udphdr *udp_hdr;
    ssize_t msg_len;

    offset = 0;

    eth_hdr = (struct ethhdr *) (buf + offset);
    if(((
        eth_hdr->h_dest[0] != 255 ||
        eth_hdr->h_dest[1] != 255 ||
        eth_hdr->h_dest[2] != 255 ||
        eth_hdr->h_dest[3] != 255 ||
        eth_hdr->h_dest[4] != 255 ||
        eth_hdr->h_dest[5] != 255
    ) && (
        eth_hdr->h_dest[0] != ntoo(options->my_mac, 0) ||
        eth_hdr->h_dest[1] != ntoo(options->my_mac, 1) ||
        eth_hdr->h_dest[2] != ntoo(options->my_mac, 2) ||
        eth_hdr->h_dest[3] != ntoo(options->my_mac, 3) ||
        eth_hdr->h_dest[4] != ntoo(options->my_mac, 4) ||
        eth_hdr->h_dest[5] != ntoo(options->my_mac, 5) 
    )) || ntohs(eth_hdr->h_proto) != ETH_P_IP) {
        return false;
    }
    offset += sizeof(struct ethhdr);

    ip_hdr = (struct iphdr *) (buf + offset);
    if((ip_hdr->daddr != htonl(INADDR_BROADCAST) &&
        ip_hdr->daddr != htonl(options->my_ip)) || 
        ip_hdr->protocol != 17) {
        return false;
    }
    offset += ip_hdr->ihl * 4;

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

int create_socket(int *if_index) {
    int socket_fd;
    struct ifreq ifreq;
    struct sockaddr_ll addr;

    uint8_t addr_link[6];

    /* Create socket */
    if((socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    /* Get interface index */
    memset(&ifreq, 0, sizeof(struct ifreq));
    strncpy(ifreq.ifr_name, INTERFACE_NAME, IFNAMSIZ - 1);
    if(ioctl(socket_fd, SIOCGIFINDEX, &ifreq) < 0) {
        perror("ioctl(SIOCGIFINDEX)");
        exit(EXIT_FAILURE);
    }
    *if_index = ifreq.ifr_ifindex;

    /* Get interface hardware address */
    if(ioctl(socket_fd, SIOCGIFHWADDR, &ifreq) < 0) {
        perror("ioctl(SIOCGIFHWADDR)");
        exit(EXIT_FAILURE);
    }
    memcpy(addr_link, &ifreq.ifr_hwaddr.sa_data, sizeof(addr_link));

    /* Get interface address */
    if(ioctl(socket_fd, SIOCGIFADDR, &ifreq) < 0) {
        perror("ioctl(SIOCGIFADDR)");
        exit(EXIT_FAILURE);
    }

    /* Fill sockaddr_ll structure */
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_IP);
    addr.sll_ifindex = *if_index;

    /* Bind interface */
    if(bind(socket_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("bind()");
        exit(EXIT_FAILURE);
    }

    printf("Binded interface\n");
    printf("|-name  %s\n", INTERFACE_NAME);
    printf("|-index %d\n", *if_index);
    printf("|-IPv4  %s\n", inet_ntoa(((struct sockaddr_in *)
                                     &ifreq.ifr_addr)->sin_addr));
    printf("|-MAC   %x:%x:%x:%x:%x:%x\n", addr_link[0], addr_link[1],
           addr_link[2], addr_link[3], addr_link[4], addr_link[5]);
    printf("Socket initialized successfully\n\n");

    return socket_fd;
}

int main(int argc, char *argv[]) {
    struct dhcp_server_options options;

    int socket_fd;
    int if_index;

    struct sockaddr_ll addr;
    net_addr_t net_addr;
    hw_addr_t hw_addr;

    uint8_t *buf;
    ssize_t buf_len;

    struct dhcp_msg msg;
    ssize_t msg_len;

    options = options_dhcp_parse(argc, argv);

    options_print(&options);
    printf("\n");

    socket_fd = create_socket(&if_index);

    buf = malloc(packet_buf_size * sizeof(uint8_t));

    while((buf_len = recv(socket_fd, buf, packet_buf_size * sizeof(uint8_t), 0) > 0)) {
        net_addr = 0;
        hw_addr = 0;

        if(!dhcp_unpack_msg(&msg, &options, buf, buf_len)) {
            continue;
        }

        if((msg_len = dhcp_handle_msg(&msg, &options, &net_addr, &hw_addr)) < 0) {
            continue;
        }

        if((buf_len = dhcp_pack_msg(&msg, &options, msg_len, buf, net_addr, hw_addr)) < 0) {
            continue;
        }

        memset(&addr, 0, sizeof(addr));
        addr.sll_ifindex = if_index;
        addr.sll_halen = ETH_ALEN;
        memset(&addr.sll_addr, 255, 6);

        if(sendto(socket_fd, buf, buf_len, 0, (const struct sockaddr *) &addr,
                  sizeof(addr)) < 0) {
            perror("sendto()");
            exit(EXIT_FAILURE);
        }
    }

    close(socket_fd);
    free(buf);

    return EXIT_SUCCESS;
}
