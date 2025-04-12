#define _POSIX_C_SOURCE 199309L

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>
#include <linux/udp.h>

#include "dhcp.h"

#define INTERFACE_NAME "eno1"

enum {
    packet_buf_size  = 65536,

    dhcp_server_port = 67,
    dhcp_client_port = 68,

    orig_dhcp_ip_1   = 192,
    orig_dhcp_ip_2   = 168,
    orig_dhcp_ip_3   = 1,
    orig_dhcp_ip_4   = 1,

    orig_dhcp_mac_1 = 0x74,
    orig_dhcp_mac_2 = 0xFE,
    orig_dhcp_mac_3 = 0xCE,
    orig_dhcp_mac_4 = 0x8C,
    orig_dhcp_mac_5 = 0x87,
    orig_dhcp_mac_6 = 0x11,

    my_dhcp_ip_1  = 192,
    my_dhcp_ip_2  = 168,
    my_dhcp_ip_3  = 1,
    my_dhcp_ip_4  = 211,

    my_dhcp_mac_1 = 0xAA,
    my_dhcp_mac_2 = 0xBB,
    my_dhcp_mac_3 = 0xCC,
    my_dhcp_mac_4 = 0xDD,
    my_dhcp_mac_5 = 0xEE,
    my_dhcp_mac_6 = 0xFF,

    conf_ip_addr_1   = 1,
    conf_ip_addr_2   = 2,
    conf_ip_addr_3   = 3,
    conf_ip_addr_4   = 4,

    conf_subnet_mask_1 = 255,
    conf_subnet_mask_2 = 255,
    conf_subnet_mask_3 = 255,
    conf_subnet_mask_4 = 0,

    conf_broadcast_addr_1 = 192,
    conf_broadcast_addr_2 = 168,
    conf_broadcast_addr_3 = 1,
    conf_broadcast_addr_4 = 255,

    conf_router_ip_1 = 192,
    conf_router_ip_2 = 168,
    conf_router_ip_3 = 1,
    conf_router_ip_4 = 200,

    conf_dns_ip_1 = 192,
    conf_dns_ip_2 = 168,
    conf_dns_ip_3 = 1,
    conf_dns_ip_4 = 200
};

#define ip_to_num(i1, i2, i3, i4) (i1 | (i2 << 8) | (i3 << 16) | (i4 << 24))
#define mac_to_num(m1, m2, m3, m4, m5, m6) \
    ((uint64_t) m1        | ((uint64_t) m2 << 8 ) | \
    ((uint64_t) m3 << 16) | ((uint64_t) m4 << 24) | \
    ((uint64_t) m5 << 32) | ((uint64_t) m6 << 40))

void dhcp_add_reply_options(struct dhcp_msg *msg, dhcp_opt_offset *offset) {
    uint8_t opt_data[4];

    opt_data[0] = 0;
    opt_data[1] = 255;
    opt_data[2] = 255;
    opt_data[3] = 255;
    dhcp_opt(msg, offset, dhcp_opt_address_time, opt_data, 4);
    dhcp_opt(msg, offset, dhcp_opt_renewal_time, opt_data, 4);
    dhcp_opt(msg, offset, dhcp_opt_rebinding_time, opt_data, 4);

    opt_data[0] = conf_subnet_mask_1;
    opt_data[1] = conf_subnet_mask_2;
    opt_data[2] = conf_subnet_mask_3;
    opt_data[3] = conf_subnet_mask_4;
    dhcp_opt(msg, offset, dhcp_opt_subnet_mask, opt_data, 4);

    opt_data[0] = conf_broadcast_addr_1;
    opt_data[1] = conf_broadcast_addr_2;
    opt_data[2] = conf_broadcast_addr_3;
    opt_data[3] = conf_broadcast_addr_4;
    dhcp_opt(msg, offset, dhcp_opt_broadcast_address, opt_data, 4);

    opt_data[0] = conf_router_ip_1;
    opt_data[1] = conf_router_ip_2;
    opt_data[2] = conf_router_ip_3;
    opt_data[3] = conf_router_ip_4;
    dhcp_opt(msg, offset, dhcp_opt_router, opt_data, 4);

    opt_data[0] = conf_dns_ip_1;
    opt_data[1] = conf_dns_ip_2;
    opt_data[2] = conf_dns_ip_3;
    opt_data[3] = conf_dns_ip_4;
    dhcp_opt(msg, offset, dhcp_opt_dns, opt_data, 4);
}

size_t dhcp_reply_ack(struct dhcp_msg *msg, enum dhcp_msg_type msg_type_ack,
                      uint8_t dhcp_ip[4]) {
    uint8_t opt_data[1];
    dhcp_opt_offset offset;

    msg->opcode = dhcp_opcode_reply;
    msg->hops = 0;
    msg->secs = 0;
    msg->flags = htons(0x8000);
    msg->ciaddr = 0;
    if(msg_type_ack == dhcp_msg_type_ack) {
        msg->yiaddr = ip_to_num(conf_ip_addr_1, conf_ip_addr_2, conf_ip_addr_3,
                                conf_ip_addr_4);
    } else {
        msg->yiaddr = 0;
    }
    msg->siaddr = ip_to_num(my_dhcp_ip_1, my_dhcp_ip_2, my_dhcp_ip_3,
                            my_dhcp_ip_4);
    msg->giaddr = 0;

    dhcp_opt_begin(msg, &offset);

    opt_data[0] = msg_type_ack;
    dhcp_opt(msg, &offset, dhcp_opt_msg_type, opt_data, 1);

    if(dhcp_ip != NULL) {
        dhcp_opt(msg, &offset, dhcp_opt_srv_id, dhcp_ip, 4);
    }

    dhcp_add_reply_options(msg, &offset);

    dhcp_opt_end(msg, &offset);

    return sizeof(struct dhcp_msg) - sizeof(msg->options) + offset * sizeof(uint8_t);
}

size_t dhcp_reply_offer(struct dhcp_msg *msg) {
    uint8_t opt_data[4];
    dhcp_opt_offset offset;

    msg->opcode = dhcp_opcode_reply;
    msg->hops = 0;
    msg->secs = 0;
    msg->flags = htons(0x8000);
    msg->ciaddr = 0;
    msg->yiaddr = ip_to_num(conf_ip_addr_1, conf_ip_addr_2, conf_ip_addr_3,
                            conf_ip_addr_4);
    msg->siaddr = ip_to_num(my_dhcp_ip_1, my_dhcp_ip_2, my_dhcp_ip_3,
                            my_dhcp_ip_4);
    msg->giaddr = 0;

    dhcp_opt_begin(msg, &offset);

    opt_data[0] = dhcp_msg_type_offer;
    dhcp_opt(msg, &offset, dhcp_opt_msg_type, opt_data, 1);

    opt_data[0] = my_dhcp_ip_1;
    opt_data[1] = my_dhcp_ip_2;
    opt_data[2] = my_dhcp_ip_3;
    opt_data[3] = my_dhcp_ip_4;
    dhcp_opt(msg, &offset, dhcp_opt_srv_id, opt_data, 4);

    dhcp_add_reply_options(msg, &offset);

    dhcp_opt_end(msg, &offset);

    return sizeof(struct dhcp_msg) - sizeof(msg->options) + offset * sizeof(uint8_t);
}

size_t dhcp_handle_request(struct dhcp_msg *msg, uint32_t *netw_addr,
                           uint64_t *hw_addr) {
    uint8_t *opt_data_ptr;
    uint8_t srv_ip[4];

    if(dhcp_opt_get(msg, dhcp_opt_srv_id, &opt_data_ptr) == 4) {
        memcpy(srv_ip, opt_data_ptr, 4);
    } else {
        opt_data_ptr = NULL;
    }

    if(
        opt_data_ptr != NULL &&
        srv_ip[0] == my_dhcp_ip_1 &&
        srv_ip[1] == my_dhcp_ip_2 &&
        srv_ip[2] == my_dhcp_ip_3 &&
        srv_ip[3] == my_dhcp_ip_4
    ) {
        return dhcp_reply_ack(msg, dhcp_msg_type_ack, srv_ip);
    }

    *netw_addr = ip_to_num(orig_dhcp_ip_1, orig_dhcp_ip_2, orig_dhcp_ip_3, orig_dhcp_ip_4);
    *hw_addr = mac_to_num(orig_dhcp_mac_1, orig_dhcp_mac_2, orig_dhcp_mac_3,
                          orig_dhcp_mac_4, orig_dhcp_mac_5, orig_dhcp_mac_6);
    return dhcp_reply_ack(msg, dhcp_msg_type_nak, srv_ip);
}

ssize_t dhcp_handle_msg(struct dhcp_msg *msg, uint32_t *netw_addr,
                          uint64_t *hw_addr) {
    uint8_t *opt_data_ptr;

    if(dhcp_opt_get(msg, dhcp_opt_msg_type, &opt_data_ptr) != 1) {
        return -1;
    }

    switch(*opt_data_ptr) {
        case dhcp_msg_type_request:
            return dhcp_handle_request(msg, netw_addr, hw_addr);

        case dhcp_msg_type_discover:
            return dhcp_reply_offer(msg);
    }

    return -1;
}

ssize_t dhcp_pack_msg(const struct dhcp_msg *msg, ssize_t msg_len, uint8_t *buf,
                      uint32_t netw_addr, uint64_t hw_addr) {
    size_t offset;
    struct ethhdr *eth_hdr;
    struct iphdr *ip_hdr;
    struct udphdr *udp_hdr;

    memset(buf, 0, packet_buf_size * sizeof(uint8_t));

    offset = 0;

    eth_hdr = (struct ethhdr *) (buf + offset);
    eth_hdr->h_source[0] = hw_addr;
    eth_hdr->h_source[1] = hw_addr >> 8;
    eth_hdr->h_source[2] = hw_addr >> 16;
    eth_hdr->h_source[3] = hw_addr >> 24;
    eth_hdr->h_source[4] = hw_addr >> 32;
    eth_hdr->h_source[5] = hw_addr >> 40;
    memset(&eth_hdr->h_dest, 255, 6);
    eth_hdr->h_proto = htons(ETH_P_IP);
    offset += sizeof(struct ethhdr);

    ip_hdr = (struct iphdr *) (buf + offset);
    ip_hdr->ihl = 5;
    ip_hdr->version = 4;
    ip_hdr->tos = 0;
    ip_hdr->id = 0;
    ip_hdr->ttl = 64;
    ip_hdr->protocol = 17;
    ip_hdr->saddr = htonl(netw_addr);
    ip_hdr->daddr = htonl(INADDR_BROADCAST);
    ip_hdr->tot_len = htons(msg_len + sizeof(struct udphdr) + sizeof(struct iphdr));
    offset += sizeof(struct iphdr);

    udp_hdr = (struct udphdr *) (buf + offset);
    udp_hdr->source = htons(dhcp_server_port);
    udp_hdr->dest = htons(dhcp_client_port);
    udp_hdr->check = 0;
    udp_hdr->len = htons(msg_len + sizeof(struct udphdr));
    offset += sizeof(struct udphdr);

    memcpy(buf + offset, msg, msg_len);

    offset += msg_len;

    /* TODO: Calculate ip checksum */

    return offset;
}

bool dhcp_unpack_msg(struct dhcp_msg *msg, const uint8_t *buf, ssize_t buf_len) {
    size_t offset;
    struct ethhdr *eth_hdr;
    struct iphdr *ip_hdr;
    struct udphdr *udp_hdr;

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
        eth_hdr->h_dest[0] != my_dhcp_mac_1 ||
        eth_hdr->h_dest[1] != my_dhcp_mac_2 ||
        eth_hdr->h_dest[2] != my_dhcp_mac_3 ||
        eth_hdr->h_dest[3] != my_dhcp_mac_4 ||
        eth_hdr->h_dest[4] != my_dhcp_mac_5 ||
        eth_hdr->h_dest[5] != my_dhcp_mac_6
    )) || ntohs(eth_hdr->h_proto) != ETH_P_IP) {
        return false;
    }
    offset += sizeof(struct ethhdr);

    ip_hdr = (struct iphdr *) (buf + offset);
    if((ntohl(ip_hdr->daddr) != INADDR_BROADCAST && ntohl(ip_hdr->daddr) !=
        ip_to_num(my_dhcp_ip_1, my_dhcp_ip_2, my_dhcp_ip_3, my_dhcp_ip_4)) || 
        ip_hdr->protocol != 17) {
        return false;
    }
    offset += ip_hdr->ihl * 4;

    udp_hdr = (struct udphdr *) (buf + offset);
    if(ntohs(udp_hdr->dest) != dhcp_server_port ||
        htons(udp_hdr->source) != dhcp_client_port) {
        return false;
    }
    offset += sizeof(struct udphdr);

    if(buf_len - offset < sizeof(struct dhcp_msg) - sizeof(msg->options)) {
        return false;
    }

    memset(&msg->options, 0, sizeof(msg->options));
    memcpy(&msg, buf + offset, buf_len - offset);

    return true;
}

int create_socket(int *if_index) {
    int socket_fd;
    /*int sockopt;*/
    struct ifreq ifreq;
    struct sockaddr_ll addr;

    uint8_t addr_link[6];

    /* Create socket */
    if((socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    /* Enable socket output broadcast */
    /*sockopt = 1;
    if(setsockopt(socket_fd, SOL_SOCKET, SO_BROADCAST, &sockopt,
                  sizeof(sockopt)) < 0) {
        perror("setsockopt()");
        exit(EXIT_FAILURE);
    }*/

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

    printf("Interface\n");
    printf("|-name %s\n", INTERFACE_NAME);
    printf("|-index %d\n", *if_index);
    printf("|-mac %x:%x:%x:%x:%x:%x\n", addr_link[0], addr_link[1], addr_link[2],
           addr_link[3], addr_link[4], addr_link[5]);
    printf("|-ip %s\n", inet_ntoa(((struct sockaddr_in *) &ifreq.ifr_addr)->sin_addr));
    printf("Socket initialized successfully\n\n");

    return socket_fd;
}

int main(void) {
    int socket_fd;
    int if_index;

    struct sockaddr_ll addr;
    uint32_t netw_addr;
    uint64_t hw_addr;

    uint8_t *buf;
    ssize_t buf_len;

    struct dhcp_msg msg;
    ssize_t msg_len;

    socket_fd = create_socket(&if_index);

    buf = malloc(packet_buf_size * sizeof(uint8_t));

    while((buf_len = recv(socket_fd, &buf, packet_buf_size * sizeof(uint8_t), 0) > 0)) {

        /*printf("DHCP message from %s\n", inet_ntoa(client_addr.sin_addr));
        printf("|-opcode: %d\n", msg.opcode);
        printf("|-xid: %x\n", ntohl(msg.xid));
        if(msg.hlen == 6) {
            printf("|-chaddr: %x:%x:%x:%x:%x:%x\n", msg.chaddr[0], msg.chaddr[1], msg.chaddr[2], msg.chaddr[3], msg.chaddr[4], msg.chaddr[5]);
        }
        printf("|-sname: %s\n", msg.sname);
        printf("|-filename: %s\n", msg.filename);
        printf("\n");*/

        if(!dhcp_unpack_msg(&msg, buf, buf_len)) {
            continue;
        }

        if((msg_len = dhcp_handle_msg(&msg, &netw_addr, &hw_addr)) < 0) {
            continue;
        }

        if((buf_len = dhcp_pack_msg(&msg, msg_len, buf, netw_addr, hw_addr)) < 0) {
            continue;
        }

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
