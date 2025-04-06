#include <stdlib.h>
#include <stdio.h>
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
    dhcp_filename_len = 128
};

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
    uint8_t options[];
} __attribute__((__packed__));

int main(void) {
    int socket_fd;
    struct sockaddr_in serv_addr;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len;
    ssize_t msg_len;
    struct dhcp_msg msg;

    if((socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) { 
        perror("socket()"); 
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
        if(msg_len < sizeof(msg)) {
            printf("Received incomplete message on DHCP port\n");
            continue;
        }

        printf("DHCP message from %s\n", inet_ntoa(client_addr.sin_addr));
        printf("|-opcode: %d\n", msg.opcode);
        printf("|-xid: %x\n", ntohl(msg.xid));
        if(msg.hlen == 6) {
            printf("|-chaddr: %x:%x:%x:%x:%x:%x\n", msg.chaddr[0], msg.chaddr[1], msg.chaddr[2], msg.chaddr[3], msg.chaddr[4], msg.chaddr[5]);
        }
        printf("|-sname: %s\n", msg.sname);
        printf("|-filename: %s\n", msg.filename);
        printf("\n");
    }

    return EXIT_SUCCESS;
}
