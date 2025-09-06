#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <linux/if.h>
#include <sys/ioctl.h>

#include "if_utils.h"

int interface_get_index(int socket_fd, const char *interface_name)
{
    struct ifreq ifreq;

    memset(&ifreq, 0, sizeof(struct ifreq));
    strncpy(ifreq.ifr_name, interface_name, IFNAMSIZ - 1);
    if(ioctl(socket_fd, SIOCGIFINDEX, &ifreq) < 0) {
        perror("ioctl(SIOCGIFINDEX)");
        exit(EXIT_FAILURE);
    }

    return ifreq.ifr_ifindex;
}

