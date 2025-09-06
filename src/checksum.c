#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>

#include "checksum.h"

uint16_t ip_checksum_compute(uint16_t* ptr, size_t cnt)
{
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

