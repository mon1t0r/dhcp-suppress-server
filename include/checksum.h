#ifndef DHCP_SUP_SERVER_CHECKSUM_H
#define DHCP_SUP_SERVER_CHECKSUM_H

#include <stdint.h>
#include <stddef.h>

uint16_t ip_checksum_compute(uint16_t* ptr, size_t cnt);

#endif
