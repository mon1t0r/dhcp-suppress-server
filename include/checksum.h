#ifndef DHCP_SUP_SERVER_CHECKSUM_H
#define DHCP_SUP_SERVER_CHECKSUM_H

#include <stdint.h>
#include <stddef.h>

uint16_t compute_ip_checksum(uint16_t* ptr, size_t cnt);

#endif
