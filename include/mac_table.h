#ifndef DHCP_SUP_SERVER_MAC_TABLE_H
#define DHCP_SUP_SERVER_MAC_TABLE_H

#include "dhcp.h"

struct node;

struct mac_table {
    int size;
    int size_cur;
    struct node **nodes;
};

struct mac_table *mt_create(int size);

void mt_add(struct mac_table *mt, net_addr_t key, hw_addr_t val);

hw_addr_t mt_get(const struct mac_table *mt, net_addr_t key);

void mt_clear(struct mac_table *mt);

void mt_free(struct mac_table *mt);

#endif
