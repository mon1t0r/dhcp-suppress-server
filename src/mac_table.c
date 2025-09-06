#include <stdlib.h>
#include <stdio.h>

#include "mac_table.h"
#include "dhcp.h"

struct mac_table_node {
    struct mac_table_node *next;
    net_addr_t key;
    hw_addr_t value;
};

struct mac_table {
    int size;
    int size_cur;
    struct mac_table_node **nodes;
};

static int hash(int x)
{
    x = ((x >> 16) ^ x) * 0x45d9f3bu;
    x = ((x >> 16) ^ x) * 0x45d9f3bu;
    x = (x >> 16) ^ x;
    return x;
}

struct mac_table *mt_create(int size)
{
    struct mac_table *mt;

    mt = malloc(sizeof(struct mac_table));
    if(mt == NULL) {
        perror("malloc()");
        exit(EXIT_FAILURE);
    }
    mt->size = size;
    mt->size_cur = 0;
    mt->nodes = calloc(size, sizeof(struct mac_table_node *));
    if(mt->nodes == NULL) {
        perror("malloc()");
        exit(EXIT_FAILURE);
    }

    return mt;
}

void mt_add(struct mac_table *mt, net_addr_t key, hw_addr_t val)
{
    int index;
    struct mac_table_node **node;

    index = hash(key) % mt->size;

    node = &mt->nodes[index];
    while(*node != NULL) {
        if((*node)->key == key) {
            (*node)->value = val;
            return;
        }

        node = &(*node)->next;
    }

    *node = malloc(sizeof(struct mac_table_node));
    if(*node == NULL) {
        perror("malloc()");
        exit(EXIT_FAILURE);
    }
    (*node)->key = key;
    (*node)->value = val;
    (*node)->next = NULL;

    mt->size_cur++;
}

hw_addr_t mt_get(const struct mac_table *mt, net_addr_t key)
{
    int index;
    struct mac_table_node *node;

    index = hash(key) % mt->size;

    node = mt->nodes[index];
    while(node != NULL) {
        if(node->key == key) {
            return node->value;
        }
        node = node->next;
    }

    return 0;
}

int mt_cur_size(struct mac_table *mt)
{
    return mt->size_cur;
}

void mt_clear(struct mac_table *mt)
{
    int i;
    struct mac_table_node *node;
    struct mac_table_node *node_next;

    for(i = 0; i < mt->size; i++) {
        node = mt->nodes[i];
        while(node != NULL) {
            node_next = node->next;
            free(node);
            node = node_next;
        }
        mt->nodes[i] = NULL;
    }

    mt->size_cur = 0;
}

void mt_free(struct mac_table *mt)
{
    int i;
    struct mac_table_node *node;
    struct mac_table_node *node_next;

    for(i = 0; i < mt->size; i++) {
        node = mt->nodes[i];
        while(node != NULL) {
            node_next = node->next;
            free(node);
            node = node_next;
        }
    }

    free(mt->nodes);
    free(mt);
}

