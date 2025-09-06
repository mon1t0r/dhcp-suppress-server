#include <string.h>

#include "dhcp.h"

void dhcp_opt_begin(struct dhcp_msg *msg, dhcp_opt_size_t *offset)
{
    if(msg == NULL) {
        *offset = -1;
        return;
    }

    memset(&msg->options, 0, sizeof(msg->options));

    *offset = 0;
}

void dhcp_opt(struct dhcp_msg *msg, dhcp_opt_size_t *offset, enum dhcp_opt opt,
              const void *opt_data, size_t opt_data_len)
{
    uint8_t *opts_ptr;

    if(*offset < 0) {
        return;
    }

    if(*offset + opt_data_len + 2 >= sizeof(msg->options)) {
        return;
    }

    opts_ptr = msg->options + *offset;

    opts_ptr[0] = opt;
    opts_ptr[1] = opt_data_len;

    memcpy(opts_ptr + 2, opt_data, opt_data_len);

    *offset += opt_data_len + 2;
}

void dhcp_opt_end(struct dhcp_msg *msg, dhcp_opt_size_t *offset)
{
    if(*offset < 0) {
        return;
    }

    if(*offset + 1 >= sizeof(msg->options)) {
        return;
    }

    msg->options[*offset] = 0xFF;

    (*offset)++;
}

ssize_t
dhcp_opt_get(struct dhcp_msg *msg, enum dhcp_opt opt, uint8_t **opt_data_ptr)
{
    size_t opt_pos;

    opt_pos = 0;

    while(opt_pos < sizeof(msg->options) / sizeof(uint8_t)) {
        if(msg->options[opt_pos] == dhcp_opt_break) {
            break;
        }

        if(msg->options[opt_pos] == opt) {
            *opt_data_ptr = &msg->options[opt_pos + 2];
            return msg->options[opt_pos + 1];
        }

        opt_pos += msg->options[opt_pos + 1] + 2;
    }

    return -1;
}

