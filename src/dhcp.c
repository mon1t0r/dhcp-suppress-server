#include <string.h>

#include "dhcp.h"

dhcp_opt_offset dhcp_opt_begin(struct dhcp_msg *msg) {
    if(msg == NULL) {
        return -1;
    }

    memset(&msg->options, 0, sizeof(msg->options));

    return 0;
}

dhcp_opt_offset dhcp_opt(struct dhcp_msg *msg, dhcp_opt_offset offset, enum dhcp_opt opt, const void *opt_data, size_t opt_data_len) {
    uint8_t *opts_ptr;

    if(offset < 0) {
        return offset;
    }

    if(offset + opt_data_len + 2 >= sizeof(msg->options)) {
        return offset;
    }

    opts_ptr = msg->options + offset;

    opts_ptr[0] = opt;
    opts_ptr[1] = opt_data_len;

    memcpy(opts_ptr + 2, opt_data, opt_data_len);

    return offset + opt_data_len + 2;
}

dhcp_opt_offset dhcp_opt_end(struct dhcp_msg *msg, dhcp_opt_offset offset) {
    if(offset < 0) {
        return offset;
    }

    if(offset + 1 >= sizeof(msg->options)) {
        return offset;
    }

    msg->options[offset] = 0xFF;

    return offset + 1;
}

ssize_t dhcp_opt_get(struct dhcp_msg *msg, enum dhcp_opt opt, uint8_t **opt_data_ptr) {
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
