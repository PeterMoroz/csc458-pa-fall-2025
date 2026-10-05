#ifndef _ICMP_H_
#define _ICMP_H_

 
#include "sr_router.h"
#include <stdint.h>

enum icmp_msg_type {
    icmp_echo_reply = 0,
    icmp_dest_unreachable = 3,
    icmp_echo = 8,
    icmp_time_exceeded = 11,
};

enum icmp_dst_unreach_code {
    icmp_net_unreachable = 0,
    icmp_host_unreachable = 1,
    icmp_port_unreachable = 3,
};

void send_icmp_message(struct sr_instance *sr, char *interface,
                        uint8_t type, uint8_t code,
                        uint8_t *dst_mac, uint32_t dst_ip);

#endif