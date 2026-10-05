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

/* Send ICMP message with given type, code and data (optional) to specified destination.
  When data is not NULL, it should point to the data which will be used as payload of 
  ICMP message. The size of these data must be equal ICMP_DATA_SIZE (see sr_protocol.h). 
  In case of error messages payload contains IP header of the original packet that 
  triggered error and few bytes followed it.
*/
void send_icmp_message(struct sr_instance *sr, char *interface,
                    uint8_t type, uint8_t code, void* data,
                    uint8_t *dst_mac, uint32_t dst_ip);

#endif