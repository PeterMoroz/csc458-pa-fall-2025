#ifndef _ARP_H_
#define _ARP_H_

#include "sr_router.h"
#include <stdint.h>

void handle_arp(struct sr_instance *sr, uint8_t *packet,
                unsigned int len, char *interface);

void compose_arp_request(uint8_t* packet, uint8_t* sender_hw_addr, 
                        uint32_t sender_ip_addr, uint32_t target_ip_addr);

#endif