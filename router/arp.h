#ifndef _ARP_H_
#define _ARP_H_

#include "sr_router.h"
#include <stdint.h>

void handle_arp(struct sr_instance *sr, uint8_t *packet,
                unsigned int len, char *interface);

#endif