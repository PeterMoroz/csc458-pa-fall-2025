#ifndef _IP_H_
#define _IP_H_

#include "sr_router.h"
#include <stdint.h>

void handle_ip(struct sr_instance *sr, uint8_t *packet,
                unsigned int len, char *interface);


#endif