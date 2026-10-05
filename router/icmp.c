#include "icmp.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <arpa/inet.h>

#include "sr_protocol.h"
#include "sr_utils.h"
#include "sr_if.h"


static void compose_icmp_message(uint8_t* packet, 
        uint8_t type, uint8_t code, void* data, 
        uint32_t src_ip, uint8_t* src_mac, uint32_t dst_ip, uint8_t* dst_mac)
{
    sr_ethernet_hdr_t* eh = (sr_ethernet_hdr_t *)packet;
    memcpy(eh->ether_dhost, dst_mac, ETHER_ADDR_LEN);
    memcpy(eh->ether_shost, src_mac, ETHER_ADDR_LEN);
    eh->ether_type = htons(ethertype_ip);

    sr_ip_hdr_t* iph = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    iph->ip_dst = dst_ip;
    iph->ip_hl = 5;
    iph->ip_id = time(NULL) & 0xFFFF;   /* some random value */
    iph->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
    iph->ip_off = 0;
    iph->ip_p = ip_protocol_icmp;
    iph->ip_src = src_ip;
    iph->ip_sum = 0;
    iph->ip_tos = 0;
    iph->ip_ttl = 64;
    iph->ip_v = 4;
    iph->ip_sum = cksum(iph, sizeof(sr_ip_hdr_t));

    sr_icmp_t3_hdr_t* icmph = (sr_icmp_t3_hdr_t *)(packet 
                            + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    icmph->icmp_code = code;
    icmph->icmp_type = type;
    if (data != NULL) {
        memcpy(icmph->data, data, ICMP_DATA_SIZE);
    }
    icmph->icmp_sum = 0;
    icmph->icmp_sum = cksum(icmph, sizeof(sr_icmp_t3_hdr_t));
}

void send_icmp_message(struct sr_instance *sr, char *interface,
                        uint8_t type, uint8_t code, void* data,
                        uint8_t *dst_mac, uint32_t dst_ip)
{
    uint8_t icmp_packet[sizeof(sr_ethernet_hdr_t) + 
                        sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t)];
    memset(icmp_packet, 0, sizeof(icmp_packet));

    struct sr_if *iface = sr_get_interface(sr, interface);
    if (iface == NULL) {
        fprintf(stderr, "send ICMP message - could not find interface '%s'\n", interface);
        return;
    }

    compose_icmp_message(icmp_packet, type, code, data,
                        iface->ip, iface->addr, dst_ip, dst_mac);

    size_t icmp_packet_len = sizeof(sr_ethernet_hdr_t) + 
                sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);

    fprintf(stderr, " -- ICMP message \n");
    print_hdrs(icmp_packet, icmp_packet_len);
    fprintf(stderr, " -- ICMP message -- \n\n");

    sr_send_packet(sr, icmp_packet, icmp_packet_len, interface);                
}
