#include "ip.h"
#include "arp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>

#include "sr_protocol.h"
#include "sr_utils.h"
#include "sr_rt.h"
#include "sr_if.h"
#include "sr_arpcache.h"

enum ip_protocol {
  ip_protocol_tcp = 0x0006,
  ip_protocol_udp = 0x0011
};

static void forward_ip_packet(struct sr_instance *sr, uint8_t *packet,
                                unsigned int len, char *interface);

static struct sr_rt* lookup_rt_entry(struct sr_rt *table, uint32_t ipaddr);

void handle_ip(struct sr_instance *sr, uint8_t *packet,
                unsigned int len, char *interface)
{
    if (len < (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t))) {
        fprintf(stderr, "handle IP - insufficient length of packet\n"
            " expected (at least): %lu + %lu, actual: %u\n\n", 
            sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t), len);
        return ;
    }

    sr_ip_hdr_t* iph = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    uint16_t orig_cksum = iph->ip_sum;
    iph->ip_sum = 0;
    uint16_t checksum = cksum(iph, sizeof(sr_ip_hdr_t));
    if (orig_cksum != checksum) {
        fprintf(stderr, "handle IP - wrong checksum\n"
            " expected: %04X, actual: %04X\n\n", checksum, orig_cksum);
        return;
    }
    
    struct sr_if *if_iter = sr->if_list;
    while (if_iter != NULL) {
        if (if_iter->ip == iph->ip_dst) {
            break;
        }
        if_iter = if_iter->next;
    }

    if (if_iter == NULL) {
        fprintf(stderr, "handle IP - forward packet with dst IP %d.%d.%d.%d\n\n",
            ((iph->ip_dst >> 0) & 0xFF), ((iph->ip_dst >> 8) & 0xFF),
            ((iph->ip_dst >> 16) & 0xFF), ((iph->ip_dst >> 24) & 0xFF));

        if (iph->ip_ttl > 1) {
            forward_ip_packet(sr, packet, len, interface);
            return;
        }

        /* TO DO: send ICMP message 'time exceeded' (type: 11, code: 0) */
        return ;
    }

    if (iph->ip_p == ip_protocol_icmp) {
        /* TO DO: 
            1. check if message is 'echo request (type: , code: )
            2. send ICMP message 'echo reply' (type: 0, code: doesn't matter) */
    }

    if (iph->ip_p == ip_protocol_tcp || iph->ip_p == ip_protocol_udp) {
        /* TO DO: send ICMP message 'port unreachable' */
    }
}

static void forward_ip_packet(struct sr_instance *sr, uint8_t *packet,
                                unsigned int len, char *interface)
{
    sr_ip_hdr_t* iph = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    struct sr_rt* rt_entry = lookup_rt_entry(sr->routing_table, iph->ip_dst);

    if (rt_entry != NULL) {
        uint8_t* tx_packet = (uint8_t *)malloc(len);
        if (tx_packet == NULL) {
            fprintf(stderr, "forward IP packet - could not allocate memory for packet\n");
            return;
        }
        memcpy(tx_packet, packet, len);

        iph = (sr_ip_hdr_t *)(tx_packet + sizeof(sr_ethernet_hdr_t));
        iph->ip_ttl -= 1;
        iph->ip_sum = 0;
        iph->ip_sum = cksum(iph, sizeof(sr_ip_hdr_t));

        struct sr_if *iface = sr_get_interface(sr, rt_entry->interface);
        if (iface == NULL) {
            fprintf(stderr, "forward IP packet - could not find interface '%s'\n", rt_entry->interface);
            free(tx_packet);
            return;
        }

        sr_ethernet_hdr_t* eh = (sr_ethernet_hdr_t *)(tx_packet);
        memcpy(eh->ether_shost, iface->addr, ETHER_ADDR_LEN);

        struct sr_arpentry *arpentry = sr_arpcache_lookup(&sr->cache, rt_entry->gw.s_addr);
        if (arpentry != NULL) {
            /* validate ARP cache entry */
            if (!arpentry->valid) {
                fprintf(stderr, "forward IP packet - got not valid ARP cache entry\n"
                    "MAC %02X:%02X:%02X:%02X:%02X:%02X  IP %s  added at %ld, now %ld\n",
                    arpentry->mac[0], arpentry->mac[1], arpentry->mac[2], 
                    arpentry->mac[3], arpentry->mac[4], arpentry->mac[5],
                    inet_ntoa(rt_entry->gw), arpentry->added, time(NULL));
                free(tx_packet);
                free(arpentry);
                return;
            }

            memcpy(eh->ether_dhost, arpentry->mac, ETHER_ADDR_LEN);
            free(arpentry);
            sr_send_packet(sr, tx_packet, len, rt_entry->interface);
            free(tx_packet);
        } else {
            fprintf(stderr, "forward IP packet - not found ARP cache entry for %s\n",
                inet_ntoa(rt_entry->gw));

            uint8_t arp_request[sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)] = { '\0'};
            memset(arp_request, 0, sizeof(arp_request));

            compose_arp_request(arp_request, iface->addr, iface->ip, rt_entry->gw.s_addr); 

            fprintf(stderr, " -- ARP request \n");
            print_hdrs(arp_request, sizeof(arp_request));
            fprintf(stderr, " -- ARP request -- \n\n");

            sr_send_packet(sr, arp_request, sizeof(arp_request), rt_entry->interface);

            sr_arpcache_queuereq(&sr->cache, rt_entry->gw.s_addr,
                                tx_packet, len, rt_entry->interface);
            free(tx_packet);
        }

        return;
    }

    /* TO DO: send ICMP message 'destination net unreachable' (type: 3, code: 0)*/
}

static struct sr_rt* lookup_rt_entry(struct sr_rt *table, uint32_t ipaddr)
{
    uint32_t best_mask = 0;
    struct sr_rt* rt_iter = table;
    struct sr_rt* rt_entry = NULL;
    while (rt_iter != NULL) {
        if (((rt_iter->mask.s_addr & ipaddr) == rt_iter->dest.s_addr) 
            && (rt_iter->mask.s_addr > best_mask)) {
                best_mask = rt_iter->mask.s_addr;
                rt_entry = rt_iter;
        }
        rt_iter = rt_iter->next;
    }
    return rt_entry;
}