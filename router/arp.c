#include "arp.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <arpa/inet.h>

#include "sr_protocol.h"
#include "sr_utils.h"
#include "sr_arpcache.h"

enum arp_proto_fmt {
  arp_proto_ipv4 = 0x0800,
};


static void handle_arp_request(struct sr_instance *sr, 
        uint8_t *packet, unsigned int len, char *interface);

static void handle_arp_reply(struct sr_instance *sr, 
        uint8_t *packet, unsigned int len, char *interface);

static void compose_arp_packet(uint8_t* packet, uint16_t opcode,
        uint8_t* sender_hw_addr, uint32_t sender_ip_addr, 
        uint8_t* target_hw_addr, uint32_t target_ip_addr);


void handle_arp(struct sr_instance *sr, uint8_t *packet,
                unsigned int len, char *interface)
{
    if (len < (sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t))) {
        fprintf(stderr, "handle ARP - insufficient length of packet\n"
            " expected: %lu + %lu, actual: %u\n\n", 
            sizeof(sr_ethernet_hdr_t), sizeof(sr_arp_hdr_t), len);
        return ;
    }

    sr_arp_hdr_t* arph = (sr_arp_hdr_t* )(packet + sizeof(sr_ethernet_hdr_t));
    /*
        TO DO: check that
        arph->ar_hrd == 1
        arph->ar_pro == 2048
        arph->ar_hln == 6
        arph->ar_pln == 4
    */    

    if (ntohs(arph->ar_op) == arp_op_request) {
        /*
            TO DO: check that
            ((sr_ethernet_hdr_t *)packet)->ether_dhost 
            contains broadcast address, i.e. FF:FF:FF:FF:FF:FF
        */
        handle_arp_request(sr, packet, len, interface);
        return;
    }

    if (ntohs(arph->ar_op) == arp_op_reply) {
        handle_arp_reply(sr, packet, len, interface);
        return;
    }
}

void compose_arp_request(uint8_t* packet, uint8_t* sender_hw_addr, 
                        uint32_t sender_ip_addr, uint32_t target_ip_addr)
{
    sr_ethernet_hdr_t* eh = (sr_ethernet_hdr_t *)packet;
    /*
    static uint8_t bcast_mac[ETHER_ADDR_LEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    memcpy(eh->ether_dhost, bcast_mac, ETHER_ADDR_LEN);    
    */
    memset(eh->ether_dhost, 0xFF, ETHER_ADDR_LEN);
    memcpy(eh->ether_shost, sender_hw_addr, ETHER_ADDR_LEN);
    eh->ether_type = htons(ethertype_arp);

    sr_arp_hdr_t* arph = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    arph->ar_hln = ETHER_ADDR_LEN;
    arph->ar_hrd = htons(arp_hrd_ethernet);
    arph->ar_op = htons(arp_op_request);
    arph->ar_pln = sizeof(uint32_t);
    arph->ar_pro = htons(ethertype_ip);
    memcpy(arph->ar_sha, sender_hw_addr, ETHER_ADDR_LEN);
    arph->ar_sip = sender_ip_addr;
    memset(arph->ar_tha, 0, ETHER_ADDR_LEN);
    arph->ar_tip = target_ip_addr;
}


static void handle_arp_request(struct sr_instance *sr, 
        uint8_t *packet, unsigned int len, char *interface)
{
    sr_arp_hdr_t* arph = (sr_arp_hdr_t* )(packet + sizeof(sr_ethernet_hdr_t));
    struct sr_if *if_iter = sr->if_list;
    while (if_iter != NULL) {
        if (if_iter->ip == arph->ar_tip) {
            break;
        }
        if_iter = if_iter->next;
    }

    if (if_iter == NULL) {
        fprintf(stderr, "handle ARP request - no interface found with IP %d.%d.%d.%d\n"
            " drop packet\n\n", 
            ((arph->ar_tip >> 0) & 0xFF), ((arph->ar_tip >> 8) & 0xFF),
            ((arph->ar_tip >> 16) & 0xFF), ((arph->ar_tip >> 24) & 0xFF));
        return;
    }

    uint8_t tx_packet[sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)] = { '\0' };
    memset(tx_packet, 0, sizeof(tx_packet));

    compose_arp_packet(tx_packet, arp_op_reply, 
        if_iter->addr, if_iter->ip, arph->ar_sha, arph->ar_sip);
    
    fprintf(stderr, " -- ARP reply \n");
    print_hdrs(tx_packet, sizeof(tx_packet));
    fprintf(stderr, " -- ARP reply -- \n\n");

    sr_send_packet(sr, tx_packet, sizeof(tx_packet), interface);
}

static void handle_arp_reply(struct sr_instance *sr, 
        uint8_t *packet, unsigned int len, char *interface)
{
    sr_arp_hdr_t* arph = (sr_arp_hdr_t* )(packet + sizeof(sr_ethernet_hdr_t));
    struct sr_arpreq* arpreq = 
        sr_arpcache_insert(&sr->cache, arph->ar_sha, arph->ar_sip);

    if (arpreq != NULL) {
        /* validate request */
        if ((arpreq->ip != arph->ar_sip) || (arpreq->times_sent >= 5)) {
            fprintf(stderr, "handle ARP reply - wrong arpreq found \n" 
                "IP %d.%d.%d.%d, times send %u\n\n",
                ((arpreq->ip >> 0) & 0xFF), ((arpreq->ip >> 8) & 0xFF), 
                ((arpreq->ip >> 16) & 0xFF), ((arpreq->ip >> 24) & 0xFF), 
                arpreq->times_sent);
            free(arpreq);
            return;
        }
        
        fprintf(stderr, "handle ARP reply - send queued packets\n");
        struct sr_packet *pkt = arpreq->packets;
        while (pkt != NULL) {
            sr_ethernet_hdr_t* eh = (sr_ethernet_hdr_t*)pkt->buf;
            memcpy(eh->ether_dhost, arph->ar_sha, ETHER_ADDR_LEN);

            fprintf(stderr, "send packet via %s\n", pkt->iface);
            print_hdrs(pkt->buf, pkt->len);
            fprintf(stderr, "-- packet headers --\n\n");
            sr_send_packet(sr, pkt->buf, pkt->len, pkt->iface);
            
            struct sr_packet* next = pkt->next;

            free(pkt->buf);
            free(pkt->iface);
            free(pkt);
            pkt = next;
        }

        free(arpreq);
    }
}

static void compose_arp_packet(uint8_t* packet, uint16_t opcode,
                uint8_t* sender_hw_addr, uint32_t sender_ip_addr, 
                uint8_t* target_hw_addr, uint32_t target_ip_addr)
{
    sr_ethernet_hdr_t* eh = (sr_ethernet_hdr_t *)packet;
    memcpy(eh->ether_dhost, target_hw_addr, ETHER_ADDR_LEN);
    memcpy(eh->ether_shost, sender_hw_addr, ETHER_ADDR_LEN);
    eh->ether_type = htons(ethertype_arp);

    sr_arp_hdr_t* arph = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    arph->ar_hln = ETHER_ADDR_LEN;
    arph->ar_hrd = htons(arp_hrd_ethernet);
    arph->ar_op = htons(opcode);
    arph->ar_pln = sizeof(uint32_t);
    arph->ar_pro = htons(arp_proto_ipv4);
    memcpy(arph->ar_sha, sender_hw_addr, ETHER_ADDR_LEN);
    arph->ar_sip = sender_ip_addr;
    memcpy(arph->ar_tha, target_hw_addr, ETHER_ADDR_LEN);
    arph->ar_tip = target_ip_addr;
}
