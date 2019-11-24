/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <byteswap.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */) {
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length good: %d \n",len);

  /* fill in code here */
  uint16_t type = ethertype(packet);

  /* if the packet is ARP, 
  then we look at the destination to figure out it is a request or reply.*/
  if(type == 2054){
    fprintf(stderr, "It is ARP! \n");
    handle_arp(sr, packet, len, interface);
  } else {
    fprintf(stderr, "It is IP! \n");
    handle_ip(sr, packet, len, interface);
  }
}/* end sr_ForwardPacket */

void handle_arp(struct sr_instance *sr,
                      uint8_t *packet/* lent */,
                      unsigned int len,
                      char *interface/* lent */){
  sr_arp_hdr_t *arp_header = get_arp_header(packet);
  sr_ethernet_hdr_t *ethernet_header = get_Ethernet_header(packet);
  struct sr_if *packet_interface = sr_get_interface(sr, interface);

  print_hdr_arp(packet + sizeof(sr_ethernet_hdr_t));

  /* if it is a arp request */
  if (ntohs(arp_header->ar_op) == arp_op_request) {
    fprintf(stderr, "It is a arp request!\n");

    /* check if the target IP address is one of your router's IP address */
    if(arp_header->ar_tip == packet_interface->ip) {
      /*fprintf(stderr, "\tsender hardware address: ");
      print_addr_eth(arp_header->ar_sha);
      fprintf(stderr, "\tsender ip address: ");
      print_addr_ip_int(ntohl(arp_header->ar_sip));

      fprintf(stderr, "\ttarget hardware address: ");
      print_addr_eth(arp_header->ar_tha);
      fprintf(stderr, "\ttarget ip address: ");
      print_addr_ip_int(ntohl(arp_header->ar_tip));*/



      /* constract a arp reply */
      uint8_t *arp_reply = (uint8_t *) malloc(len);
      memset(arp_reply, 0, len * sizeof(uint8_t));
      sr_ethernet_hdr_t *reply_ethernet_header = get_Ethernet_header(arp_reply);
      sr_arp_hdr_t *reply_arp_header = get_arp_header(arp_reply);

      /* reply ethernet */

      memcpy(reply_ethernet_header->ether_shost, packet_interface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
      memcpy(reply_ethernet_header->ether_dhost, ethernet_header->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
      reply_ethernet_header->ether_type = htons(ethertype_arp);

      /* reply arp */
      memcpy(reply_arp_header, arp_header, sizeof(sr_arp_hdr_t));
      reply_arp_header->ar_op = htons(arp_op_reply);
      memcpy(reply_arp_header->ar_tha, arp_header->ar_sha, ETHER_ADDR_LEN);
      memcpy(reply_arp_header->ar_sha, packet_interface->addr, ETHER_ADDR_LEN);
      reply_arp_header->ar_sip = packet_interface->ip;
      reply_arp_header->ar_tip = arp_header->ar_sip;
      
      /*print_hdr_arp(arp_reply + sizeof(sr_ethernet_hdr_t));
      print_hdr_eth((sr_ethernet_hdr_t *)arp_reply);*/

      /* send the packet back */
      sr_send_packet(sr, arp_reply, len, interface);
      free(arp_reply);
    }
  } else if (arp_op_reply == ntohs(arp_header->ar_op)) { /* if it is a arp reply */
    printf("It is a arp reply!\n");
    struct sr_arpreq *cached_arp_req = sr_arpcache_insert(&(sr->cache), arp_header->ar_sha, arp_header->ar_sip);

    if (cached_arp_req) {
      struct sr_packet *arp_reply_packet = cached_arp_req->packets;
      while (arp_reply_packet) { /* Send ARP reply for original ARP request*/
        uint8_t *send_packet = arp_reply_packet->buf;
        sr_ethernet_hdr_t *modified_ethernet_header = get_Ethernet_header(send_packet);
        memcpy(modified_ethernet_header->ether_dhost, arp_header->ar_sha, ETHER_ADDR_LEN);
        memcpy(modified_ethernet_header->ether_shost, packet_interface->addr, ETHER_ADDR_LEN);
        sr_send_packet(sr, send_packet, arp_reply_packet->len, interface);
        arp_reply_packet = arp_reply_packet->next;
      }
      sr_arpreq_destroy(&(sr->cache), cached_arp_req);
    }
  }
}

/** changed**/
void send_icmp_packet(struct sr_instance *sr, uint8_t *packet, unsigned int data_len,
                             char *receiving_interface, uint8_t icmp_type, uint8_t icmp_code, struct sr_if *dest_interface)
{
    int onlyheader_len = sizeof(sr_icmp_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
    int out_len;
    if (0x00 == icmp_type) { /* Send back data with headers */
        out_len = data_len;
    } else { /* Send back only headers*/
        out_len = onlyheader_len;
    }
    uint8_t *icmp_packet = (uint8_t *)malloc(out_len);
    memset(icmp_packet, 0, sizeof(uint8_t) * out_len);

    sr_ip_hdr_t *orig_ip_header = get_ip_header(packet);
    sr_ethernet_hdr_t *orig_ethernet_header = get_Ethernet_header(packet);

    sr_ip_hdr_t *modified_ip_header = get_ip_header(icmp_packet);
    sr_icmp_hdr_t *modified_icmp_header = get_icmp_header(icmp_packet);
    sr_ethernet_hdr_t *modified_ethernet_header = get_Ethernet_header(icmp_packet);

    struct sr_if *out_interface = sr_get_interface(sr, receiving_interface);
    uint32_t source_ip = out_interface->ip;

    if (dest_interface) { /* Check if the packet was for the same interface it came in from */
        source_ip = dest_interface->ip;
    }
    /*Prepare ICMP Header*/
    if (0x00 == icmp_type) {
        /* Copying ICMP into new ICMP header */
        memcpy(modified_icmp_header, get_icmp_header(packet), out_len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
    } else {
        /*Copying IP Header into icmp header */
        memcpy(modified_icmp_header, orig_ip_header, ICMP_DATA_SIZE);
    }
    modified_icmp_header->icmp_code = icmp_code;
    modified_icmp_header->icmp_type = icmp_type;
    modified_icmp_header->icmp_sum = 0;
    if (0x00 == icmp_type) { /* Calculate checksum for header with data */
        modified_icmp_header->icmp_sum = cksum(modified_icmp_header, data_len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
    } else { /* Calculate checksum for header only */
        modified_icmp_header->icmp_sum = cksum(modified_icmp_header, sizeof(sr_icmp_hdr_t));
    }
    /* IP Header*/
    memcpy(modified_ip_header, orig_ip_header, sizeof(sr_ip_hdr_t));
    modified_ip_header->ip_ttl = INIT_TTL;
    modified_ip_header->ip_p = ip_protocol_icmp;
    modified_ip_header->ip_dst = orig_ip_header->ip_src;
    modified_ip_header->ip_len = htons(out_len - sizeof(sr_ethernet_hdr_t));
    modified_ip_header->ip_src = source_ip;
    modified_ip_header->ip_sum = 0;
    modified_ip_header->ip_sum = cksum(modified_ip_header, sizeof(sr_ip_hdr_t));

    /* Ethernet Header*/
    memcpy(modified_ethernet_header->ether_shost, out_interface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
    memcpy(modified_ethernet_header->ether_dhost, orig_ethernet_header->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
    modified_ethernet_header->ether_type = htons(ethertype_ip);
    sr_send_packet(sr, icmp_packet, out_len, receiving_interface);
    free(icmp_packet);

}


void handle_ip(struct sr_instance *sr,
                      uint8_t *packet/* lent */,
                      unsigned int len,
                      char *interface/* lent */){

    if (sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t) > len) {
            fprintf(stderr, "Error! IP packet is short.\n");
            return 1;
    }
    sr_ip_hdr_t *orig_ip_header = get_ip_header(packet);


    /* IP Header checksum */
    uint16_t orig_sum = orig_ip_header->ip_sum;
    orig_ip_header->ip_sum = 0;
    orig_ip_header->ip_sum = cksum(orig_ip_header, sizeof(sr_ip_hdr_t));
    uint16_t calculated_sum = orig_ip_header->ip_sum;
    if (calculated_sum != orig_sum) {
        orig_ip_header->ip_sum = orig_sum;
        return 1;
    }

     /* Check if packet is for my interfaces */
    struct sr_if *dest_interface = get_interface_from_ip(sr, orig_ip_header->ip_dst);
    if (dest_interface) {
        if (ip_protocol_icmp == orig_ip_header->ip_p) {
            if (sizeof(sr_icmp_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) > len) {
                fprintf(stderr, "Error! ICMP packet is short.\n");
                return 1;
            }

            /* Packet is for my interfaces and is ICMP */
            sr_icmp_hdr_t *orig_icmp_header = get_icmp_header(packet);

            /* ICMP Header checksum */
            orig_sum = orig_icmp_header->icmp_sum;
            orig_icmp_header->icmp_sum = 0;
            orig_icmp_header->icmp_sum = cksum(orig_icmp_header, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

            calculated_sum = orig_icmp_header->icmp_sum;
            if (calculated_sum != orig_sum) {
                orig_icmp_header->icmp_sum = orig_sum;
                return 1;
            }
            if (orig_icmp_header->icmp_type != 8) {
                fprintf(stderr, "Packet is not an echo request\n");
                return 1;
            }

            send_icmp_packet(sr, packet, len, interface, 0x00, 0x00, dest_interface);

        } else {  /*Packet is not ICMP.*/
            send_icmp_packet(sr, packet, len, interface, 3, 3, dest_interface);

        }
    } else {  /* Packet was not for my interfaces */

        if (orig_ip_header->ip_ttl <= 1) {
            fprintf(stderr, "The ttl expired\n");
            send_icmp_packet(sr, packet, len, interface, 11, 0, NULL);
            return 1;
        }
        /* Forward the packet with valid TTL. */

        struct sr_rt *next_hop_ip = longest_prefix_match(sr, orig_ip_header->ip_dst);
        if (!next_hop_ip) { /* No match found in routing table */

            send_icmp_packet(sr, packet, len, interface, 3, 0, NULL);
            return 1;
        }
        orig_ip_header->ip_sum = 0;
        orig_ip_header->ip_ttl--;
        orig_ip_header->ip_sum = cksum(orig_ip_header, sizeof(sr_ip_hdr_t));

        struct sr_arpentry *next_hop_mac = sr_arpcache_lookup(&(sr->cache), next_hop_ip->gw.s_addr);

        if (!next_hop_mac) { /* No ARP cache entry found */

            struct sr_arpreq *arp_req_queue = sr_arpcache_queuereq(&(sr->cache), next_hop_ip->gw.s_addr,
                                               packet, len, next_hop_ip->interface);
            arp_req_helper(sr, arp_req_queue);
            return 1;
        }

        sr_ethernet_hdr_t *send_ethernet_header = get_Ethernet_header(packet);
        memcpy(send_ethernet_header->ether_shost, sr_get_interface(sr, next_hop_ip->interface)->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
        memcpy(send_ethernet_header->ether_dhost, next_hop_mac->mac, sizeof(uint8_t) * ETHER_ADDR_LEN);
        free(next_hop_mac);
        sr_send_packet(sr, packet, len, sr_get_interface(sr, next_hop_ip->interface)->name);

    }
}

struct sr_rt *longest_prefix_match(struct sr_instance *sr, uint32_t dest_ip){
    struct sr_rt *rtable = sr->routing_table;
    struct sr_rt *longest_prefix = NULL;
    while (rtable) {
        /*if ((rtable->dest.s_addr & rtable->mask.s_addr) == (dest_ip & rtable->mask.s_addr)) {*/
        if (rtable->dest.s_addr == dest_ip ) {
            if(longest_prefix == NULL){
                longest_prefix = rtable;
            } else if(rtable->mask.s_addr > longest_prefix->mask.s_addr){
                longest_prefix = rtable;
            }
        }
        rtable = rtable->next;
    }
    return longest_prefix;
}

sr_arp_hdr_t *get_arp_header(uint8_t *packet) {
  return (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
}

sr_ethernet_hdr_t *get_Ethernet_header(uint8_t *packet){
  return (sr_ethernet_hdr_t *)packet;
}

sr_icmp_hdr_t *get_icmp_header(uint8_t *packet)
{
  return (sr_icmp_hdr_t *)(packet + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));
}

sr_ip_hdr_t *get_ip_header(uint8_t *packet)
{
  return (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
}

struct sr_if *get_interface_from_ip(struct sr_instance *sr, uint32_t ip_address)
{
    struct sr_if *curr_interface = sr->if_list;
    while (curr_interface) {
        if (ip_address == curr_interface->ip) {
            return curr_interface;
        }
        curr_interface = curr_interface->next;
    }
    return NULL;
}
