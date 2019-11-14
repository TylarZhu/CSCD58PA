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
      reply_arp_header->ar_op = ntohl(arp_op_reply);
      memcpy(reply_arp_header->ar_tha, arp_header->ar_sha, ETHER_ADDR_LEN);
      memcpy(reply_arp_header->ar_sha, packet_interface->addr, ETHER_ADDR_LEN);
      reply_arp_header->ar_sip = packet_interface->ip;
      reply_arp_header->ar_tip = arp_header->ar_sip;
      
      print_hdr_arp(arp_reply + sizeof(sr_ethernet_hdr_t));

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
        sr_ethernet_hdr_t *send_ethernet_header = get_Ethernet_header(send_packet);
        memcpy(send_ethernet_header->ether_dhost, arp_header->ar_sha, ETHER_ADDR_LEN);
        memcpy(send_ethernet_header->ether_shost, packet_interface->addr, ETHER_ADDR_LEN);
        sr_send_packet(sr, send_packet, arp_reply_packet->len, interface);
        arp_reply_packet = arp_reply_packet->next;
      }
      sr_arpreq_destroy(&(sr->cache), cached_arp_req);
    }
  }
}

void send__icmp_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len,
                             char *receiving_interface, uint8_t icmp_type, uint8_t icmp_code, struct sr_if *destination_interface)
{
    int header_len = sizeof(sr_icmp_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
    int outgoing_len;
    if (0x00 == icmp_type) { /* Send back original data with headers if type 0 */
        outgoing_len = len;
    } else { /* Send back only headers if not type 0 */
        outgoing_len = header_len;
    }
    uint8_t *send_icmp_packet = (uint8_t *)malloc(outgoing_len);
    memset(send_icmp_packet, 0, sizeof(uint8_t) * outgoing_len);

    sr_ethernet_hdr_t *original_ethernet_header = extract_ethernet_header(packet);
    sr_ip_hdr_t *original_ip_header = extract_ip_header(packet);
    sr_icmp_hdr_t *send_icmp_header = extract_icmp_header(send_icmp_packet);
    sr_ip_hdr_t *send_ip_header = extract_ip_header(send_icmp_packet);
    sr_ethernet_hdr_t *send_ethernet_header = extract_ethernet_header(send_icmp_packet);

    struct sr_if *outgoing_interface = sr_get_interface(sr, receiving_interface);
    uint32_t source_ip = outgoing_interface->ip;

    if (destination_interface) { /* Check if the packet was destined for an interface other than the one it came in on */
        source_ip = destination_interface->ip;
    }
    /*Prepare ICMP Header*/
    if (0x00 == icmp_type) {
        /* Copying ICMP metadata into new ICMP header for type 0 */
        fprintf(stderr, "Outgoing ICMP is type 0. Copying original ICMP header into outgoing ICMP header\n");
        memcpy(send_icmp_header, extract_icmp_header(packet), outgoing_len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
    } else {
        /*Copying 28 bytes of IP Header into icmp header for type 11 or type 3*/
        memcpy(send_icmp_header->data, original_ip_header, ICMP_DATA_SIZE);
    }
    send_icmp_header->icmp_code = icmp_code;
    send_icmp_header->icmp_type = icmp_type;
    send_icmp_header->icmp_sum = 0;
    if (0x00 == icmp_type) { /* Calculate cksum for header + data if type 0 */
        send_icmp_header->icmp_sum = cksum(send_icmp_header, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
    } else { /* Calculate cksum for header only if not type 0 */
        send_icmp_header->icmp_sum = cksum(send_icmp_header, sizeof(sr_icmp_hdr_t));
    }
    /*Prepare IP Header*/
    memcpy(send_ip_header, original_ip_header, sizeof(sr_ip_hdr_t));
    send_ip_header->ip_ttl = INIT_TTL;
    send_ip_header->ip_p = ip_protocol_icmp;
    send_ip_header->ip_dst = original_ip_header->ip_src;
    send_ip_header->ip_len = htons(outgoing_len - sizeof(sr_ethernet_hdr_t));
    send_ip_header->ip_src = source_ip;
    send_ip_header->ip_sum = 0;
    send_ip_header->ip_sum = cksum(send_ip_header, sizeof(sr_ip_hdr_t));
    /*Prepare Ethernet Header*/
    memcpy(send_ethernet_header->ether_shost, outgoing_interface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
    memcpy(send_ethernet_header->ether_dhost, original_ethernet_header->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
    send_ethernet_header->ether_type = htons(ethertype_ip);
    sr_send_packet(sr, send_icmp_packet, outgoing_len, receiving_interface);
    free(send_icmp_packet);
    return;
}


void handle_ip(struct sr_instance *sr,
                      uint8_t *packet/* lent */,
                      unsigned int len,
                      char *interface/* lent */){
  
}

void longest_prefix_match(struct in_addr des){
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
