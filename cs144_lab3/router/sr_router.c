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
    printf("It is ARP! \n");
    handle_arp(sr, packet, len, interface);
  } else {
    printf("It is IP! \n");
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

  /* if it is a arp request */
  if (ntohs(arp_header->ar_op) == arp_op_request) {
    printf("It is a arp request!\n");

    /* check if the target IP address is one of your router's IP address */
    if(arp_header->ar_tip == packet_interface->ip) {
      fprintf(stderr, "\tsender hardware address: ");
      print_addr_eth(arp_header->ar_sha);
      fprintf(stderr, "\tsender ip address: ");
      print_addr_ip_int(ntohl(arp_header->ar_sip));

      fprintf(stderr, "\ttarget hardware address: ");
      print_addr_eth(arp_header->ar_tha);
      fprintf(stderr, "\ttarget ip address: ");
      print_addr_ip_int(ntohl(arp_header->ar_tip));

      /* constract a arp reply */
      uint8_t *arp_reply = (uint8_t *) malloc(len);
      memset(arp_reply, 0, len * sizeof(uint8_t));
      sr_ethernet_hdr_t *reply_ethernet_header = (sr_ethernet_hdr_t *) arp_reply;
      sr_arp_hdr_t *reply_arp_header = (sr_arp_hdr_t *) arp_reply;

      /* reply ethernet */
      memcpy(reply_ethernet_header->ether_dhost, ethernet_header->ether_shost, ETHER_ADDR_LEN);
      memcpy(reply_ethernet_header->ether_shost, packet_interface->addr, ETHER_ADDR_LEN);
      reply_ethernet_header->ether_type = ntohl(ethertype_arp);

      /* reply arp */
      memcpy(reply_arp_header, arp_header, sizeof(sr_arp_hdr_t));
      reply_arp_header->ar_op = ntohl(arp_op_reply);
      memcpy(reply_arp_header->ar_tha, arp_header->ar_sha, ETHER_ADDR_LEN);
      memcpy(reply_arp_header->ar_sha, packet_interface->addr, ETHER_ADDR_LEN);
      reply_arp_header->ar_sip = packet_interface->ip;
      reply_arp_header->ar_tip = arp_header->ar_sip;

      fprintf(stderr, "++++++++++++++++\n");
      print_addr_eth(ethernet_header->ether_shost);
      sr_print_if(packet_interface);
      
      /* send the packet back */
      sr_send_packet(sr, arp_reply, len, interface);
      free(arp_reply);
    }

  } else {
    printf("It is a arp reply!\n");
  }
}

void handle_ip(struct sr_instance *sr,
                      uint8_t *packet/* lent */,
                      unsigned int len,
                      char *interface/* lent */){

}

void longest_prefix_match(struct in_addr des){
  printf("%s\t\t\n",inet_ntoa(des));
}

sr_arp_hdr_t *get_arp_header(uint8_t *packet) {
  return (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
}

sr_ethernet_hdr_t *get_Ethernet_header(uint8_t *packet){
  return (sr_ethernet_hdr_t *)packet;
}