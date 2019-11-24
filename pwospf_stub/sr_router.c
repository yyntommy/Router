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
#include <stdlib.h>
#include <string.h>


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
    pthread_t arp_thread;

    pthread_create(&arp_thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    srand(time(NULL));
    pthread_mutexattr_init(&(sr->rt_lock_attr));
    pthread_mutexattr_settype(&(sr->rt_lock_attr), PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&(sr->rt_lock), &(sr->rt_lock_attr));

    pthread_attr_init(&(sr->rt_attr));
    pthread_attr_setdetachstate(&(sr->rt_attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->rt_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->rt_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t rt_thread;
    pthread_create(&rt_thread, &(sr->rt_attr), sr_rip_timeout, sr);
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
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);
  printf("*** -> Received packet of length %d \n",len);
  /* fill in code here */
  print_hdrs(packet, len);
  int len_check = sizeof(sr_ethernet_hdr_t);
  if (len < len_check) {
	  printf("minimal size not reached (ethernet header)");
	  return;
  }
  sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t*) packet;

  if (ntohs(ether_hdr->ether_type) == ethertype_ip) {
	  printf("this is an ip packet\n");
	  len_check = len_check + sizeof(sr_ip_hdr_t);
	  if (len < len_check) {
		  printf("minimal size not reached (ip header)\n");
		  return;
	  }
	  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
	  uint16_t checksum1 = ip_hdr->ip_sum;
	  ip_hdr->ip_sum = 0;
	  uint16_t checksum2 = cksum(ip_hdr, ip_hdr->ip_hl*4);
	  if (checksum1 != checksum2) {
		  printf("checksum error\n");
		  return;
	  }
	  printf("ip checksum passed\n");
	  ip_hdr->ip_sum = checksum1;
	  struct sr_if *tif = get_if_by_ip_no_mask(sr->if_list, ip_hdr->ip_dst);
	  if (tif != 0 && tif->status == 1) {
		  printf("this packet is for my interface\n");
		  if (ip_hdr->ip_p == 1) {
			  printf("this is imcp, sending echo\n");
			  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t*)((uint8_t*)ip_hdr + sizeof(sr_ip_hdr_t));
			  uint16_t icmp_checksum1 = icmp_hdr->icmp_sum;
			  icmp_hdr->icmp_sum = 0;
			  uint16_t icmp_checksum2 = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t));
			  if (icmp_checksum1 != icmp_checksum2) {
				  printf("icmp checksum error\n");
				  return;
			  }
			  printf("icmp checksum passed\n");
			  send_echo_back(sr, ip_hdr);
		  } else if (ip_hdr->ip_p == 6) {
			  printf("this is TCP\n");
			  icmp_error(sr, ip_hdr, 3, 3);
		  } else if (ip_hdr->ip_p == 17) {
			  printf("this is UDP\n");
			  sr_udp_hdr_t *udp_hdr = (sr_udp_hdr_t*)((uint8_t*)ip_hdr + sizeof(sr_ip_hdr_t));
			  /*uint16_t udp_checksum1 = udp_hdr->udp_sum;
			  udp_hdr->udp_sum = 0;
			  uint16_t udp_checksum2 = cksum(udp_hdr, ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t));
			  udp_hdr->udp_sum = htons(checksum1);
			  printf("checksum1 %d, checksum2 %d\n", udp_checksum1, udp_checksum2);
			  printf("the port number is %d", ntohs(udp_hdr->port_src));
			  if (udp_checksum1 != udp_checksum2) {
				  printf("udp checksum error\n");
				  return;
			  }
			  printf("udp checksum passed\n"); */
			  if (ntohs(udp_hdr->port_dst) == 520) {
				  printf("this is rip\n");
				  sr_rip_pkt_t *rip_pkt = (sr_rip_pkt_t*)((uint8_t*)ip_hdr + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t));
				  if (rip_pkt->command == 1) {
					  printf("this is rip request\n");
					  send_rip_update(sr);
				  } else {
					  printf("this is rip response\n");
					  update_route_table(sr, ip_hdr, rip_pkt, tif->name);
				  }
			  } else {
				  printf("not rip, sending icmp\n");
				  icmp_error(sr, ip_hdr, 3, 3);
			  }
		  } else {
			  printf("ip protocal out of scope\n");
		  }
	  } else {
		  struct sr_if *tif2 = get_if_by_ip(sr->if_list, ip_hdr->ip_dst);
		  if (tif2 != 0) {
			  if (ip_hdr->ip_p == 17) {
				  sr_udp_hdr_t *udp_hdr = (sr_udp_hdr_t*)((uint8_t*)ip_hdr + sizeof(sr_ip_hdr_t));
				  /*uint16_t udp_checksum1 = udp_hdr->udp_sum;
				  udp_hdr->udp_sum = 0;
				  uint16_t udp_checksum2 = cksum(udp_hdr, ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t));
				  udp_hdr->udp_sum = htons(checksum1);
				  printf("checksum1 %d, checksum2 %d\n", udp_checksum1, udp_checksum2);
				  printf("the port number is %d", ntohs(udp_hdr->port_src));
				  if (udp_checksum1 != udp_checksum2) {
					  printf("udp checksum error\n");
					  return;
				  }
				  printf("udp checksum passed\n"); */
				  if (ntohs(udp_hdr->port_dst) == 520) {
					  printf("this is rip\n");
					  sr_rip_pkt_t *rip_pkt = (sr_rip_pkt_t*)((uint8_t*)ip_hdr + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t));
					  if (rip_pkt->command == 1) {
						  printf("this is rip request\n");
						  send_rip_update(sr);
					  } else {
						  printf("this is rip response\n");
						  update_route_table(sr, ip_hdr, rip_pkt, tif2->name);
					  }
					  return;
				  }
			  }
		  }
		  printf("this packet is not for my interface, going to forward it\n");
		  if(ip_hdr->ip_ttl == 1) {
			  printf("ttl is zero");
			  icmp_error(sr, ip_hdr, 11, 0);
		  } else {
			  ip_hdr->ip_ttl--;
			  ip_hdr->ip_sum = 0;
			  ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl*4);
			  pthread_mutex_lock(&(sr->rt_lock));
			  struct sr_rt *best_rt = find_best_rt(sr->routing_table, ip_hdr->ip_dst);
			  pthread_mutex_unlock(&(sr->rt_lock));
			  if (best_rt) {
				  pthread_mutex_lock(&(sr->rt_lock));
				  struct sr_if *interface = sr_get_interface(sr, best_rt->interface);
				  if (best_rt->gw.s_addr == 0) {
						forward_package(sr, packet, len, ip_hdr->ip_dst, interface);
					} else {
						forward_package(sr, packet, len, best_rt->gw.s_addr, interface);
					}
				  pthread_mutex_unlock(&(sr->rt_lock));
			  } else {
				  printf("Dest net unreachable");
				  icmp_error(sr, ip_hdr, 3, 0);
			  }
		  }
	  }
  }
  else if (ntohs(ether_hdr->ether_type) == ethertype_arp) {
	  printf("this is an arp packet\n");
	  len_check = len_check + sizeof(sr_arp_hdr_t);
	  if (len < len_check) {
		  printf("minimal size not rached (arp header)\n");
		  return;
	  }
	  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
	  if (ntohs(arp_hdr->ar_op) == arp_op_request) {
		  printf("this is an arp request\n");
		  struct sr_if *tif = get_if_by_ip(sr->if_list, arp_hdr->ar_tip);
		  if(tif != 0) {
			  send_arp_reply(sr, arp_hdr, tif);
			  struct sr_arpreq *request = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
			  if (request == 0){
				  printf("did not find the corresponding request");
			  } else {
				  struct sr_packet *packets = request->packets;
				  while(packets){
					  struct sr_if *interface = sr_get_interface(sr, packets->iface);
			  		  forward_package(sr, packets->buf, packets->len, arp_hdr->ar_sip, interface);
			  		  packets = packets->next;
				  }
			  	  sr_arpreq_destroy(&sr->cache, request);
			  }
		  } else {
			  printf("The request is not to me, ignore it");
		  }
	  } else if (ntohs(arp_hdr->ar_op) == arp_op_reply) {
		  printf("this is an arp reply\n");
		  struct sr_if *tif = get_if_by_ip(sr->if_list, arp_hdr->ar_tip);
		  if (tif != 0){
			  struct sr_arpreq *request = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
			  if (request == 0){
				  printf("did not find the corresponding request");
			  } else {
				  struct sr_packet *packets = request->packets;
				  while(packets){
					  struct sr_if *interface = sr_get_interface(sr, packets->iface);
					  forward_package(sr, packets->buf, packets->len, arp_hdr->ar_sip, interface);
					  packets = packets->next;
				  }
				  sr_arpreq_destroy(&sr->cache, request);
			  }
		  } else {
			  printf("The reply is not to me, ignore it");
		  }
	  } else {
		  printf("neither request nor reply, error");
		  return;
	  }
  } else {
	  printf("the type is %d\n", ntohs(ether_hdr->ether_type));
	  printf("neither ip packet nor arp packet\n");
  }

}/* end sr_ForwardPacket */

void send_arp_reply(struct sr_instance* sr, struct sr_arp_hdr* arp_hdr, struct sr_if* tif) {
	printf("I have the interface, sending the reply rn\n");
	uint8_t *buf = (uint8_t*)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
	sr_ethernet_hdr_t *r_ether_hdr = (sr_ethernet_hdr_t*)buf;
	memcpy(r_ether_hdr->ether_dhost, arp_hdr->ar_sha, 6);
	memcpy(r_ether_hdr->ether_shost, tif->addr, 6);
	r_ether_hdr->ether_type = htons(ethertype_arp);
	sr_arp_hdr_t *r_arp_hdr = (sr_arp_hdr_t*)(buf + sizeof(sr_ethernet_hdr_t));
	memcpy(r_arp_hdr, arp_hdr, sizeof(sr_arp_hdr_t));
	r_arp_hdr->ar_op = htons(arp_op_reply);
	memcpy(r_arp_hdr->ar_sha, tif->addr, 6);
	memcpy(r_arp_hdr->ar_tha, arp_hdr->ar_sha, 6);
	r_arp_hdr->ar_sip = tif->ip;
	r_arp_hdr->ar_tip = arp_hdr->ar_sip;
	sr_send_packet(sr, buf, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), tif->name);
	print_hdrs(buf,sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
	free(buf);
}

void sr_arp_send_request(struct sr_instance *sr, struct sr_arpreq *current){
	printf("I am sending an arp request\n");
	unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
	pthread_mutex_lock(&(sr->rt_lock));
	struct sr_rt *best_rt = find_best_rt(sr->routing_table, current->ip);
	pthread_mutex_unlock(&(sr->rt_lock));
	if(best_rt == 0) {
		printf("the ip address is %d\n", current->ip);
		printf("I cannot reach this destination\n");
		return;
	}
	pthread_mutex_lock(&(sr->rt_lock));
	struct sr_if *interface = sr_get_interface(sr, best_rt->interface);
	pthread_mutex_unlock(&(sr->rt_lock));
	uint8_t *buf = (uint8_t*)malloc(len);
	sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t*)buf;
	memset(ether_hdr->ether_dhost, 0xff, 6);
	memcpy(ether_hdr->ether_shost, interface->addr, 6);
	ether_hdr->ether_type = htons(ethertype_arp);
	sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t*)(buf + sizeof(sr_ethernet_hdr_t));
	arp_hdr->ar_hln = 0x06;
	arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
	arp_hdr->ar_op = htons(arp_op_request);
	arp_hdr->ar_pln = 0x04;
	arp_hdr->ar_pro = htons(ethertype_ip);
	memcpy(arp_hdr->ar_sha, interface->addr, 6);
	memset(arp_hdr->ar_tha, 0, 6);
	arp_hdr->ar_sip = interface->ip;
	arp_hdr->ar_tip = current->ip;
	sr_send_packet(sr, buf, len, interface->name);
	print_hdrs(buf, len);
	current->times_sent = current->times_sent+1;
	time_t now = time(NULL);
	current->sent = now;
}

void send_echo_back(struct sr_instance* sr, struct sr_ip_hdr* ip_hdr) {
	printf("I am going to echo back\n");
	unsigned int len = sizeof(sr_ethernet_hdr_t) + ntohs(ip_hdr->ip_len);
	uint8_t *buf = (uint8_t*)malloc(len);
	sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t*)buf;
	memset(ether_hdr->ether_dhost, 0, 6);
	memset(ether_hdr->ether_shost, 0, 6);
	ether_hdr->ether_type = htons(ethertype_ip);
	sr_ip_hdr_t *e_ip_hdr = (sr_ip_hdr_t*)(buf + sizeof(sr_ethernet_hdr_t));
	memcpy(e_ip_hdr, ip_hdr, ntohs(ip_hdr->ip_len));
	e_ip_hdr->ip_sum = 0;
	e_ip_hdr->ip_src = ip_hdr->ip_dst;
	e_ip_hdr->ip_ttl = 64;
	e_ip_hdr->ip_dst = ip_hdr->ip_src;
	e_ip_hdr->ip_sum = cksum(e_ip_hdr, e_ip_hdr->ip_hl*4);
	sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t*)((uint8_t*)e_ip_hdr + sizeof(sr_ip_hdr_t));
	icmp_hdr->icmp_code = 0;
	icmp_hdr->icmp_type = 0;
	icmp_hdr->icmp_sum = 0;
	icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t));
	pthread_mutex_lock(&(sr->rt_lock));
	struct sr_rt *best_rt = find_best_rt(sr->routing_table, e_ip_hdr->ip_dst);
	pthread_mutex_unlock(&(sr->rt_lock));
	if(best_rt) {
		printf("found the entry in the routing table\n");
		pthread_mutex_lock(&(sr->rt_lock));
		struct sr_if *interface = sr_get_interface(sr, best_rt->interface);
		if (best_rt->metric == 0) {
			forward_package(sr, buf, len, e_ip_hdr->ip_dst, interface);
		} else {
			forward_package(sr, buf, len, best_rt->gw.s_addr, interface);
		}
		pthread_mutex_unlock(&(sr->rt_lock));
		free(buf);
	} else {
		printf("I cannot reach the echo back destination\n");
		return;
	}
}

void forward_package(struct sr_instance* sr, uint8_t* buf, unsigned int len, uint32_t ip, struct sr_if* interface) {
	printf("trying to forward package\n");
	struct sr_arpentry* arpentry = sr_arpcache_lookup(&(sr->cache), ip);
	if(arpentry) {
		printf("found arp entry\n");
		sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t*)buf;
		memcpy(ether_hdr->ether_shost, interface->addr, 6);
		memcpy(ether_hdr->ether_dhost, arpentry->mac, 6);
		sr_send_packet(sr, buf, len, interface->name);
		printf("printing forwarded package");
		print_hdrs(buf, len);
		free(arpentry);
	} else {
		printf("did not find arp entry, now adding package to the queue\n");
		struct sr_arpreq *current = sr_arpcache_queuereq(&(sr->cache), ip, buf, len, interface->name);
		sr_arp_send_request(sr, current);
	}
}

void icmp_error(struct sr_instance *sr, struct sr_ip_hdr *ip_hdr, uint8_t type, uint8_t code){
	unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
	uint8_t *buf = (uint8_t*)malloc(len);
	sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t*)buf;
	memset(ether_hdr->ether_dhost, 0, 6);
	memset(ether_hdr->ether_shost, 0, 6);
	ether_hdr->ether_type = htons(ethertype_ip);
	pthread_mutex_lock(&(sr->rt_lock));
	struct sr_rt *best_rt = find_best_rt(sr->routing_table, ip_hdr->ip_src);
	pthread_mutex_unlock(&(sr->rt_lock));
	if (best_rt == 0) {
		printf("cannot reach the destination");
		return;
	}
	pthread_mutex_lock(&(sr->rt_lock));
	struct sr_if *interface = sr_get_interface(sr, best_rt->interface);
	pthread_mutex_unlock(&(sr->rt_lock));
	sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t*)(buf + sizeof(sr_ethernet_hdr_t));
	new_ip_hdr->ip_dst = ip_hdr->ip_src;
	new_ip_hdr->ip_hl = ip_hdr->ip_hl;
	new_ip_hdr->ip_id = ip_hdr->ip_id;
	new_ip_hdr->ip_len = htons(len - sizeof(sr_ethernet_hdr_t));
	new_ip_hdr->ip_off = ip_hdr->ip_off;
	new_ip_hdr->ip_p = 1;
	new_ip_hdr->ip_sum = 0;
	if (code == 3) {
		new_ip_hdr->ip_src = ip_hdr->ip_dst;
	} else {
		new_ip_hdr->ip_src = interface->ip;
	}
	new_ip_hdr->ip_tos = ip_hdr->ip_tos;
	new_ip_hdr->ip_ttl = 64;
	new_ip_hdr->ip_v = ip_hdr->ip_v;
	new_ip_hdr->ip_sum = cksum(new_ip_hdr, new_ip_hdr->ip_hl*4);
	sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t*)((uint8_t*)new_ip_hdr + sizeof(sr_ip_hdr_t));
	memcpy(icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);
	icmp_hdr->icmp_code = code;
	icmp_hdr->icmp_sum = 0;
	icmp_hdr->icmp_type = type;
	icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(new_ip_hdr->ip_len) - sizeof(sr_ip_hdr_t));
	pthread_mutex_lock(&(sr->rt_lock));
	if (best_rt->gw.s_addr == 0) {
		forward_package(sr, buf, len, new_ip_hdr->ip_dst, interface);
	} else {
		forward_package(sr, buf, len, best_rt->gw.s_addr, interface);
	}
	pthread_mutex_unlock(&(sr->rt_lock));
	free(buf);
}
