/*-----------------------------------------------------------------------------
 * file:  sr_rt.c
 * date:  Mon Oct 07 04:02:12 PDT 2002
 * Author:  casado@stanford.edu
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>


#include <sys/socket.h>
#include <netinet/in.h>
#define __USE_MISC 1 /* force linux to show inet_aton */
#include <arpa/inet.h>

#include "sr_rt.h"
#include "sr_if.h"
#include "sr_utils.h"
#include "sr_router.h"

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

int sr_load_rt(struct sr_instance* sr,const char* filename)
{
    FILE* fp;
    char  line[BUFSIZ];
    char  dest[32];
    char  gw[32];
    char  mask[32];    
    char  iface[32];
    struct in_addr dest_addr;
    struct in_addr gw_addr;
    struct in_addr mask_addr;
    int clear_routing_table = 0;

    /* -- REQUIRES -- */
    assert(filename);
    if( access(filename,R_OK) != 0)
    {
        perror("access");
        return -1;
    }

    fp = fopen(filename,"r");

    while( fgets(line,BUFSIZ,fp) != 0)
    {
        sscanf(line,"%s %s %s %s",dest,gw,mask,iface);
        if(inet_aton(dest,&dest_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    dest);
            return -1; 
        }
        if(inet_aton(gw,&gw_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    gw);
            return -1; 
        }
        if(inet_aton(mask,&mask_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    mask);
            return -1; 
        }
        if( clear_routing_table == 0 ){
            printf("Loading routing table from server, clear local routing table.\n");
            sr->routing_table = 0;
            clear_routing_table = 1;
        }
        sr_add_rt_entry(sr,dest_addr,gw_addr,mask_addr,(uint32_t)0,iface);
    } /* -- while -- */

    return 0; /* -- success -- */
} /* -- sr_load_rt -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/
int sr_build_rt(struct sr_instance* sr){
    struct sr_if* interface = sr->if_list;
    char  iface[32];
    struct in_addr dest_addr;
    struct in_addr gw_addr;
    struct in_addr mask_addr;

    while (interface){
        dest_addr.s_addr = (interface->ip & interface->mask);
        gw_addr.s_addr = 0;
        mask_addr.s_addr = interface->mask;
        strcpy(iface, interface->name);
        sr_add_rt_entry(sr, dest_addr, gw_addr, mask_addr, (uint32_t)0, iface);
        interface = interface->next;
    }
    return 0;
}

void sr_add_rt_entry(struct sr_instance* sr, struct in_addr dest,
struct in_addr gw, struct in_addr mask, uint32_t metric, char* if_name)
{   
    struct sr_rt* rt_walker = 0;

    /* -- REQUIRES -- */
    assert(if_name);
    assert(sr);

    pthread_mutex_lock(&(sr->rt_lock));
    /* -- empty list special case -- */
    if(sr->routing_table == 0)
    {
        sr->routing_table = (struct sr_rt*)malloc(sizeof(struct sr_rt));
        assert(sr->routing_table);
        sr->routing_table->next = 0;
        sr->routing_table->dest = dest;
        sr->routing_table->gw   = gw;
        sr->routing_table->mask = mask;
        strncpy(sr->routing_table->interface,if_name,sr_IFACE_NAMELEN);
        sr->routing_table->metric = metric;
        time_t now;
        time(&now);
        sr->routing_table->updated_time = now;

        pthread_mutex_unlock(&(sr->rt_lock));
        return;
    }

    /* -- find the end of the list -- */
    rt_walker = sr->routing_table;
    while(rt_walker->next){
      rt_walker = rt_walker->next; 
    }

    rt_walker->next = (struct sr_rt*)malloc(sizeof(struct sr_rt));
    assert(rt_walker->next);
    rt_walker = rt_walker->next;

    rt_walker->next = 0;
    rt_walker->dest = dest;
    rt_walker->gw   = gw;
    rt_walker->mask = mask;
    strncpy(rt_walker->interface,if_name,sr_IFACE_NAMELEN);
    rt_walker->metric = metric;
    time_t now;
    time(&now);
    rt_walker->updated_time = now;
    
     pthread_mutex_unlock(&(sr->rt_lock));
} /* -- sr_add_entry -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_print_routing_table(struct sr_instance* sr)
{
    pthread_mutex_lock(&(sr->rt_lock));
    struct sr_rt* rt_walker = 0;

    if(sr->routing_table == 0)
    {
        printf(" *warning* Routing table empty \n");
        pthread_mutex_unlock(&(sr->rt_lock));
        return;
    }
    printf("  <---------- Router Table ---------->\n");
    printf("Destination\tGateway\t\tMask\t\tIface\tMetric\tUpdate_Time\n");

    rt_walker = sr->routing_table;
    
    while(rt_walker){
        if (rt_walker->metric < INFINITY)
            sr_print_routing_entry(rt_walker);
        rt_walker = rt_walker->next;
    }
    pthread_mutex_unlock(&(sr->rt_lock));


} /* -- sr_print_routing_table -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_print_routing_entry(struct sr_rt* entry)
{
    /* -- REQUIRES --*/
    assert(entry);
    assert(entry->interface);
    
    char buff[20];
    struct tm* timenow = localtime(&(entry->updated_time));
    strftime(buff, sizeof(buff), "%H:%M:%S", timenow);
    printf("%s\t",inet_ntoa(entry->dest));
    printf("%s\t",inet_ntoa(entry->gw));
    printf("%s\t",inet_ntoa(entry->mask));
    printf("%s\t",entry->interface);
    printf("%d\t",entry->metric);
    printf("%s\n", buff);

} /* -- sr_print_routing_entry -- */


void *sr_rip_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    while (1) {
        sleep(5);
        pthread_mutex_lock(&(sr->rt_lock));
        /* Fill your code here */
        struct sr_rt *previous = 0;
        struct sr_rt *current = sr->routing_table;
        time_t now = time(NULL);
        while (current) {
        	if (difftime(now, current->updated_time) >= 20) {
        		if (previous) {
        			previous->next = current->next;
        			current = current->next;
        		} else {
        			sr->routing_table = current->next;
        			current = current->next;
        		}
        	} else {
        		previous = current;
        		current = current->next;
        	}
        }
        send_rip_update(sr);
        pthread_mutex_unlock(&(sr->rt_lock));
    }
    return NULL;
}

void send_rip_request(struct sr_instance *sr){
    /* Fill your code here */
	unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t);
	uint8_t *buf = (uint8_t*)malloc(len);
	sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t*)buf;
	memset(ether_hdr->ether_dhost, 0xff, 6);
	memset(ether_hdr->ether_shost, 0, 6);
	ether_hdr->ether_type = htons(ethertype_ip);
	sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t*)(buf + sizeof(sr_ethernet_hdr_t));
	new_ip_hdr->ip_hl = 5;
	new_ip_hdr->ip_len = htons(len - sizeof(sr_ethernet_hdr_t));
	new_ip_hdr->ip_off = htons(IP_DF);
	new_ip_hdr->ip_p = ip_protocol_udp;
	new_ip_hdr->ip_tos = 0;
	new_ip_hdr->ip_ttl = 64;
	new_ip_hdr->ip_v = 4;
	sr_udp_hdr_t *udp_hdr = (sr_udp_hdr_t*)((uint8_t*)new_ip_hdr + sizeof(sr_ip_hdr_t));
	udp_hdr->port_src = htons(520);
	udp_hdr->port_dst = htons(520);
	udp_hdr->udp_len = htons(len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
	sr_rip_pkt_t *rip_pkt = (sr_rip_pkt_t*)((uint8_t*)udp_hdr + sizeof(sr_udp_hdr_t));
	rip_pkt->command = 1;
	rip_pkt->version = 2;
	udp_hdr->udp_sum = 0;
	udp_hdr->udp_sum = cksum(udp_hdr, ntohs(new_ip_hdr->ip_len) - sizeof(sr_ip_hdr_t));
	pthread_mutex_lock(&(sr->rt_lock));
	struct sr_rt* temp = sr->routing_table;
	while (temp) {
		if (temp->metric != 0) {
			continue;
		}
		struct sr_if *interface = sr_get_interface(sr, temp->interface);
		if (sr_obtain_interface_status(sr, interface->name) == 0) {
			interface->status = 0;
			continue;
		}
		new_ip_hdr->ip_dst = temp->dest.s_addr;
		memcpy(ether_hdr->ether_shost, interface->addr, 6);
		new_ip_hdr->ip_src = interface->ip;
		new_ip_hdr->ip_sum = 0;
		new_ip_hdr->ip_sum = cksum(new_ip_hdr, new_ip_hdr->ip_hl*4);
		sr_send_packet(sr, buf, len, interface->name);
		temp = temp->next;
	}
	pthread_mutex_unlock(&(sr->rt_lock));
	free(buf);
}

void send_rip_update(struct sr_instance *sr){
    pthread_mutex_lock(&(sr->rt_lock));
    /* Fill your code here */
    unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t);
	uint8_t *buf = (uint8_t*)malloc(len);
	sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t*)buf;
	memset(ether_hdr->ether_dhost, 0xff, 6);
	memset(ether_hdr->ether_shost, 0, 6);
	ether_hdr->ether_type = htons(ethertype_ip);
	sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t*)(buf + sizeof(sr_ethernet_hdr_t));
	new_ip_hdr->ip_hl = 5;
	new_ip_hdr->ip_len = htons(len - sizeof(sr_ethernet_hdr_t));
	new_ip_hdr->ip_off = htons(IP_DF);
	new_ip_hdr->ip_p = ip_protocol_udp;
	new_ip_hdr->ip_tos = 0;
	new_ip_hdr->ip_ttl = 64;
	new_ip_hdr->ip_v = 4;
	sr_udp_hdr_t *udp_hdr = (sr_udp_hdr_t*)((uint8_t*)new_ip_hdr + sizeof(sr_ip_hdr_t));
	udp_hdr->port_src = htons(520);
	udp_hdr->port_dst = htons(520);
	udp_hdr->udp_len = htons(len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
	sr_rip_pkt_t *rip_pkt = (sr_rip_pkt_t*)((uint8_t*)udp_hdr + sizeof(sr_udp_hdr_t));
	struct sr_rt* temp = sr->routing_table;
	memset(rip_pkt, 0, sizeof(sr_rip_pkt_t));
	while (temp) {
		if (temp->metric != 0) {
			temp = temp->next;
			continue;
		}
		struct sr_if *interface = sr_get_interface(sr, temp->interface);
		if (sr_obtain_interface_status(sr, interface->name) == 0) {
			interface->status = 0;
			temp = temp->next;
			continue;
		}
		rip_pkt->version = 2;
		rip_pkt->command = 2;
		int i = 0;
		struct sr_rt* temp2 = sr->routing_table;
		while (temp2) {
			if(strcmp(interface->name, temp2->interface) == 0) {
				temp2 = temp2->next;
				continue;
			} else {
				rip_pkt->entries[i].afi = 1;
				rip_pkt->entries[i].address = temp2->dest.s_addr;
				rip_pkt->entries[i].mask = temp2->mask.s_addr;
				rip_pkt->entries[i].next_hop = interface->ip;
				rip_pkt->entries[i].metric = temp2->metric;
				i++;
				temp2 = temp2->next;
			}
		}
		new_ip_hdr->ip_dst = temp->dest.s_addr;
		memcpy(ether_hdr->ether_shost, interface->addr, 6);
		new_ip_hdr->ip_src = interface->ip;
		new_ip_hdr->ip_sum = 0;
		new_ip_hdr->ip_sum = cksum(new_ip_hdr, new_ip_hdr->ip_hl*4);
		udp_hdr->udp_sum = 0;
		udp_hdr->udp_sum = cksum(udp_hdr, ntohs(new_ip_hdr->ip_len) - sizeof(sr_ip_hdr_t));
		sr_send_packet(sr, buf, len, interface->name);
		time_t now;
		time(&now);
		temp->updated_time = now;
		temp = temp->next;
		memset(rip_pkt, 0, sizeof(sr_rip_pkt_t));
	}
	free(buf);
    pthread_mutex_unlock(&(sr->rt_lock));
}

void update_route_table(struct sr_instance *sr, sr_ip_hdr_t* ip_packet ,sr_rip_pkt_t* rip_packet, char* iface){
    pthread_mutex_lock(&(sr->rt_lock));
    /* Fill your code here */
    int i = 0;
    int updated = 0;
    while(rip_packet->entries[i].afi) {
    	struct sr_rt* temp = sr->routing_table;
    	while (temp) {
    		if ((temp->dest.s_addr & temp->mask.s_addr) == (rip_packet->entries[i].address & rip_packet->entries[i].mask)) {
    			break;
    		} else {
    			temp = temp->next;
    		}
    	}
    	if (temp && (temp->metric > 1 + rip_packet->entries[i].metric)) {
    		strncpy(temp->interface,iface,sr_IFACE_NAMELEN);
    		struct in_addr gw;
    		gw.s_addr = rip_packet->entries[i].next_hop;
    		temp->gw = gw;
    		temp->metric = 1 + rip_packet->entries[i].metric;
    		time_t now;
            time(&now);
            temp->updated_time = now;
            updated = 1;
    	} else if (!temp) {
    		struct in_addr dest;
    		struct in_addr gw;
    		struct in_addr mask;
    		dest.s_addr = rip_packet->entries[i].address;
    		gw.s_addr = rip_packet->entries[i].next_hop;
    		mask.s_addr = rip_packet->entries[i].mask;
    		sr_add_rt_entry(sr, dest, gw, mask, rip_packet->entries[i].metric + 1, iface);
    		updated = 1;
    	} else {
    		if ((strcmp(temp->interface, iface) == 0) && temp->metric == rip_packet->entries[i].metric + 1) {
    			time_t now;
    			time(&now);
    			temp->updated_time = now;
    		}
    	}
    	i++;
    }
    struct sr_if* if_walker = sr->if_list;
    while (if_walker) {
    	if (sr_obtain_interface_status(sr, if_walker->name) == 1) {
    		if_walker->status = 1;
    	} else {
    		if_walker = if_walker->next;
    		continue;
    	}
    	struct sr_rt* rt_walker = sr->routing_table;
    	while (rt_walker) {
    		if (rt_walker->dest.s_addr == (if_walker->ip & if_walker->mask)) {
    			break;
    		}
    		else {
    			rt_walker = rt_walker->next;
    		}
    	}
    	if (rt_walker == 0) {
    		struct in_addr dest;
			struct in_addr gw;
			struct in_addr mask;
			dest.s_addr = (if_walker->ip & if_walker->mask);
			gw.s_addr = 0;
			mask.s_addr = if_walker->mask;
			sr_add_rt_entry(sr, dest, gw, mask, 0, if_walker->name);
			updated = 1;
    	} else {
    		rt_walker->metric = 0;
			strncpy(rt_walker->interface,if_walker->name,sr_IFACE_NAMELEN);
			rt_walker->gw.s_addr = 0;
			time_t now;
			time(&now);
			rt_walker->updated_time = now;
    	}
    	if_walker = if_walker->next;
    }
    if (updated) {
    	send_rip_update(sr);
    }
    sr_print_routing_table(sr);
    pthread_mutex_unlock(&(sr->rt_lock));
}

struct sr_rt* find_best_rt(struct sr_rt* rt, uint32_t ip) {
	uint32_t most = 0;
	struct sr_rt* best_rt = 0;
	while(rt) {
		uint32_t mask = rt->mask.s_addr;
		if((rt->dest.s_addr & mask) == (ip & mask) && mask >= most) {
			most = mask;
			best_rt = rt;
		}
		rt = rt->next;
	}
	return best_rt;
}
