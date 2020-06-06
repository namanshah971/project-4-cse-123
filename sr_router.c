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
#include <string.h>
#include <stdlib.h>
#include <assert.h>


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
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n",len);
    
    /* fill in code here */

    /* Make copies of lent parameters */
    uint8_t * packet_copy = (uint8_t *) malloc(len);
    memcpy(packet_copy, packet, len);
    char* interface_copy = (char*) malloc(sr_IFACE_NAMELEN);
    strncpy(interface_copy, interface, sr_IFACE_NAMELEN);
    
    /* Sanity check */
    if ( len < sizeof(sr_ethernet_hdr_t) ){
        fprintf(stderr , "** Error: packet is way too short! \n");
        return;
    }

    /* Determine whether packet dest is one of the router's interfaces */
    /* TODO */

    /* Get receiving interface object from name */
    struct sr_if * rec_if = sr_get_interface(sr, interface_copy);

    if (!rec_if) {
        fprintf(stderr, "ERROR: could not get interface object from where packet was received");
        return;
    }

    /* If destined to one of router's interfaces */


    /* If not destined one of router's interfaces */

    uint16_t ether_type = ethertype(packet_copy);

    switch (ether_type)
    {
        case ethertype_arp:
        {
            /* Skip ethernet header to reach arp header */
            sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet_copy + sizeof(sr_ethernet_hdr_t));
            uint16_t opcode = ntohs(arp_hdr->ar_op);

            switch (opcode)
            {
                case arp_op_request:
                    sr_handlepacket_arp_request(sr, packet_copy, len, interface_copy);
                    break;
                case arp_op_reply:
                    sr_handlepacket_arp_reply(sr, packet_copy, len, interface_copy);
                    break;
                
                default:
                    break;
            }

            break;
        }
        
        case ethertype_ip:
            sr_handlepacket_ip(sr, packet_copy, len, interface_copy);
            break;
        
        default:
            fprintf(stderr, "Packet of unknown type!\n");
            break;
    }


}/* end sr_ForwardPacket */


/* Handle incoming arp requests by sending reply if request intended for this router's receiving interface */
void sr_handlepacket_arp_request(struct sr_instance* sr, 
                                 uint8_t * packet/* lent */,
                                 unsigned int len, char* interface/* lent */)
{
    fprintf(stderr, "Handling arp request\n");

    sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)packet;

    fprintf(stderr, "Eth header is: \n");
    print_hdr_eth(ehdr);

    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    /* Get receiving interface object from name */
    struct sr_if * rec_if = sr_get_interface(sr, interface);

    if (!rec_if) {
        fprintf(stderr, "ERROR: could not get interface object from where packet was received\n");
        return;
    }

    /* If the target ip is the receiving interface */
    if (arp_hdr->ar_tip == rec_if->ip) {
        /* Prepare response */
        uint32_t total_length = sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t);
        uint8_t * res_packet = malloc(total_length);

        sr_ethernet_hdr_t * res_ehdr = (sr_ethernet_hdr_t *) res_packet;
        sr_arp_hdr_t * res_arp_hdr = (sr_arp_hdr_t *) (res_packet + sizeof(sr_ethernet_hdr_t));

        /* Source MAC address of response packet is of interface in which request was received */
        memcpy(res_ehdr->ether_shost, rec_if->addr, ETHER_ADDR_LEN);
        /* Dest MAC address of response packet is the source MAC address of request packet */
        memcpy(res_ehdr->ether_dhost, ehdr->ether_shost, ETHER_ADDR_LEN);
        /* Same ether type for res packet as req packet */
        res_ehdr->ether_type = ehdr->ether_type;

        /* Copy over struct members from req arp header to res arp header, and change fields appropriately */
        *res_arp_hdr = *arp_hdr;
        /* Change reply type */
        res_arp_hdr->ar_op = htons(arp_op_reply);
        /* Change source and target ip */
        res_arp_hdr->ar_sip = rec_if->ip;
        res_arp_hdr->ar_tip = arp_hdr->ar_sip;
        
        /* Change source and destination hardware addresses in arp header*/
        memcpy(res_arp_hdr->ar_sha, rec_if->addr, ETHER_ADDR_LEN);
        memcpy(res_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);

        fprintf(stderr, "About to send response packet for arp request\n");

        sr_send_packet(sr, res_packet, total_length, interface);

    } else {
        fprintf(stderr, "Target ip address not for this interface\n");
    }
    
}


void sr_handlepacket_arp_reply(struct sr_instance* sr, 
                               uint8_t * packet/* lent */,
                               unsigned int len, char* interface/* lent */)
{
    fprintf(stderr, "Handling arp reply\n");

    sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)packet;

    fprintf(stderr, "Eth header is: \n");
    print_hdr_eth(ehdr);

    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    /* Get receiving interface object from name */
    struct sr_if * rec_if = sr_get_interface(sr, interface);

    if (!rec_if) {
        fprintf(stderr, "ERROR: could not get interface object from where packet was received\n");
        return;
    }

    /* Only process replies intended for this router (tip is same as receiving interfaces' ip) */
    if (arp_hdr->ar_tip == rec_if->ip) {
       
        fprintf(stderr, "ARP Reply intended for router, processing\n");


        /* Process queue for corresponding request to send packets */

        pthread_mutex_lock(&(sr->cache.lock));
        struct sr_arpreq * request = sr_arpcache_locate_req(&sr->cache, arp_hdr->ar_sip);
        
        /* Send all packets that was waiting for this request response */
        if (request) {
            /* Acquire lock when accessing stuff inside cache */

            struct sr_packet * curr_sr_packet = request->packets;
            while (curr_sr_packet) {

                uint8_t * packet_to_send = (uint8_t *) malloc(curr_sr_packet->len);

                /* Copy packet data */
                memcpy(packet_to_send, curr_sr_packet->buf, curr_sr_packet->len);

                sr_ethernet_hdr_t *send_ehdr = (sr_ethernet_hdr_t *)packet_to_send;

                sr_ip_hdr_t *send_iphdr = (sr_ip_hdr_t *)(packet_to_send + sizeof(sr_ethernet_hdr_t));

                fprintf(stderr, "Resolved arp request for packet below (before sending):\n");
                print_hdr_eth(send_ehdr);
                print_hdr_ip(send_iphdr);

                /* Interface object from which to send should be interface that received arp reply */
                /* Fill in eth header with sending interface info and ARP reply SHA info */
                memcpy(send_ehdr->ether_shost, rec_if->addr, ETHER_ADDR_LEN);
                memcpy(send_ehdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);

                /* Recompute IPv4 checksum */
                send_iphdr->ip_sum = 0;
                send_iphdr->ip_sum = cksum(send_iphdr, sizeof(sr_ip_hdr_t));

                fprintf(stderr, "Changed ethernet fields before sending, now is\n");
                print_hdr_eth(send_ehdr);

                /* Send packet */
                fprintf(stderr, "Sending packet!\n");
                sr_send_packet(sr, packet_to_send, curr_sr_packet->len, rec_if->name);
                
                free(packet_to_send);

                curr_sr_packet = curr_sr_packet->next;
            }
            
            /* Destroy request from queue when done */
            sr_arpreq_destroy(&sr->cache, request);

            /* Note different mutex from the lock acquired by sr_arpreq_destroy() */
            pthread_mutex_unlock(&(sr->cache.lock));

        } else {
            fprintf(stderr, "Received ARP reply for this router, but does not still have request\n");
            return;
        }

    }
}


void sr_handlepacket_ip(struct sr_instance* sr, uint8_t * packet/* lent */,
                        unsigned int len, char* interface/* lent */)
{
    fprintf(stderr, "Handling ip packet\n");

    sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)packet;

    fprintf(stderr, "Eth header is: \n");
    print_hdr_eth(ehdr);
    
    /* Sanity check */
    if ( len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) ){
        fprintf(stderr , "** Error: packet is way too short to contain ip header! \n");
        return;
    }

    sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    fprintf(stderr, "IP header is: \n");
    print_hdr_ip(iphdr);

    /* Check sum check */
    uint16_t check_sum = cksum(iphdr, sizeof(sr_ip_hdr_t));
    fprintf(stderr, "IP Header Check sum result is %X\n", check_sum);

    if (check_sum != 0xffff) {
        fprintf(stderr, "IP Check sum result error!\n");
        return;
    }
    
    /* Check if ip destination one of this router's interfaces' ip */
    struct sr_if * curr_iface = sr->if_list;

    /* Go through list to look for a match; if none reach end of list (null) */
    while (curr_iface) {
        if (curr_iface->ip == iphdr->ip_dst) {
            break;
        } 

        curr_iface = curr_iface->next;
    }

    /* If destination is this router */
    if (curr_iface) {
        uint8_t ip_pro = ip_protocol(iphdr);
        fprintf(stderr, "IP protocol is %u\n", ip_pro);
        /* Block to handle ICMP packets (still under ip header) destined to router */
        if (ip_pro == ip_protocol_icmp) {
            /* Sanity check */
            if ( len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t) ){
                fprintf(stderr , "** Error: packet is way too short to contain icmp header! \n");
                return;
            }
            
            sr_handlepacket_icmp(sr, packet, len, curr_iface, interface);

        } else {
            /* Just regular IP */
        }

    } else {
        /* Handle Forwarding of IP Packet (which may contain icmp) */
        sr_handleforwarding_ip(sr, packet, len, interface);
    }

}

void sr_handleforwarding_ip(struct sr_instance* sr, 
                            uint8_t * packet/* lent */,
                            unsigned int len, char* interface/* lent */)
{
    fprintf(stderr, "Handling ip forwarding\n");

    sr_ethernet_hdr_t * old_ehdr = (sr_ethernet_hdr_t *) packet;
    sr_ip_hdr_t * old_iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    
    /* If needs to be forwarded, make copy, decrease TTL and recompute checksum before forwarding */
    uint8_t * fw_packet = (uint8_t *) malloc(len);

    /* Copy over packet data and then only change appropriate headers fields */
    memcpy(fw_packet, packet, len);

    sr_ethernet_hdr_t * fw_ehdr = (sr_ethernet_hdr_t *) fw_packet;
    sr_ip_hdr_t * fw_iphdr = (sr_ip_hdr_t *)(fw_packet + sizeof(sr_ethernet_hdr_t));

    /* NOTE: my implementation don't change ehdr of the new packet as for arp req dest host unreachable,
       will be passing in new packet and sr_send_icmp_t3 will use (reverse) src and mac addr of this packet  */
    
    /* Ignore wrong packets with somehow ttl 0 */
    if (fw_iphdr->ip_ttl == 0) {
        return;
    }

    struct sr_if * rec_if = sr_get_interface(sr, interface);

    /* Decrement time to live */
    fw_iphdr->ip_ttl = fw_iphdr->ip_ttl - 1;

    /* If TTL is now 0, send back ICMP TTL expired */
    if (fw_iphdr->ip_ttl == 0) {
        
        fprintf(stderr, "TTL is 0, sending ICMP\n\n");

        /* Type 11 is time exceeded, combinded with Code 0 indicates TTL = 0 */
        sr_send_ICMP_packet(sr, packet, len, rec_if, 11, 0);

    } else {
        /* Can forward packet */
        /* Looks in routing table for dest mac address to attempt to send to */
        sr_add_dest_mac_addr(sr, packet, len, fw_packet, len, fw_iphdr->ip_dst, rec_if);
    }

}

/* Handles ICMP packets destined for this router, which can only be ping requests */
void sr_handlepacket_icmp(struct sr_instance* sr, uint8_t * packet/* lent */,
                          unsigned int len, struct sr_if * original_dst_iface, char* interface/* lent */)
{
    sr_ethernet_hdr_t *old_ehdr = (sr_ethernet_hdr_t *)packet;
    
    /* Sanity check */
    if ( len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) ){
        fprintf(stderr , "** Error: packet is way too short to contain ip header! \n");
        return;
    }

    sr_ip_hdr_t *old_iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    /* Sanity check */
    if ( len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t) ){
        fprintf(stderr , "** Error: packet is way too short to contain icmp header! \n");
        return;
    }

    sr_icmp_hdr_t * old_icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    /* Look for echo request (no need to worry about byte ordering as these fields are 1 byte) */
    if (!(old_icmp_hdr->icmp_type == 8 && old_icmp_hdr->icmp_code == 0)) {
        fprintf(stderr, "Error: Not a ping ICMP packet yet destined to this router\n");
        return;
    }
    
    /* Due to print implementation, ICMP header part must be at least sizeof(sr_icmp_t11_hdr_t) */
    if (len >= sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t)) {
        print_hdr_icmp(old_icmp_hdr);
    } else {
        fprintf(stderr, "ICMP packet too short to call print_hdr_icmp()\n");
    }
    
    /* Check sum sanity test */
   
    /* As ICMP data field for echo request is variable length, 
       subtract eth and ip header lengths from total length to determine ICMP total length */
    uint16_t check_sum = cksum(old_icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
    fprintf(stderr, "ICMP Header Check sum result is %u (hex %X)\n", check_sum, check_sum);

    if (check_sum != 0xffff) {
        fprintf(stderr, "ICMP Check sum result error!\n");
        return;
    }

    struct sr_if * original_rec_if = sr_get_interface(sr, interface);
    sr_send_ICMP_packet(sr, packet, len, original_rec_if, 0, 0);
}

/* Determine DMA based on next hop IP and send ARP request if needed then attempt send, else reply unreachable */
void sr_add_dest_mac_addr(struct sr_instance* sr, 
                          uint8_t * original_packet /* lent */, 
                          unsigned int original_len,
                          uint8_t * send_packet, 
                          unsigned int send_len, 
                          uint32_t dest_ip, struct sr_if * original_rec_if/* lent */)
{

    sr_ethernet_hdr_t *old_ehdr = (sr_ethernet_hdr_t *) original_packet;
    
    /* Sanity check */
    if ( original_len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) ){
        fprintf(stderr , "** Error: packet is way too short to contain ip header! \n");
        return;
    }

    sr_ip_hdr_t *old_iphdr = (sr_ip_hdr_t *)(original_packet + sizeof(sr_ethernet_hdr_t));
    
    sr_ethernet_hdr_t *send_ehdr = (sr_ethernet_hdr_t *) send_packet;
    
    /* Sanity check */
    if ( send_len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) ){
        fprintf(stderr , "** Error: packet is way too short to contain ip header! \n");
        return;
    }

    sr_ip_hdr_t *send_iphdr = (sr_ip_hdr_t *)(send_packet + sizeof(sr_ethernet_hdr_t));

    /* Lookup routing table for next hop entry */
    struct sr_rt * rtable_node = sr->routing_table;

    /* Try to find exact matching entry for next hop ip */
    while(rtable_node) {
        /* If destination ip in entry matches, break */
        if (rtable_node->dest.s_addr == dest_ip) {
            break;            
        }

        rtable_node = rtable_node->next;
    }

    /* If matching entry found in routing table */
    if (rtable_node) {
        /* Get interface object from which to send */
        struct sr_if * arp_req_send_iface = sr_get_interface(sr, rtable_node->interface);

        uint32_t arp_req_target_ip = rtable_node->gw.s_addr;

        fprintf(stderr, "Storing packet before doing arp request\n");

        fprintf(stderr, "Packet to be stored is:\n");
        
        print_hdr_eth(send_ehdr);
        print_hdr_ip(send_iphdr);

        /* TODO*/
        /* These two functions should always be together */
        /* Store request in queue, note 2nd parameter is ARP request IP (not intended 
           IP dest of packet that is being stored)*/
        struct sr_arpreq* request = sr_arpcache_queuereq(&sr->cache, arp_req_target_ip,
                                                         send_packet, send_len, original_rec_if->name);

        sr_send_arp_req(sr, arp_req_send_iface, arp_req_target_ip);

        /* Update time sent of ARP request to current time */
        pthread_mutex_lock(&(sr->cache.lock));
        request->sent = time(NULL);
        request->times_sent = 1;
        pthread_mutex_unlock(&(sr->cache.lock));

   
    } else {
        fprintf(stderr, "Destination unreachable!\n");

        /* Send ICMP destination unreachable */ 
        /* TODO what if infinite recursion between sr_send_ICMP and sr_add_dest_mac_addr when no entry in table */
        /* Send ICMP packet back through original interface received */
        sr_send_ICMP_packet(sr, original_packet, original_len, original_rec_if, 3, 0);
        
    }

}


void sr_send_arp_req(struct sr_instance * sr,
                     struct sr_if * arp_send_iface, 
                     uint32_t target_ip)
{
    /* Send ARP request */
    unsigned int arp_total_length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t * arp_req_packet = (uint8_t *) malloc(arp_total_length);
    sr_ethernet_hdr_t * arp_req_ehdr = (sr_ethernet_hdr_t *) arp_req_packet;
    sr_arp_hdr_t * arp_req_arp_hdr = (sr_arp_hdr_t *) (arp_req_packet + sizeof(sr_ethernet_hdr_t));

    /* Set source MAC address to that of sending interface */
    memcpy(arp_req_ehdr->ether_shost, arp_send_iface->addr, ETHER_ADDR_LEN);
    /* Set Dest MAC address to broadcast address (all 1s) */
    memset(arp_req_ehdr->ether_dhost, 0xFF, ETHER_ADDR_LEN);
    arp_req_ehdr->ether_type = htons(ethertype_arp);

    /* Format of hardware address is ethernet (1) */
    arp_req_arp_hdr->ar_hrd = htons(arp_hrd_ethernet);             
    /* Format of protocol address is IP (0x800) */
    arp_req_arp_hdr->ar_pro = htons(ethertype_ip);
    /* Length of hardware address ethernet */             
    arp_req_arp_hdr->ar_hln = ETHER_ADDR_LEN;             
    /* Length of protocol address IP is 4 bytes */
    arp_req_arp_hdr->ar_pln = 4;             
    /* ARP opcode set to request */
    arp_req_arp_hdr->ar_op = htons(arp_op_request);            
    /* Sender hardware address is our sending interface's MAC addr */
    memcpy(arp_req_arp_hdr->ar_sha, arp_send_iface->addr, ETHER_ADDR_LEN);   
    /* Sender ip address is our sending interface's ip */
    arp_req_arp_hdr->ar_sip = arp_send_iface->ip;             
    /* Although Target hardware address will be ignored in a arprequest, still setting to broadcast addr */
    memset(arp_req_arp_hdr->ar_tha, 0xFF, ETHER_ADDR_LEN);
    /* Target IP address is the next hop ip */  
    arp_req_arp_hdr->ar_tip = target_ip;               
    
    fprintf(stderr, "Sending ARP request for target ip:");
    print_addr_ip_int(ntohl(arp_req_arp_hdr->ar_tip));
    sr_send_packet(sr, arp_req_packet, arp_total_length, arp_send_iface->name);

}

/* Determines send interface based on next hop for packet ip_dst then delegate to sr_send_arp_req */
void sr_send_arp_req_again(struct sr_instance * sr, uint8_t * send_packet, uint32_t arp_req_target_ip)
{
    sr_ethernet_hdr_t *send_ehdr = (sr_ethernet_hdr_t *) send_packet;
    sr_ip_hdr_t *send_iphdr = (sr_ip_hdr_t *)(send_packet + sizeof(sr_ethernet_hdr_t));

    /* Lookup routing table for next hop entry */
    struct sr_rt * rtable_node = sr->routing_table;

    /* Try to find exact matching entry for next hop ip */
    while(rtable_node) {
        /* If destination ip in entry matches, break */
        if (rtable_node->dest.s_addr == send_iphdr->ip_dst) {
            break;            
        }

        rtable_node = rtable_node->next;
    }

    /* If matching entry found in routing table */
    if (rtable_node) {
        /* Get interface object from which to send */
        struct sr_if * arp_req_send_iface = sr_get_interface(sr, rtable_node->interface);

        if (arp_req_target_ip != rtable_node->gw.s_addr) {
            fprintf(stderr, "Error, target ip changed for repeat arp request\n");
        }
   
        sr_send_arp_req(sr, arp_req_send_iface, arp_req_target_ip);
   
    } else {
        fprintf(stderr, "ERROR: Somehow destination unreachable for repeat arp request!\n");
    }

}             

/* Send packet based on type and code */
void sr_send_ICMP_packet(struct sr_instance * sr, uint8_t * old_packet, 
                         unsigned int old_len, struct sr_if* original_rec_if, 
                         uint8_t icmp_type, uint8_t icmp_code)
{
    sr_ethernet_hdr_t *old_ehdr = (sr_ethernet_hdr_t *) old_packet;
    
    /* Sanity check */
    if ( old_len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) ){
        fprintf(stderr , "** Error: packet is way too short to contain ip header! \n");
        return;
    }

    sr_ip_hdr_t *old_iphdr = (sr_ip_hdr_t *)(old_packet + sizeof(sr_ethernet_hdr_t));
    
    /* Decide what subroutine to call based on ICMP type */
    switch (icmp_type)
    {
        case 0: /* i.e. Echo reply */
            sr_send_ICMP_t0_packet(sr, old_packet, old_len, original_rec_if, icmp_type, icmp_code);
            break;
        
        case 3: /* i.e. Destination unreachable */
            sr_send_ICMP_t3_packet(sr, old_packet, old_len, original_rec_if, icmp_type, icmp_code);
            break;
        
        case 11: /* i.e. Time exceeded */
            sr_send_ICMP_t11_packet(sr, old_packet, old_len, original_rec_if, icmp_type, icmp_code);
            break;
        
        default:
            break;
    }

}

/* Send an echo reply ICMP type 0 packet */
void sr_send_ICMP_t0_packet(struct sr_instance * sr, uint8_t * old_packet, 
                            unsigned int old_len, struct sr_if* original_rec_if, 
                            uint8_t icmp_type, uint8_t icmp_code)
{
    sr_ethernet_hdr_t *old_ehdr = (sr_ethernet_hdr_t *) old_packet;
    
    /* Sanity check */
    if ( old_len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) ){
        fprintf(stderr , "** Error: packet is way too short to contain ip header! \n");
        return;
    }

    sr_ip_hdr_t *old_iphdr = (sr_ip_hdr_t *)(old_packet + sizeof(sr_ethernet_hdr_t));
    
    /* Length is same as request for echo reply */
    unsigned int new_packet_length = old_len;

    uint8_t * new_icmp_packet = (uint8_t *) calloc(1, new_packet_length);
    sr_ethernet_hdr_t *new_ehdr = (sr_ethernet_hdr_t *) new_icmp_packet;
    sr_ip_hdr_t *new_iphdr = (sr_ip_hdr_t *)(new_icmp_packet + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t0_hdr_t * new_icmp_hdr = (sr_icmp_t0_hdr_t*)(new_icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    /* Copy over old packet then change appropriate fields */
    memcpy(new_icmp_packet, old_packet, old_len);

    /* Update ip header fields */
    /* Ip source of echo reply packet may not match the ip from which we are sending reply (as we are sending
       echo reply if echo request ip dst matches any of the router's interface id. Therefore, the original
       receiving interface may not be same as the destination interface). Therefore this line is different
       from other ICMP sending methods which uses the original receiving interface ip (as there is no concept
       of original destination ip of router unless it is echo request) */
    new_iphdr->ip_src = old_iphdr->ip_dst; /* Should be same as destination ip from echo request packet */
    new_iphdr->ip_dst = old_iphdr->ip_src;
    /* Total IP length excludes ethernet header (result should be same as ip_len of request packet) */
    new_iphdr->ip_len = htons(new_packet_length - sizeof(sr_ethernet_hdr_t)); 
    new_iphdr->ip_ttl = INIT_TTL;   

    /* Recompute IPv4 checksum (may be recalculated again later) */
    new_iphdr->ip_sum = 0;
    new_iphdr->ip_sum = cksum(new_iphdr, sizeof(sr_ip_hdr_t));

    /* Change (set to 0) some ICMP header fields to indicate ICMP echo reply */
    new_icmp_hdr->icmp_type = icmp_type;
    new_icmp_hdr->icmp_code = icmp_code;
    
    /* Recompute ICMP header checksum */
    /* Note as icmp data field is variable length, entire ICMP message length is not sizeof(sr_icmp_t0_hdr_t) */
    /* Reply packet data must match echo request data */
    new_icmp_hdr->icmp_sum = 0;
    new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, new_packet_length - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

    /* Lookup routing table for next hop entry */
    struct sr_rt * rtable_node = sr->routing_table;

    /* Try to find exact matching entry for next hop ip */
    while(rtable_node) {
        /* If destination ip in entry matches, break */
        if (rtable_node->dest.s_addr == new_iphdr->ip_dst) {
            break;            
        }

        rtable_node = rtable_node->next;
    }

    /* If matching entry found in routing table */
    if (rtable_node) {
        /* Get interface mac addr from which to send */
        struct sr_if * send_iface = sr_get_interface(sr, rtable_node->interface);

        /* 
        int i;
        fprintf(stderr, "Sending iface for echo reply should have mac addr: ");
        for (i = 0; i < ETHER_ADDR_LEN; i++){
            fprintf(stderr, "%x:", send_iface->addr[i]);
        }
        fprintf(stderr, "\n");
        fprintf(stderr, "Sending iface for echo reply should have ip: ");
        print_addr_ip_int(ntohl(send_iface->ip));

        fprintf(stderr, "Original receiving iface for echo request has ip: ");
        print_addr_ip_int(ntohl(original_rec_if->ip));

        if (send_iface->ip != original_rec_if->ip) {
            fprintf(stderr, "Sending iface's ip for echo reply is different from receiving ip of echo request\n");
        }

        fprintf(stderr, "Dest mac address should be: ");
        for (i = 0; i < ETHER_ADDR_LEN; i++){
            fprintf(stderr, "%x:", old_ehdr->ether_shost[i]);
        }
        fprintf(stderr, "\n");

        fprintf(stderr, "Original receiving iface mac addr is: ");
        for (i = 0; i < ETHER_ADDR_LEN; i++){
            
            fprintf(stderr, "%x:", original_rec_if->addr[i]);
        }
        fprintf(stderr, "\n");
        */

        memcpy(new_ehdr->ether_shost, send_iface->addr, ETHER_ADDR_LEN);
   
        memcpy(new_ehdr->ether_dhost, old_ehdr->ether_shost, ETHER_ADDR_LEN);

        sr_send_packet(sr, new_icmp_packet, new_packet_length, send_iface->name);
        
    
    } else {
        fprintf(stderr, "Error: unable to find entry in routing table to send destination unreachable msg\n");
    }
    
    /*
    fprintf(stderr, "Calling sr_add_dest_mac_addr from sr_send_ICMP_t0_packet()\n");

    sr_add_dest_mac_addr(sr, old_packet, old_len, new_icmp_packet, new_packet_length, new_iphdr->ip_dst, original_rec_if);
    */
}

/* Send a destination unreachable ICMP type 3 packet */
void sr_send_ICMP_t3_packet(struct sr_instance * sr, uint8_t * old_packet, 
                            unsigned int old_len, struct sr_if* original_rec_if, 
                            uint8_t icmp_type, uint8_t icmp_code)
{
    sr_ethernet_hdr_t *old_ehdr = (sr_ethernet_hdr_t *) old_packet;
    
    /* Sanity check */
    if ( old_len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) ){
        fprintf(stderr , "** Error: packet is way too short to contain ip header! \n");
        return;
    }

    sr_ip_hdr_t *old_iphdr = (sr_ip_hdr_t *)(old_packet + sizeof(sr_ethernet_hdr_t));
    
    /* Length of Data field is orignal packet ip header + first 64 bits (8 bytes) of original data */
    unsigned int new_icmp_data_field_len = sizeof(sr_ip_hdr_t) + 8; /* Assuming typical ip header for orignal packet*/
    /* Note one component of sum below is length of generic icmp header before not including data field */
    unsigned int new_packet_length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + 
                                     sizeof(sr_icmp_hdr_t) + new_icmp_data_field_len;

    uint8_t * new_icmp_packet = (uint8_t *) calloc(1, new_packet_length);
    sr_ethernet_hdr_t *new_ehdr = (sr_ethernet_hdr_t *) new_icmp_packet;
    sr_ip_hdr_t *new_iphdr = (sr_ip_hdr_t *)(new_icmp_packet + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t3_hdr_t * new_icmp_hdr = (sr_icmp_t3_hdr_t*)(new_icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    /* Copy fields of original packet up to end of ip header then change appropriate fields */
    memcpy(new_icmp_packet, old_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    /* Copy the header of original packet IP header + first 64 bits (8 bytes) of original data to
       data field of new icmp packet */
    unsigned int num_bytes_to_copy = new_icmp_data_field_len;
    if (old_len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t) < 8) {
        fprintf(stderr, "Original packet data is of length less than 8 bytes\n");
        num_bytes_to_copy = old_len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);
    }
    memcpy(&new_icmp_hdr->data, old_packet + sizeof(sr_ethernet_hdr_t), num_bytes_to_copy);

    /* Update ip header fields */
    /* Ip source of destination unreachable message is the ip of the router's receiving iface */
    new_iphdr->ip_src = original_rec_if->ip;
    new_iphdr->ip_dst = old_iphdr->ip_src;
    /* Length is the entire new ip icmp packet excluding ethernet header */
    new_iphdr->ip_len = htons(new_packet_length - sizeof(sr_ethernet_hdr_t)); 
    new_iphdr->ip_ttl = INIT_TTL;   

    /* Recompute IPv4 checksum (may be recalculated again later) */
    new_iphdr->ip_sum = 0;
    new_iphdr->ip_sum = cksum(new_iphdr, sizeof(sr_ip_hdr_t));

    /* Set correct ICMP header */
    new_icmp_hdr->icmp_type = icmp_type;
    new_icmp_hdr->icmp_code = icmp_code;
    new_icmp_hdr->unused = 0; /* 0 so no need to worry about byte ordering */
    
    /* Recompute ICMP header checksum */
    /* Entire ICMP message length may not be sizeof(sr_icmp_t3_hdr_t) */
    new_icmp_hdr->icmp_sum = 0;
    new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, new_packet_length - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
    

    /* Lookup routing table for next hop entry */
    struct sr_rt * rtable_node = sr->routing_table;

    /* Try to find exact matching entry for next hop ip */
    while(rtable_node) {
        /* If destination ip in entry matches, break */
        if (rtable_node->dest.s_addr == new_iphdr->ip_dst) {
            break;            
        }

        rtable_node = rtable_node->next;
    }

    /* If matching entry found in routing table */
    if (rtable_node) {
        /* Get interface mac addr from which to send */
        struct sr_if * send_iface = sr_get_interface(sr, rtable_node->interface);

        if (send_iface != original_rec_if) {
            fprintf(stderr, "Just warning: sending interface for ICMP message not the same as original rec iface\n");
        }

        memcpy(new_ehdr->ether_shost, send_iface->addr, ETHER_ADDR_LEN);
   
        memcpy(new_ehdr->ether_dhost, old_ehdr->ether_shost, ETHER_ADDR_LEN);

        sr_send_packet(sr, new_icmp_packet, new_packet_length, send_iface->name);
    
    } else {
        fprintf(stderr, "Error: unable to find entry in routing table to send destination unreachable msg\n");
    }
  
    /*
    fprintf(stderr, "Calling sr_add_dest_mac_addr\n");

    sr_add_dest_mac_addr(sr, old_packet, old_len, new_icmp_packet, new_packet_length, new_iphdr->ip_dst, original_rec_if);
    */
}

/* Send a time exceeded ICMP type 11 packet */
void sr_send_ICMP_t11_packet(struct sr_instance * sr, uint8_t * old_packet, 
                             unsigned int old_len, struct sr_if* original_rec_if, 
                             uint8_t icmp_type, uint8_t icmp_code)
{
    fprintf(stderr, "In sending tcmp11 function\n");
    
    sr_ethernet_hdr_t *old_ehdr = (sr_ethernet_hdr_t *) old_packet;
    
    /* Sanity check */
    if ( old_len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) ){
        fprintf(stderr , "** Error: packet is way too short to contain ip header! \n");
        return;
    }

    sr_ip_hdr_t *old_iphdr = (sr_ip_hdr_t *)(old_packet + sizeof(sr_ethernet_hdr_t));
    
    
    /* Length of Data field is orignal packet ip header + first 64 bits (8 bytes) of original data */
    unsigned int new_icmp_data_field_len = sizeof(sr_ip_hdr_t) + 8; /* Assuming typical ip header for orignal packet*/
    /* Note one component of sum below is length of generic icmp header before not including data field */
    unsigned int new_packet_length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + 
                                     sizeof(sr_icmp_hdr_t) + new_icmp_data_field_len;

    uint8_t * new_icmp_packet = (uint8_t *) calloc(1, new_packet_length);
    sr_ethernet_hdr_t *new_ehdr = (sr_ethernet_hdr_t *) new_icmp_packet;
    sr_ip_hdr_t *new_iphdr = (sr_ip_hdr_t *)(new_icmp_packet + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t11_hdr_t * new_icmp_hdr = (sr_icmp_t11_hdr_t*)(new_icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    /* Copy fields of original packet up to end of ip header then change appropriate fields */
    memcpy(new_icmp_packet, old_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    /* Copy the header of original packet IP header + first 64 bits (8 bytes) of original data to
       data field of new icmp packet */
    unsigned int num_bytes_to_copy = new_icmp_data_field_len;
    if (old_len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t) < 8) {
        fprintf(stderr, "Original packet data is of length less than 8 bytes\n");
        num_bytes_to_copy = old_len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);
    }
    memcpy(&new_icmp_hdr->data, old_packet + sizeof(sr_ethernet_hdr_t), num_bytes_to_copy);

    /* Update ip header fields */
    /* Ip source of destination unreachable message is the ip of the router's receiving iface */
    new_iphdr->ip_src = original_rec_if->ip;
    new_iphdr->ip_dst = old_iphdr->ip_src;
    /* Length is the entire new ip icmp packet excluding ethernet header */
    new_iphdr->ip_len = htons(new_packet_length - sizeof(sr_ethernet_hdr_t)); 
    new_iphdr->ip_ttl = INIT_TTL;   

    /* Recompute IPv4 checksum (may be recalculated again later) */
    new_iphdr->ip_sum = 0;
    new_iphdr->ip_sum = cksum(new_iphdr, sizeof(sr_ip_hdr_t));

    /* Set correct ICMP header */
    new_icmp_hdr->icmp_type = icmp_type;
    new_icmp_hdr->icmp_code = icmp_code;
    new_icmp_hdr->unused = 0; /* 0 so no need to worry about byte ordering */
    
    /* Recompute ICMP header checksum */
    /* Entire ICMP message length may not be sizeof(sr_icmp_t11_hdr_t) */
    new_icmp_hdr->icmp_sum = 0;
    new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, new_packet_length - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
    
    /* Lookup routing table for next hop entry */
    struct sr_rt * rtable_node = sr->routing_table;

    /* Try to find exact matching entry for next hop ip */
    while(rtable_node) {
        /* If destination ip in entry matches, break */
        if (rtable_node->dest.s_addr == new_iphdr->ip_dst) {
            break;            
        }

        rtable_node = rtable_node->next;
    }

    /* If matching entry found in routing table */
    if (rtable_node) {
        /* Get interface mac addr from which to send */
        struct sr_if * send_iface = sr_get_interface(sr, rtable_node->interface);

        if (send_iface != original_rec_if) {
            fprintf(stderr, "Just warning: sending interface for ICMP message not the same as original rec iface\n");
        }
        
        memcpy(new_ehdr->ether_shost, send_iface->addr, ETHER_ADDR_LEN);
   
        memcpy(new_ehdr->ether_dhost, old_ehdr->ether_shost, ETHER_ADDR_LEN);

        sr_send_packet(sr, new_icmp_packet, new_packet_length, send_iface->name);
    
    } else {
        fprintf(stderr, "Error: unable to find entry in routing table to send destination unreachable msg\n");
    }

    /* 

    fprintf(stderr, "Calling sr_add_dest_mac_addr\n");

    sr_add_dest_mac_addr(sr, old_packet, old_len, new_icmp_packet, new_packet_length, new_iphdr->ip_dst, original_rec_if);
    */
}

/* IMPORTANT: NEED TO ACQUIRE LOCK AND RELEASE BEFORE AND AFTER CALLING
   Returns, if exists in req queue, the sr_arpreq struct for this ARP request for ip */
struct sr_arpreq *sr_arpcache_locate_req(struct sr_arpcache *cache, uint32_t ip)
{
    struct sr_arpreq *req = NULL, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    return req;
}