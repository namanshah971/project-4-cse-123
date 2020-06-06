/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
    char user[32]; /* user name */
    char host[32]; /* host name */ 
    char template[30]; /* template name if any */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct sr_arpcache cache;   /* ARP cache */
    pthread_attr_t attr;
    FILE* logfile;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );


/* -- My sr_router functions -- */
void sr_handlepacket_arp_request();
void sr_handlepacket_arp_reply();
void sr_handlepacket_icmp();
void sr_handlepacket_ip();
void sr_handleforwarding_ip();
void sr_send_ICMP_packet(struct sr_instance * sr, uint8_t * old_packet, 
                         unsigned int len, struct sr_if * original_rec_if, 
                         uint8_t icmp_type, uint8_t icmp_code);
void sr_send_ICMP_t0_packet(struct sr_instance * sr, uint8_t * old_packet, 
                            unsigned int old_len, struct sr_if* original_rec_if, 
                            uint8_t icmp_type, uint8_t icmp_code);
void sr_send_ICMP_t3_packet(struct sr_instance * sr, uint8_t * old_packet, 
                            unsigned int old_len, struct sr_if* original_rec_if, 
                            uint8_t icmp_type, uint8_t icmp_code);
void sr_send_ICMP_t11_packet(struct sr_instance * sr, uint8_t * old_packet, 
                             unsigned int old_len, struct sr_if* original_rec_if, 
                             uint8_t icmp_type, uint8_t icmp_code);
void sr_send_arp_req(struct sr_instance * sr,
                     struct sr_if * send_iface, 
                     uint32_t target_ip);
void sr_add_dest_mac_addr(struct sr_instance* sr, 
                          uint8_t * original_packet /* lent */, 
                          unsigned int original_len,
                          uint8_t * send_packet, 
                          unsigned int send_len, 
                          uint32_t dest_ip, struct sr_if * original_rec_if/* lent */);
struct sr_arpreq *sr_arpcache_locate_req(struct sr_arpcache *cache,
                                              uint32_t ip);                                           
void sr_send_arp_req_again(struct sr_instance * sr, uint8_t * send_packet, uint32_t arp_req_target_ip);

#endif /* SR_ROUTER_H */
