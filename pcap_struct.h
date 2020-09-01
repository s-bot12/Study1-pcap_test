#include <stdint.h>

/* eth */
#define ETH_ALEN 6
#define ETHERTYPE_IP 0x0800
#define IP_TCP 6

struct libnet_ethernet_hdr {
	uint8_t ether_dhost[ETH_ALEN];
	uint8_t ether_shost[ETH_ALEN];
	uint16_t ether_type;
};

/* ipv4 */

struct libnet_ipv4_hdr 
{
    u_int8_t ip_hl:4,      /* header length */
           ip_v:4;         /* version */
    u_int8_t ip_tos;       /* type of service */

    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;

    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};


/* tcp */
struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
    
    u_int8_t th_x2:4,         /* (unused) */
           th_off:4;        /* data offset */
    
    u_int8_t  th_flags;       /* control flags */
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};

