#ifndef __FILLPACKET__H_
#define __FILLPACKET__H_

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

typedef char u8;
typedef unsigned short u16;

#define DEFAULT_TIMEOUT 1500
#define ETHERNET_HDR_SIZE 14

typedef struct
{
	struct ip ip_hdr;
	struct icmphdr icmp_hdr;
	u8 data[10];
} myicmp ;

typedef struct
{
	struct icmphdr icmp_hdr;
	u8 data[10];
} icmp_all ;

// struct ip {
// #if BYTE_ORDER == LITTLE_ENDIAN 
//     u_char  ip_hl:4,        /* header length */
//         ip_v:4;         /* version */
// #endif
// #if BYTE_ORDER == BIG_ENDIAN 
//     u_char  ip_v:4,         /* version */
//         ip_hl:4;        /* header length */
// #endif
//     u_char  ip_tos;         /* type of service */
//     short   ip_len;         /* total length */
//     u_short ip_id;          /* identification */
//     short   ip_off;         /* fragment offset field */
// #define IP_DF 0x4000            /* dont fragment flag */
// #define IP_MF 0x2000            /* more fragments flag */
//     u_char  ip_ttl;         /* time to live */
//     u_char  ip_p;           /* protocol */
//     u_short ip_sum;         /* checksum */
//     struct  in_addr ip_src,ip_dst;  /* source and dest address */
// };

void fill_iphdr (struct ip *ip_hdr, uint32_t src_ip, uint32_t dst_ip);
void fill_icmphdr(struct icmphdr *icmp_hdr, pid_t pid, int seq, icmp_all *icmp_all);
 
#endif
 