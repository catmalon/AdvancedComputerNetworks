#include "fill_packet.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

void fill_iphdr (struct ip *ip_hdr, uint32_t src_ip, uint32_t dst_ip)
{
	ip_hdr->ip_v = 4;
	ip_hdr->ip_tos = 0;
	ip_hdr->ip_id = 0;
	ip_hdr->ip_off = htons(IP_DF);
	ip_hdr->ip_ttl = 1;
	ip_hdr->ip_p = IPPROTO_ICMP;
	ip_hdr->ip_src.s_addr = htonl(src_ip);
	ip_hdr->ip_dst.s_addr = htonl(dst_ip);
	ip_hdr->ip_len = sizeof(myicmp);
	ip_hdr->ip_hl = sizeof(struct iphdr) >> 2;	
}

// from ping.c
static u_short in_cksum(const u_short *addr, register int len, u_short csum)
{
	register int nleft = len;
	const u_short *w = addr;
	register u_short answer;
	register int sum = csum;

	/*
	 *  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}


void fill_icmphdr (struct icmphdr *icmp_hdr, pid_t pid, int seq, icmp_all *icmp_all)
{
	icmp_hdr->type = ICMP_ECHO;
	icmp_hdr->code = 0;
	icmp_hdr->un.echo.id = htons(pid);
	icmp_hdr->un.echo.sequence = htons(seq);
	memcpy(icmp_all->data, "M093040067", 10);
	icmp_hdr->checksum = in_cksum((u_short *)icmp_all, sizeof(*icmp_all), 0);
}
