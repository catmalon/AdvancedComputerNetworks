#include "pcap.h"
#include "fill_packet.h"
#include <sys/types.h>
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

static pcap_t *p;

/*
 * This function is almost completed.
 * But you still need to edit the filter string.
 */
void pcap_init(const char* interface, const char* dst_ip, int timeout)
{	
	int ret;
	char* net;
	char* mask;
	char errbuf[PCAP_ERRBUF_SIZE];
	char filter_string[FILTER_STRING_SIZE];
	bpf_u_int32 netp;
	bpf_u_int32 maskp;
	struct in_addr addr;
	struct bpf_program fcode;

	ret = pcap_lookupnet(interface, &netp, &maskp, errbuf);
	if (ret == -1) {
		fprintf(stderr, "%s\n", errbuf);
		exit(1);
	}
	
	addr.s_addr = netp;
	net = inet_ntoa(addr);
	if (net == NULL){
		perror("inet_ntoa error");
		exit(1);
	}

	addr.s_addr = maskp;
	mask = inet_ntoa(addr);
	if (mask == NULL){
		perror("inet_ntoa error");
		exit(1);
	}
	
	p = pcap_open_live(interface, 8000, 1, timeout, errbuf);
	if (!p) {
		fprintf(stderr, "%s\n", errbuf);
		exit(1);
	}

	sprintf(filter_string, "dst %s and icmp", dst_ip);
	if (pcap_compile(p, &fcode, filter_string, 0, maskp) == -1) {
		pcap_perror(p, "pcap_compile error");
		exit(1);
	}
	
	if (pcap_setfilter(p, &fcode) == -1) {
		pcap_perror(p, "pcap_setfilter error");
		exit(1);
	}
}

int pcap_get_reply(void)
{
	const u_char *ptr;
	myicmp *packet;
	struct pcap_pkthdr *hdr;

	int ret = pcap_next_ex(p, &hdr, &ptr);
	printf("ret in pcap = %d\n", ret);

	if (ret == 0) {
		printf("Destination unreachable\n");
		return ret;
	}
	
	if (ret == 1) {
		packet = (myicmp*)(ptr + ETHERNET_HDR_SIZE); /* length of ethernet header */

		if (packet->icmp_hdr.type == 3) {
			printf("Destination unreachable\n");
		}
		printf("\tReply from : %s , ", inet_ntoa(packet->ip_hdr.ip_src));
	} else if (ret == -1) {
		fprintf(stderr, "pcap_next_ex(): %s\n", pcap_geterr(p));
	} else if (ret == -2) {
		printf("No more packet from file\n");
	}
	
	return ret;
}
