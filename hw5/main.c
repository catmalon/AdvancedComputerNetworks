#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <time.h>

#include "fill_packet.h"
#include "pcap.h"



int main(int argc, char* argv[])
{
	int choose = -1;
	int option_index = 0;
	pid_t pid;
	int sockfd_send;
	int on = 1;
	int seq = 1;
	struct ifreq ifr;
	uint32_t myip, currip, mask, dest = 0;
	char ipstr[15], interface[20];
	struct sockaddr_in dst;
	struct in_addr tmp;
	myicmp *send_packet = (myicmp*)malloc(sizeof(myicmp));
	int timeout = DEFAULT_TIMEOUT;
	clock_t start_t, end_t;
	double totol_t;
	int need_help = 1;

	pid = getpid();

	if ((getuid()) != 0) {
		printf("ERROR: You must be root to use this tool!\n");
		exit(1);
	}

	while ((choose = getopt(argc, argv, "i:t:")) != -1) {
		switch (choose) {
			case 'i':
				need_help = 0;
				strcpy(interface, optarg);
				strcpy(ifr.ifr_ifrn.ifrn_name, interface);
				break;
			case 't':
				timeout = atoi(optarg);
				break;
			default:
				need_help = 1;
				break;
		}
	}

	if (need_help) {
		printf("sudo ./ipscanner –i [Network Interface Name] -t [timeout(ms)]\n");
		return 0;
	}
	
	if ((sockfd_send = socket(AF_INET, SOCK_RAW , IPPROTO_RAW)) < 0) {
		perror("socket error");
		exit(1);
	}

	/*
	* open send socket
	*/
	if (setsockopt(sockfd_send, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
		perror("setsockopt error");
		exit(1);
	}

	// get IP addr
	if (ioctl(sockfd_send, SIOCGIFADDR, &ifr) < 0) {
		perror("ioctl SIOCGIFADDR error");
		return -1;
	}
	myip = ntohl(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr);

	// get subnet mask
	if (ioctl(sockfd_send, SIOCGIFNETMASK, &ifr) < 0) {
		perror("ioctl SIOCGIFNETMASK error");
		return -1;
	}
	mask = ntohl(((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr.s_addr);

	/* 
	* in pcap.c, initialize the pcap
	*/
	tmp.s_addr = htonl(myip);
	strcpy(ipstr, inet_ntoa(tmp));
	pcap_init(interface, ipstr, timeout);

	for (uint32_t ip = (myip & mask)+1; (ip & mask) == (myip & mask); ip++) {
		int ret = 0;

		/*
		* fill send_packet
		*/
		memset(send_packet, 0, sizeof(myicmp));
		fill_iphdr(&send_packet->ip_hdr, myip, ip);
		fill_icmphdr(&send_packet->icmp_hdr, pid, seq, (icmp_all*) &send_packet->icmp_hdr);
		seq += 1;
		
		/*
		* Use "sendto" to send packets
		*/
		memset(&dst, 0, sizeof(dst));
		dst.sin_family = AF_INET;
		dst.sin_addr.s_addr = htonl(ip);

		start_t = clock();
		if (sendto(sockfd_send, send_packet, sizeof(myicmp), 0, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
				perror("sendto error");
				exit(1);
		}
		
		printf("PING %s (data size = %ld, id = %x, seq = %d, timeout = %d ms)\n",
				inet_ntoa(send_packet->ip_hdr.ip_dst), strlen(send_packet->data), 
				ntohs(send_packet->icmp_hdr.un.echo.id), ntohs(send_packet->icmp_hdr.un.echo.sequence),
				timeout);

		/*
		*  Use "pcap_get_reply"(in pcap.c) to get the "ICMP echo response" packets
		*/
		ret = pcap_get_reply();
		if(ret != 1){
			continue;
		}
		end_t = clock();
		totol_t = (double)(end_t - start_t) *1000 / CLOCKS_PER_SEC;
		printf("time : %.5f ms\n", totol_t);
	}
	close(sockfd_send);
	free(send_packet);

	return 0;
}