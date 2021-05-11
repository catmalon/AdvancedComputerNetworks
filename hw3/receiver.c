#include "arp.h"

void arp_capture(const char *filtered_ip)
{
	int sockfd_recv = 0;
	ssize_t recvd_size;
	struct ifreq req;
	struct sockaddr_ll sa;
	void *buffer = NULL;
	struct arp_packet *packet;
	char ip[20];

	// Open a recv socket in data-link layer
	if((sockfd_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("open recv socket error");
		exit(1);
	}
	printf("### ARP sniffer mode ###\n");

	// retrieve ethernet interface index 
	strncpy(req.ifr_name, DEVICE_NAME, IFNAMSIZ);
	if (ioctl(sockfd_recv, SIOCGIFINDEX, &req) == -1) {
		perror("SIOCGIFINDEX");
		exit(1);
	}

	sa.sll_family = AF_PACKET;
	sa.sll_protocol = htons(ETH_P_ARP); 
	sa.sll_ifindex = req.ifr_ifindex;
	if(bind(sockfd_recv, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
		perror("bind(): ");
		exit(-1);
	}

	buffer = malloc(BUFF_SIZE);
	
	while (1) {
		if ( (recvd_size = recv(sockfd_recv, buffer, BUFF_SIZE, 0)) == -1) {
			perror("recv(): ");
			free(buffer);
			close(sockfd_recv);
			exit(-1);
		}

		if (recvd_size <= (sizeof(struct arp_packet))) {
			printf("Short packet. Packet len: %ld\n", recvd_size);
			continue;
		}

		packet = buffer;
		if (ntohs(packet->eth_hdr.ether_type) != ETH_P_ARP) {
			continue;
		}
		if (ntohs(packet->arp.ea_hdr.ar_op) != ARPOP_REQUEST) {
			continue;
		}

		sprintf(ip, "%d.%d.%d.%d", packet->arp.arp_spa[0], packet->arp.arp_spa[1], packet->arp.arp_spa[2], packet->arp.arp_spa[3]);
		if (strcmp(filtered_ip, "-a") == 0 || strcmp(filtered_ip, ip) == 0) {
			printf("Get ARP packet - Who has %d.%d.%d.%d ?\t\t", packet->arp.arp_tpa[0], packet->arp.arp_tpa[1], packet->arp.arp_tpa[2], packet->arp.arp_tpa[3]);
			printf("Tell %d.%d.%d.%d\n", packet->arp.arp_spa[0], packet->arp.arp_spa[1], packet->arp.arp_spa[2], packet->arp.arp_spa[3]);
		} 
	}
	close(sockfd_recv);
	free(buffer);
}