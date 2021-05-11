#include "arp.h"

void arp_query(const char *filtered_ip)
{
	void* buffer = (void*)malloc(BUFF_SIZE);
	int sockfd_send = 0;
	int ifindex = 0;
	struct ifreq req;
	struct sockaddr_ll addr;
	char *ipaddr;
	unsigned char source_ip[4];
	unsigned char target_ip[4];
	struct arp_packet *packet;
	ssize_t recvd_size;

	// open socket
	if((sockfd_send = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("open socket error");
		exit(1);
	}
	printf("### ARP query mode ###\n");

	// retrieve ethernet interface index
	strncpy(req.ifr_name, DEVICE_NAME, IFNAMSIZ);
	if (ioctl(sockfd_send, SIOCGIFINDEX, &req) == -1) {
		perror("SIOCGIFINDEX");
		exit(1);
	}
	ifindex = req.ifr_ifindex; // prevent another iotcl reset it

	
	// retrieve ethernet IP address
	if (ioctl(sockfd_send, SIOCGIFADDR, &req) == -1) {
		perror("SIOCGIFADDR");
		exit(1);
	}
	ipaddr = (char *)malloc(INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(((struct sockaddr_in *)&req.ifr_addr)->sin_addr), ipaddr, INET_ADDRSTRLEN);
	sscanf(ipaddr, "%hhu.%hhu.%hhu.%hhu", &source_ip[0], &source_ip[1], &source_ip[2], &source_ip[3]);
	sscanf(filtered_ip, "%hhu.%hhu.%hhu.%hhu", &target_ip[0], &target_ip[1], &target_ip[2], &target_ip[3]);

	// retrieve ethernet interface MAC
	if (ioctl(sockfd_send, SIOCGIFHWADDR, &req) == -1) {
		perror("SIOCGIFHWADDR");
		exit(1);
	}

	// prepare sockaddr_ll
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ARP);
	addr.sll_ifindex = ifindex;
	addr.sll_hatype = htons(ARPHRD_ETHER);
	addr.sll_pkttype = (PACKET_BROADCAST);
	addr.sll_halen = ETH_ALEN;
	addr.sll_addr[0] = req.ifr_hwaddr.sa_data[0];
	addr.sll_addr[1] = req.ifr_hwaddr.sa_data[1];
	addr.sll_addr[2] = req.ifr_hwaddr.sa_data[2];
	addr.sll_addr[3] = req.ifr_hwaddr.sa_data[3];
	addr.sll_addr[4] = req.ifr_hwaddr.sa_data[4];
	addr.sll_addr[5] = req.ifr_hwaddr.sa_data[5];
	addr.sll_addr[6] = 0x00;
	addr.sll_addr[7] = 0x00;

	// Creating ARP request
	//Broadcast
	packet = buffer;
    memset(packet->eth_hdr.ether_dhost, 0xff, 6);
	memcpy(packet->eth_hdr.ether_shost, req.ifr_hwaddr.sa_data, 6);
	packet->eth_hdr.ether_type = htons(ETH_P_ARP);

	packet->arp.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
	packet->arp.ea_hdr.ar_pro = htons(ETH_P_IP);
	packet->arp.ea_hdr.ar_hln = ETH_ALEN;
	packet->arp.ea_hdr.ar_pln = 4;
	packet->arp.ea_hdr.ar_op = htons(ARPOP_REQUEST);
	for (int i = 0 ; i < 4; i++) {
		packet->arp.arp_spa[i] = (unsigned char)source_ip[i];
		packet->arp.arp_tpa[i] = (unsigned char)target_ip[i];
	}
	for (int i = 0 ; i < 6; i++) {
		packet->arp.arp_sha[i] = req.ifr_hwaddr.sa_data[i];
		packet->arp.arp_tha[i] = 0;
	}

	// Send request for a raw socket descriptor.
	if (sendto(sockfd_send, packet, sizeof(struct arp_packet), 0, (struct sockaddr*)&addr, sizeof(struct sockaddr_ll)) < 0) {
		perror("sendto():");
		exit(1);
	}

	//OUTPUT
	while (1) {
		if ((recvd_size = recv(sockfd_send, buffer, BUFF_SIZE, 0)) == -1) {
			perror("recv(): ");
			close(sockfd_send);
			exit(-1);
		}

		if (ntohs(packet->eth_hdr.ether_type) != ETH_P_ARP) {
			continue;
		}
		if (ntohs(packet->arp.ea_hdr.ar_op) != ARPOP_REPLY) {
			continue;
		}

		if (source_ip[0] == packet->arp.arp_tpa[0] && source_ip[1] == packet->arp.arp_tpa[1] &&
			source_ip[2] == packet->arp.arp_tpa[2] && source_ip[3] == packet->arp.arp_tpa[3]) {
			
			printf("MAC address of ");

			//Receiver IP
			printf(" %d.%d.%d.%d", packet->arp.arp_spa[0],packet->arp.arp_spa[1],packet->arp.arp_spa[2],packet->arp.arp_spa[3]);
			printf(" is ");	

			//Receiver MAC
			printf("%02X:%02X:%02X:%02X:%02X:%02X\n", packet->arp.arp_sha[0], packet->arp.arp_sha[1], packet->arp.arp_sha[2], 
							packet->arp.arp_sha[3], packet->arp.arp_sha[4], packet->arp.arp_sha[5]);
			break;
		}
	}

	free(buffer);
	close(sockfd_send);

}