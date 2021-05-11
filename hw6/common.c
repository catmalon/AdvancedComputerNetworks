#include "common.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h> 
#include <time.h>
#include <stdlib.h>

int is_valid_ip(char *ip)
{
	struct sockaddr_in sa;
	int result = inet_pton(AF_INET, ip, &(sa.sin_addr));
	return result != 0;
}

void generate_id(char *output, unsigned int size)
{
	int i = 0;
	char symbols[] = "abcdefghijklmnopqrstuvwxyz0123456789";

	srand(time(NULL));
	for (i = 0; i < size; i++)
		output[i] = symbols[rand() % strlen(symbols)];
	output[size] = '\0';
}

int connect_to(const char *ip, int port)
{
	int sockfd = 0, err = -1;
	struct sockaddr_in info = {};

	sockfd = socket(AF_INET , SOCK_STREAM , 0);
	if (sockfd == -1){
		printf("Fail to create a socket.\n");
		return sockfd;
	}

	info.sin_family = PF_INET;
	info.sin_addr.s_addr = inet_addr(ip);
	info.sin_port = htons(port);

	err = connect(sockfd, (struct sockaddr *)&info, sizeof(info));
	if (err == -1) {
		printf("Connection error.\n");
		close(sockfd);
		return err;
	}

	return sockfd;
}