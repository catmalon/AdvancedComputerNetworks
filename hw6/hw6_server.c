
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/select.h>
#include <time.h>
#include <signal.h>
#include "common.h"

#define LISTENQ 5


static int start_server(int port)
{
	int sockfd = 0;
	struct sockaddr_in info = {0};

	// create socket resource
	sockfd = socket(AF_INET, SOCK_STREAM , 0);
	if (sockfd == -1){
		printf("Fail to create a socket.\n");
		return sockfd;
	}

	// fill configuration & start server
	info.sin_family = PF_INET;
	info.sin_addr.s_addr = INADDR_ANY;
	info.sin_port = htons(port);
	bind(sockfd,(struct sockaddr *)&info, sizeof(info));
	listen(sockfd, LISTENQ);

	return sockfd;
}

int pri_sockfd = 0;
void intHandler(int dummy)
{
	char *buffer = "Ctrl + C";
	if (pri_sockfd > 0) {
		send(pri_sockfd, buffer, strlen(buffer), 0);
	}
}

int main(int argc, char *argv[])
{
	char buffer[256] = {0}, id[16] = {0};
	int sockfd = 0, client_sockfd = 0, port = 0;
	struct sockaddr_in clientInfo = {0};
	int addrlen = sizeof(clientInfo);
	ssize_t recv_size = 0;
	fd_set rfds;

	if (geteuid() != 0 || argc != 2 || sscanf(argv[1], "%d", &port) != 1) {
		printf("[USAGE] ./hw6_server SERVER_PORT\n");
		exit(-1);
	}

	sockfd = start_server(port);
	if (sockfd == -1){
		exit(-1);
	}
	printf(">> server started.\n");

	client_sockfd = accept(sockfd,(struct sockaddr*) &clientInfo, &addrlen);
	if (client_sockfd == -1) {
		printf("accept error");
		exit(-1);
	}
	printf(">> %s connects in.\n", inet_ntoa(clientInfo.sin_addr));

	recv(client_sockfd, buffer, sizeof(buffer), 0);
	sscanf(buffer, "%s %d", id, &port);
	printf(">> %s issues the listen port %d and cookie %s\n", inet_ntoa(clientInfo.sin_addr), port, id);

	pri_sockfd = connect_to(inet_ntoa(clientInfo.sin_addr), port);
	if (pri_sockfd == -1){
		exit(-1);
	}
	printf(">> connected to %s:%d.\n", inet_ntoa(clientInfo.sin_addr), port);

	sprintf(buffer,"%s", id);
	send(pri_sockfd, buffer, strlen(buffer), 0);

	signal(SIGINT, intHandler);

	while (1) {

		FD_ZERO(&rfds);
		FD_SET(client_sockfd, &rfds);
		FD_SET(pri_sockfd, &rfds);

		select((pri_sockfd > client_sockfd ? pri_sockfd : client_sockfd) + 1, &rfds, NULL, NULL, NULL);
		if (FD_ISSET(client_sockfd, &rfds)) {
			recv_size = recv(client_sockfd, buffer, sizeof(buffer), 0);
			if (recv_size == 0) {
				printf("client disconnected.\n");
				break;
			}
			buffer[recv_size] = '\0';
			printf(">> received client message - %s...\t", buffer);
			send(client_sockfd, buffer,  sizeof(buffer), 0);
			printf("and echo.\n");
		} else if (FD_ISSET(pri_sockfd, &rfds)) {
			recv_size = recv(pri_sockfd, buffer, sizeof(buffer), 0);
			if (recv_size == 0) {
				printf("client disconnected.\n");
				break;
			}
			buffer[recv_size] = '\0';
			printf(">> received urgent message from client - %s.\n", buffer);
		}
	}

	close(sockfd);
	close(client_sockfd);
	close(pri_sockfd);
	return 0;
}
