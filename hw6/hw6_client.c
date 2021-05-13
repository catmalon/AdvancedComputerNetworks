
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
#include <sys/select.h>
#include <signal.h>
#include "common.h"

#define STDIN 0
#define LISTENQ 5


static int start_priority_server(int *port)
{
	int sockfd = 0, err = -1;
	struct sockaddr_in info = {};
	socklen_t len = sizeof(info);

	sockfd = socket(AF_INET, SOCK_STREAM , 0);
	if (sockfd == -1){
		printf("Fail to create a socket.\n");
		return sockfd;
	}

	info.sin_family = AF_INET;
	info.sin_addr.s_addr = INADDR_ANY;
	info.sin_port = 0;
	if (bind(sockfd, (struct sockaddr *) &info, sizeof(info)) != 0) {
		printf("Fail to find an available port. (bind)\n");
		close(sockfd);
		return err;
	}

	if (getsockname(sockfd, (struct sockaddr *)&info, &len) != 0) {
		printf("Fail to find an available port. (getsockname)\n");
		close(sockfd);
		return err;
	}

	*port = ntohs(info.sin_port);

	// fill configuration & start server
	info.sin_family = PF_INET;
	info.sin_addr.s_addr = INADDR_ANY;
	bind(sockfd,(struct sockaddr *)&info, sizeof(info));
	listen(sockfd, LISTENQ);

	return sockfd;
}

int client_sockfd = 0;
void intHandler(int dummy)
{
	char *buffer = "Ctrl + C";
	if (client_sockfd > 0) {
		send(client_sockfd, buffer, strlen(buffer), 0);
	}
}

int main(int argc, char *argv[])
{
	int sockfd = 0, pri_sockfd = 0, port = 0;
	struct sockaddr_in clientInfo = {};
	int addrlen = sizeof(clientInfo);
	char id[16] = {}, buffer[256] = {};
	ssize_t recv_size = 0;
	fd_set rfds;

	if ((getuid()) != 0) {
		printf("ERROR: You must be root to use this tool!\n");
		exit(1);
	}

	if (argc != 3 || !is_valid_ip(argv[1]) || sscanf(argv[2], "%d", &port) != 1) {
		printf("[USAGE] ./hw6_client SERVER_IP PORT\n");
		exit(-1);
	}

	sockfd = connect_to(argv[1], port);
	if (sockfd == -1){
		exit(-1);
	}
	printf(">> connected.\n");

	pri_sockfd = start_priority_server(&port);
	if (sockfd == -1){
		exit(-1);
	}
	printf(">> priority server on port %d started.\n", port);

	generate_id(id, 6);
	sprintf(buffer, "%s %d", id, port);
	send(sockfd, buffer, strlen(buffer), 0);
	printf(">> send cookie (%s) and port %d to server.\n", id, port);

	printf(">> wait for connection...\n");
	client_sockfd = accept(pri_sockfd,(struct sockaddr*) &clientInfo, &addrlen);
	printf(">> priority socket connected.\n");

	recv_size = recv(client_sockfd, buffer, sizeof(buffer), 0);
	buffer[recv_size] = '\0';
	if (strcmp(buffer, id) != 0) {
		printf("cookie error!\n");
		exit(-1);
	}

	signal(SIGINT, intHandler);

	while (1) {
		printf("Type any message to server: ");
		fflush(stdout);

		FD_ZERO(&rfds);
		FD_SET(STDIN, &rfds);
		FD_SET(sockfd, &rfds);
		FD_SET(client_sockfd, &rfds);

		select((sockfd > client_sockfd ? sockfd : client_sockfd) + 1, &rfds, NULL, NULL, NULL);
		if (FD_ISSET(STDIN, &rfds)) {
			char *line_buf = NULL;
			size_t line_buf_size = 0;
			getline(&line_buf, &line_buf_size, stdin);
			line_buf[strlen(line_buf)-1] = '\0';
			send(sockfd, line_buf, line_buf_size, 0);
			printf(">> send message to server.\n");
		} else if (FD_ISSET(sockfd, &rfds)) {
			recv_size = recv(sockfd, buffer, sizeof(buffer), 0);
			if (recv_size == 0) {
				printf("server disconnected.\n");
				break;
			}
			buffer[recv_size] = '\0';
			printf("\n>> received server message - %s.\n", buffer);
		} else if (FD_ISSET(client_sockfd, &rfds)) {
			recv_size = recv(client_sockfd, buffer, sizeof(buffer), 0);
			if (recv_size == 0) {
				printf("server disconnected.\n");
				break;
			}
			buffer[recv_size] = '\0';
			printf("\n>> received server urgent message - %s.\n", buffer);
		}
	}

	close(sockfd);
	close(client_sockfd);
	close(pri_sockfd);
	return 0;
}
