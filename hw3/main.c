#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <arpa/inet.h>

#include "arp.h"

void help()
{
	printf("Format : \n");
	printf("1) ./arp -l -a\n");
	printf("2) ./arp -l <filter_ip_address>\n");
	printf("3) ./arp -q <query_ip_address>\n");
	printf("4) ./arp <fake_mac_address> <taget_ip_address>\n");
}

int isValidMacAddress(const char* mac) {
    int i = 0;
    int s = 0;

    while (*mac) {
       if (isxdigit(*mac)) {
          i++;
       } else if (*mac == ':' || *mac == '-') {
          if (i == 0 || i / 2 - 1 != s) {
			  break;
		  }
          ++s;
       } else {
           s = -1;
       }
       ++mac;
    }

    return (i == 12 && (s == 5 || s == 0));
}

int check_spoof_parameters(char *mac, char *ip)
{
	struct sockaddr_in sa;

    return inet_pton(AF_INET, ip, &(sa.sin_addr)) != 0 && isValidMacAddress(mac);
}

int check_list_parameters(const char *param)
{
	struct sockaddr_in sa;
    
	if (strcmp(param, "-a") == 0) {
		return 1; // True
	}

    return inet_pton(AF_INET, param, &(sa.sin_addr)) != 0;
}

int check_query_parameters(const char *param)
{
	struct sockaddr_in sa;

    return inet_pton(AF_INET, param, &(sa.sin_addr)) != 0;
}

int main(int argc, char* argv[])
{
	int choose = -1;
	int option_index = 0;
	int valid = 1;

	static struct option long_options[] = {
		{"list",  required_argument, 0,   'l'},
		{"query", required_argument, 0,   'q'},
		{"help",  no_argument,       0,   'h'},
		{NULL,    0,                 NULL, 0}
	};

	if (getuid() != 0) {
		printf("ERROR: You must be root to use this tool!\n");
		exit(1);
	}

	printf("[ ARP sniffer and spoof program ]\n");

	choose = getopt_long(argc, argv, "hl:q:", long_options, &option_index);
	switch (choose) {
		case 'l':
			if (!check_list_parameters(optarg)) {
				printf("Option list with value '%s' not valid!!\n", optarg);
				valid = 0;
			} else {
				arp_capture(optarg);
			}
			break;
		case 'q':
			if (!check_query_parameters(optarg)) {
				printf("Option query with value '%s' not valid!!\n", optarg);
				valid = 0;
			} else {
				arp_query(optarg);
			}
			break;
		case 'h':
			help();
			break;
		case -1:
			if (argc != 3 || !check_spoof_parameters(argv[1], argv[2])){
				printf("Option not valid!!\n");
				valid = 0;
			} else {
				arp_spoofing(argv[1], argv[2]);
			}
			break;
		default:
			valid = 0;
			break;
	}

	if (valid == 0) {
		help();
	}

	return 0;
}