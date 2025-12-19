#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <memory.h>

#define DNS_HEADER_SIZE 12
#define MAX_UDP_PACKET_SIZE 65536
#define MAX_BUFFER_SIZE 1024

#include "../headers/structs.h"

char *base64_encode(char *plain);
char *base64_decode(char *cipher);

int send_dns_query(const char *server_ip, const char *domain, char *response, int response_size);
