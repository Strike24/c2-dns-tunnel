#ifndef LISTENER_H
#define LISTENER_H

#define TRUE 1
#define FALSE 0
#define ERROR -1
#define PORT 5353 // Non-privileged port for DNS
#define MAX_BUFFER_SIZE 1024
#define DNS_HEADER_SIZE 12

#include <stdio.h>      // Standard Input/Output
#include <stdlib.h>     // Standard Library
#include <unistd.h>     // closing the socket
#include <string.h>     // Memory handling
#include <sys/socket.h> // main Socket API
#include <netinet/in.h> // Definitions for IP addresses
#include <arpa/inet.h>  // Utilities to convert IPs

// A standard DNS header is exactly 12 bytes
struct dns_header
{
    unsigned short id;        // 16-bit Transaction ID
    unsigned short flags;     // 16-bit Flags (Query/Response, Opcode, ...)
    unsigned short q_count;   // questions count
    unsigned short ans_count; // answers count
    unsigned short auth_count;
    unsigned short add_count;
} __attribute__((packed)); // Prevent compiler padding

struct dns_question
{
    char name[256]; // Domain name (max 255 chars + null terminator)
    unsigned short qtype;
    unsigned short qclass;
};

struct dns_packet
{
    struct dns_header header;
    struct dns_question question;
};

/* Parses raw DNS packet data from the given buffer into a structured dns_packet object,
extracting the DNS header, question name, question type, and question class fields.
*/
void parse_dns_packet(char *buffer, struct dns_packet *packet);

void send_response(int sockfd, char *request_buffer, int request_len, struct dns_packet *parsed_packet, struct sockaddr_in *client_addr, socklen_t addr_len);
#endif // LISTENER_H