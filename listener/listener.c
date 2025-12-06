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

    struct dns_header *reply_header = (struct dns_header *)reply_buffer;

    // Copying data to send a valid response back
    reply_header->id = parsed_packet->header.id;           // Copy original ID
    reply_header->flags = htons(0x8180);                   // Response, No Error
    reply_header->q_count = parsed_packet->header.q_count; // Copy question count
    reply_header->ans_count = htons(1);                    // adding one more answer
    reply_header->auth_count = 0;
    reply_header->add_count = 0;

    // Find the end of QClass in the original request buffer
    char *q_section_start = request_buffer + DNS_HEADER_SIZE;
    char *q_section_end = q_section_start;

    while (*q_section_end != 0)
    { // Find the null byte
        q_section_end += *q_section_end + 1;
    }
    q_section_end += 5; // Skip the final 0x00, QTYPE (2), QCLASS (2)

    int q_section_len = q_section_end - q_section_start;

    // Copy the raw question section to the reply buffer
    memcpy(reply_buffer + DNS_HEADER_SIZE, q_section_start, q_section_len);

    // Start writing the answer immediately after the question section.
    // char *answer_start = reply_buffer + DNS_HEADER_SIZE + q_section_len;

    // *** C2 LOGIC GOES HERE ***

    int reply_len = DNS_HEADER_SIZE + q_section_len;

    // --- STEP 4: SEND ---
    sendto(sockfd, reply_buffer, reply_len, 0, (const struct sockaddr *)client_addr, addr_len);
    printf("Valid NO_ERROR response sent back (Length: %d)\n", reply_len);
};