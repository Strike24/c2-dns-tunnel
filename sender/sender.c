#include "sender.h"

int main()
{
    const char *dns_server_ip = "127.0.0.1";
    const char domain[MAX_BUFFER_SIZE] = "example.com";
    char *payload = "run whoami";
    char *encoded_payload = base64_encode(payload);
    char response[MAX_UDP_PACKET_SIZE];

    // Send DNS query with encoded payload
    char full_domain[MAX_BUFFER_SIZE + 3];
    snprintf(full_domain, sizeof(full_domain), "%s.%s", encoded_payload, domain);

    send_dns_query(dns_server_ip, full_domain, response, sizeof(response));
    free(encoded_payload);
    return 0;
}

char base64_map[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                     'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                     'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                     'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};

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

int send_dns_query(const char *server_ip, const char *domain, char *response, int response_size)
{
    // Create a simple DNS query packet (A record query for example.com)
    struct dns_packet packet;
    memset(&packet, 0, sizeof(packet));
    packet.header.id = htons(0x1234);    // Transaction ID
    packet.header.flags = htons(0x0100); // Standard query
    packet.header.q_count = htons(1);    // One question
    char *name_ptr = packet.question.name;
    const char *pos = domain;
    while (*pos)
    {
        const char *dot = strchr(pos, '.');
        if (!dot)
            dot = pos + strlen(pos);
        int len = dot - pos;
        *name_ptr++ = len;
        memcpy(name_ptr, pos, len);
        name_ptr += len;
        if (*dot == '.')
            pos = dot + 1;
        else
            break;
    }
    *name_ptr++ = 0;                                                                       // End of name
    packet.question.qtype = htons(1);                                                      // Type A
    packet.question.qclass = htons(1);                                                     // Class IN
    int packet_length = sizeof(struct dns_header) + (name_ptr - packet.question.name) + 4; // 4 bytes for QTYPE and QCLASS

    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd < 0)
    {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in dns_server_addr;
    memset(&dns_server_addr, 0, sizeof(dns_server_addr));
    dns_server_addr.sin_family = AF_INET;
    dns_server_addr.sin_port = htons(PORT);                     // DNS uses port 53
    inet_pton(AF_INET, "127.0.0.1", &dns_server_addr.sin_addr); // Replace with your desired DNS server IP

    int bytes = sendto(sockfd, (char *)&packet, packet_length, 0,
                       (struct sockaddr *)&dns_server_addr, sizeof(dns_server_addr));

    if (bytes < 0)
    {
        perror("CRITICAL ERROR: sendto failed"); // This will print why it failed
        close(sockfd);
        exit(1);
    }

    socklen_t addr_len = sizeof(dns_server_addr);
    int bytes_received = recvfrom(sockfd, response, response_size, 0,
                                  (struct sockaddr *)&dns_server_addr, &addr_len);
    if (bytes_received < 0)
    {
        perror("recvfrom failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Extract TXT response from the DNS answer section
    struct dns_header *response_header = (struct dns_header *)response;
    unsigned short answer_count = ntohs(response_header->ans_count);
    if (answer_count > 0)
    {
        // Skip question section
        char *reader = response + DNS_HEADER_SIZE;
        while (*reader != 0)
            reader += (*reader) + 1; // Skip labels
        reader += 1 + 2 + 2;         // Skip Null byte, QType(2), QClass(2)
        // Now at the beginning of the answer section
        // Parse the first answer
        struct dns_answer *answer = (struct dns_answer *)reader;
        if (ntohs(answer->qtype) == 16) // TXT record
        {
            reader += sizeof(struct dns_answer);
            unsigned short data_len = ntohs(answer->data_len);
            if (data_len > 0)
            {
                unsigned char txt_len = *reader; // First byte is length
                if (txt_len + 1 <= data_len)
                {
                    char txt_data[256];
                    memcpy(txt_data, reader + 1, txt_len);
                    txt_data[txt_len] = '\0';
                    printf("Received TXT response: %s\n", txt_data);
                }
            }
        }
    }
    return 0;
}