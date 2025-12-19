#include "sender.h"

int main(int argc, char *argv[])
{

    if (argc < MIN_ARGUMENTS)
    {
        printf("Usage: %s <dns_server_ip> <domain> <payload>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *dns_server_ip = argv[1];
    const char *domain = argv[2];
    char *payload = argv[3];
    char *encoded_payload = base64_encode(payload);
    char response[MAX_UDP_PACKET_SIZE];

    // Send DNS query with encoded payload
    char full_domain[MAX_BUFFER_SIZE + 3];
    snprintf(full_domain, sizeof(full_domain), "%s.%s", encoded_payload, domain);

    send_dns_query(dns_server_ip, full_domain, response, sizeof(response));
    free(encoded_payload);
    return 0;
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
    dns_server_addr.sin_port = htons(PORT);                   // DNS uses port 53
    inet_pton(AF_INET, server_ip, &dns_server_addr.sin_addr); // Replace with your desired DNS server IP

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
                    char *decoded_txt = base64_decode(txt_data);
                    if (decoded_txt)
                    {
                        printf("Received TXT response: %s\n", decoded_txt);
                        free(decoded_txt);
                    }
                }
            }
        }
    }
    return 0;
}