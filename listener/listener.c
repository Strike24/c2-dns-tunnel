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
    server_addr.sin_addr.s_addr = INADDR_ANY; // Listen on all network cards
    server_addr.sin_port = htons(PORT);       // Listen on port 5353

    // Bind port for listening
    if ((bind(sockfd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0))
    {

        perror("Port Binding failed.");
        exit(EXIT_FAILURE);
    }

    printf("Listening on port %d for UDP packets..", PORT);

    while (TRUE)
    {
        // Wait until data packet, write from sockfd file to buffer
        int n = recvfrom(sockfd, (char *)buffer, MAX_BUFFER_SIZE, MSG_WAITALL, (struct sockaddr *)&client_addr, &addr_len);
        buffer[n] = '\0';

        printf("\nRecived packet from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        struct dns_header *dns = (struct dns_header *)buffer; // Convert raw packet into dns header
        printf("DNS ID: 0x%X\n", ntohs(dns->id));

        // QNAME starts after the header, (byte 12).
        char *qname = buffer + sizeof(struct dns_header);
        char *reader = qname;
        while (*reader != 0)
        {
            int length = *reader; // Read the length byte (e.g., 3)
            reader++;             // Move past the length byte

            // Print the label
            for (int i = 0; i < length; i++)
            {
                printf("%c", *reader);
                reader++;
            }
            printf("."); // Separate with dots
        }
        printf("\n");

        // Question Type is 2 bytes after question name
        reader++;
        unsigned short *qtype_ptr = (unsigned short *)reader;
        unsigned short qtype = ntohs(*qtype_ptr);
        printf("QType Value: %hu\n", qtype);

        return 0;
    }
}
