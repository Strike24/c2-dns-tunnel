#define PORT 5353
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

struct dns_answer
{
    unsigned short name;   // Pointer to question name
    unsigned short qtype;  // qtype
    unsigned short qclass; // qclass
    unsigned int ttl;
    unsigned short data_len; // Length of RDATA
} __attribute__((packed));   // Prevent compiler padding