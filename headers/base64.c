#include "base64.h"

#include <stdlib.h>
#include <string.h>

static const char base64_map[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};

char *base64_encode(const char *plain)
{
    int counts = 0;
    unsigned char buffer[3];
    size_t plain_len = strlen(plain);
    char *cipher = malloc(plain_len * 4 / 3 + 4);
    int i = 0, c = 0;

    if (!cipher)
        return NULL;

    for (i = 0; plain[i] != '\0'; i++)
    {
        buffer[counts++] = (unsigned char)plain[i];
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
        {
            cipher[c++] = base64_map[((buffer[0] & 0x03) << 4) + (buffer[1] >> 4)];
            cipher[c++] = base64_map[(buffer[1] & 0x0f) << 2];
        }
        cipher[c++] = '=';
    }

    cipher[c] = '\0';
    return cipher;
}

char *base64_decode(const char *cipher)
{
    int counts = 0;
    unsigned char buffer[4];
    size_t cipher_len = strlen(cipher);
    char *plain = malloc(cipher_len * 3 / 4 + 1);
    int i = 0, p = 0;

    if (!plain)
        return NULL;

    for (i = 0; cipher[i] != '\0'; i++)
    {
        int k;
        if (cipher[i] == '=')
            k = 64;
        else
        {
            for (k = 0; k < 64 && base64_map[k] != cipher[i]; k++)
                ;
        }

        buffer[counts++] = (unsigned char)k;
        if (counts == 4)
        {
            plain[p++] = (char)((buffer[0] << 2) + (buffer[1] >> 4));
            if (buffer[2] != 64)
                plain[p++] = (char)((buffer[1] << 4) + (buffer[2] >> 2));
            if (buffer[3] != 64)
                plain[p++] = (char)((buffer[2] << 6) + buffer[3]);
            counts = 0;
        }
    }

    plain[p] = '\0';
    return plain;
}
