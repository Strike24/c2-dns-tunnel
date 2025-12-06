#include "sender.h"

int main()
{
    char answer_buffer[MAX_BUFFER_SIZE];
    res_query("example.com", C_IN, T_A, answer_buffer, sizeof(answer_buffer));

        return 0;
}