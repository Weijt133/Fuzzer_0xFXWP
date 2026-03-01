#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *line = NULL;
    size_t len = 0;
    ssize_t read;

    while ((read = getline(&line, &len, stdin)) != -1) {
        if (read > 0 && line[read - 1] == '\n') {
            line[read - 1] = '\0';
        }

        char *rest = line;
        char *token;
        char field_buffer[32];

        while ((token = strtok_r(rest, ",", &rest)) != NULL) {
            /* Vulnerability: buffer overflow */
            strcpy(field_buffer, token);
            printf("Field: %s\n", field_buffer);
        }
    }

    free(line);
    return 0;
}


