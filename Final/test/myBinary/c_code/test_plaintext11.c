#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char buffer[64];
    char *line = NULL;
    size_t len = 0;

    while (getline(&line, &len, stdin) != -1) {
        /* Vulnerability: buffer overflow */
        strcpy(buffer, line);
        printf("Processed: %s", buffer);
    }

    free(line);
    return 0;
}


