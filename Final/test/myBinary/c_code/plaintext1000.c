
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define MAX_LINE 4096

int main(void) {
    char buf[MAX_LINE];

    printf("plaintext1000 - safe plaintext detector\n");
    printf("Enter a line (up to %d chars):\n", MAX_LINE - 1);

    if (!fgets(buf, sizeof(buf), stdin)) {
        fprintf(stderr, "[error] failed to read input\n");
        return 1;
    }

    size_t len = strlen(buf);
    if (len == 0) {
        printf("[result] empty input\n");
        return 0;
    }

    if (buf[len - 1] == '\n') {
        buf[len - 1] = '\0';
        len--;
    }

    size_t printable = 0;
    size_t control   = 0;

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)buf[i];
        if (isprint(c) || c == '\t') {
            printable++;
        } else {
            control++;
        }
    }

    double ratio = (len > 0) ? (double)printable / (double)len : 0.0;

    printf("[debug] length=%zu, printable=%zu, non-printable=%zu, printable_ratio=%.2f\n",
           len, printable, control, ratio);

    if (len > 0 && ratio >= 0.90) {
        printf("[result] This looks like plaintext.\n");
    } else {
        printf("[result] This does NOT look like plaintext.\n");
    }

    return 0;
}
