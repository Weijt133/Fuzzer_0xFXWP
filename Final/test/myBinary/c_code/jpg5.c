#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

static int read_byte(FILE *fp) {
    int c = fgetc(fp);
    if (c == EOF) {
        return -1;
    }
    return c & 0xFF;
}

static uint16_t read_be16(FILE *fp) {
    int hi = read_byte(fp);
    int lo = read_byte(fp);
    if (hi < 0 || lo < 0) {
        return 0;
    }
    return (uint16_t)((hi << 8) | lo);
}

static void skip_segment(FILE *fp, uint16_t len) {
    if (len < 2) return;
    uint16_t remaining = (uint16_t)(len - 2);
    char tmp[512];

    while (remaining > 0) {
        size_t chunk = remaining > sizeof(tmp) ? sizeof(tmp) : remaining;
        size_t got = fread(tmp, 1, chunk, fp);
        if (got == 0) {
            break;
        }
        remaining -= (uint16_t)got;
    }
}

static void parse_app_segment(FILE *fp, uint16_t len, int marker) {
    unsigned char buffer[256];  /* 小栈缓冲区 */

    if (len < 2) return;
    uint16_t payload = (uint16_t)(len - 2);

    /*
     * *** INTENTIONAL BUG ***
     */
    size_t n = fread(buffer, 1, payload, fp);

    if (n > 0) {
        volatile unsigned char dummy = buffer[0];
        dummy = buffer[256];
    }
}

int main(int argc, char **argv) {
    FILE *fp = stdin;

    if (argc == 2) {
        fp = fopen(argv[1], "rb");
        if (!fp) {
            perror("fopen");
            return 1;
        }
    }

    /* SOI: FF D8 */
    int b0 = read_byte(fp);
    int b1 = read_byte(fp);
    if (b0 != 0xFF || b1 != 0xD8) {
        if (fp != stdin) fclose(fp);
        return 0;
    }

    for (;;) {
        int c;

        do {
            c = read_byte(fp);
            if (c < 0) goto done;
        } while (c != 0xFF);

        int marker;
        do {
            marker = read_byte(fp);
            if (marker < 0) goto done;
        } while (marker == 0xFF);

        if (marker == 0xD9) { 
            break;
        }

        uint16_t len = read_be16(fp);
        if (len < 2) {
            break;
        }

        if (marker >= 0xE0 && marker <= 0xEF) {
            parse_app_segment(fp, len, marker);
        } else {
            skip_segment(fp, len);

            if (marker == 0xDA) {
                break;
            }
        }
    }

done:
    if (fp != stdin) fclose(fp);
    return 0;
}