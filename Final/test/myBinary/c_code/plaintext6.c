#include <stdio.h>
#include <string.h>
#include <ctype.h>

/*
plaintext check
 */
int looks_like_plaintext(const unsigned char *buf) {
    int total = 0;
    int printable = 0;

    for (int i = 0; buf[i] != '\0'; i++) {
        unsigned char c = buf[i];

        if (c == '\n' || c == '\r')
            continue;

        total++;

        if (isprint(c)) {
            printable++;
        }
    }

    if (total == 0) {
        return 0;
    }

    double ratio = (double)printable / (double)total;
    return (ratio >= 0.8);
}

typedef struct {
    char workbuf[32];
    unsigned long crash_ptr;
} Frame;

void analyze_line(void) {
    unsigned long safe_target = 0x12345678ul;
    Frame f;

    
    f.crash_ptr = (unsigned long)&safe_target;

    puts("Enter candidate plaintext line:");

    if (fgets(f.workbuf, 1024, stdin) == NULL) {
        puts("Input error.");
        return;
    }

    if (looks_like_plaintext((unsigned char *)f.workbuf)) {
        puts("[+] This looks like plaintext.");
    } else {
        puts("[-] This does NOT look like plaintext.");
    }

    unsigned long *p = (unsigned long *)f.crash_ptr;
    *p = 0xdeadbeef;


}

int main(void) {
    puts("-----------------------------------------------------------------");
    analyze_line();
    puts("Done.");
    return 0;
}
