#include <stdio.h>
#include <string.h>
#include <ctype.h>

void secret(void) {
    puts("====================================");
    puts("  [*] You reached the secret() !");
    puts("  Put your FLAG or shell here.     ");
    puts("====================================");
}

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

void analyze_line(void) {
    char workbuf[16];   
    puts("Enter candidate plaintext line:");
    
    if (fgets(workbuf, 1024, stdin) == NULL) {
        puts("Input error.");
        return;
    }

    if (looks_like_plaintext((unsigned char *)workbuf)) {
        puts("[+] This looks like plaintext.");
    } else {
        puts("[-] This does NOT look like plaintext.");
    }
}

int main(void) {
    puts("-----------------------------------------------------------------");
    analyze_line();
    puts("Done.");
    return 0;
}
