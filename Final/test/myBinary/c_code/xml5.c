#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_XML  8192
#define MAX_MSG  512

static void extract_h1(const char *xml, char *out, size_t out_size) {
    const char *open_tag  = "<h1>";
    const char *close_tag = "</h1>";

    const char *start = strstr(xml, open_tag);
    const char *end   = strstr(xml, close_tag);

    if (!start || !end || end <= start) {
        snprintf(out, out_size, "no <h1> tag found");
        return;
    }

    start += strlen(open_tag);
    size_t len = (size_t)(end - start);
    if (len >= out_size) {
        len = out_size - 1;
    }

    memcpy(out, start, len);
    out[len] = '\0';
}


static void vulnerable_print(const char *msg) {
    printf("XML5 might have a format string\n");

    volatile int *p = NULL;

    /*fmt vuln*/
    printf(msg, p);

    printf("\nI'm still not a web developer :)\n");
}

int main(void) {
    char xml_buf[MAX_XML];
    size_t n = fread(xml_buf, 1, sizeof(xml_buf) - 1, stdin);
    xml_buf[n] = '\0';

    char h1_msg[MAX_MSG];
    extract_h1(xml_buf, h1_msg, sizeof(h1_msg));

    vulnerable_print(h1_msg);

    return 0;
}
