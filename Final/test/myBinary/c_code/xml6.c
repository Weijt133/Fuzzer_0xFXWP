#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_XML    8192
#define MAX_TITLE  512
#define MAX_LINKS  16
#define MAX_LINK   256

typedef struct {
    char summary[80]; 
    unsigned long crash_ptr; 
} Frame;

static int looks_like_decent_html(const char *xml) {
    if (!strstr(xml, "<html") || !strstr(xml, "</html>"))
        return 0;
    if (!strstr(xml, "<head") || !strstr(xml, "</head>"))
        return 0;
    if (!strstr(xml, "<body") || !strstr(xml, "</body>"))
        return 0;
    return 1;
}

static void extract_title(const char *xml, char *out, size_t out_size) {
    const char *open_tag  = "<title>";
    const char *close_tag = "</title>";

    const char *start = strstr(xml, open_tag);
    const char *end   = strstr(xml, close_tag);

    if (!start || !end || end <= start) {
        snprintf(out, out_size, "no title");
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

static int extract_links(const char *xml, char links[][MAX_LINK], int max_links) {
    const char *p = xml;
    const char *pattern = "href=\"";
    int count = 0;

    while (count < max_links) {
        const char *found = strstr(p, pattern);
        if (!found) break;

        found += strlen(pattern); 
        const char *end = strchr(found, '"');
        if (!end) break;

        size_t len = (size_t)(end - found);
        if (len >= MAX_LINK) len = MAX_LINK - 1;

        memcpy(links[count], found, len);
        links[count][len] = '\0';

        count++;
        p = end + 1;
    }

    return count;
}

static void build_summary_and_crash(const char *title,
                                    char links[][MAX_LINK],
                                    int link_count) {
    unsigned long safe_target = 0x12345678ul;
    Frame f;

    f.crash_ptr = (unsigned long)&safe_target;
    f.summary[0] = '\0';

    strcpy(f.summary, title);

    for (int i = 0; i < link_count; i++) {
        strcat(f.summary, " ");
        strcat(f.summary, links[i]);
    }

    printf("XML6 may have a title/link overflow =)\n");
    printf("Now its your time to shine\n");

    unsigned long *p = (unsigned long *)f.crash_ptr;
    *p = 0xdeadbeef;

    printf("wait, I survived\n");
}

int main(void) {
    char xml_buf[MAX_XML];
    size_t n = fread(xml_buf, 1, sizeof(xml_buf) - 1, stdin);
    xml_buf[n] = '\0';

    if (!looks_like_decent_html(xml_buf)) {
        fprintf(stderr, "[warn] input does not look like a normal HTML/XML page, exiting safely.\n");
        return 0;
    }

    char title[MAX_TITLE];
    char links[MAX_LINKS][MAX_LINK];
    int link_count = 0;

    extract_title(xml_buf, title, sizeof(title));
    link_count = extract_links(xml_buf, links, MAX_LINKS);

    build_summary_and_crash(title, links, link_count);

    return 0;
}
