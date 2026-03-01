#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_XML    8192

typedef struct {
    char body_text[256];
    unsigned long crash_ptr;
} BodySummary;

/* 看起来像不像一个正常 HTML 页面 */
static int looks_like_decent_html(const char *xml) {
    if (!strstr(xml, "<html") || !strstr(xml, "</html>"))
        return 0;
    if (!strstr(xml, "<head") || !strstr(xml, "</head>"))
        return 0;
    if (!strstr(xml, "<body") || !strstr(xml, "</body>"))
        return 0;
    return 1;
}

static int find_body_range(const char *xml,
                           const char **out_start,
                           const char **out_end) {
    const char *open = strstr(xml, "<body");
    if (!open) return 0;

    const char *gt = strchr(open, '>');
    if (!gt) return 0;

    const char *close = strstr(gt, "</body>");
    if (!close) return 0;

    *out_start = gt + 1;
    *out_end   = close;
    return 1;
}

static void build_body_summary_and_crash(const char *body_start,
                                         const char *body_end) {
    BodySummary s;
    unsigned long safe_target = 0x12345678ul;

    s.crash_ptr = (unsigned long)&safe_target;
    s.body_text[0] = '\0';

    const char *p = body_start;
    char segment[128];

    while (p < body_end && *p) {
        if (*p == '<') {
            const char *gt = strchr(p, '>');
            if (!gt || gt >= body_end) {
                break;
            }
            p = gt + 1;
        } else {
            size_t seg_len = 0;
            const char *q = p;
            while (q < body_end && *q != '<' && seg_len < sizeof(segment) - 1) {
                segment[seg_len++] = *q++;
            }
            segment[seg_len] = '\0';

            strcat(s.body_text, segment);

            p = q;
        }
    }

    printf("XML7 real-body-parse \n");
 

    unsigned long *ptr = (unsigned long *)s.crash_ptr;
    *ptr = 0xdeadbeef;

    printf("Now I know what you wrote\n");
}

int main(void) {
    char xml_buf[MAX_XML];
    size_t n = fread(xml_buf, 1, sizeof(xml_buf) - 1, stdin);
    xml_buf[n] = '\0';

    if (!looks_like_decent_html(xml_buf)) {
        fprintf(stderr, "[warn] input does not look like a normal HTML page, exiting safely.\n");
        return 0;
    }

    const char *body_start = NULL;
    const char *body_end   = NULL;

    if (!find_body_range(xml_buf, &body_start, &body_end)) {
        fprintf(stderr, "[warn] could not find <body>...</body> range, exiting safely.\n");
        return 0;
    }

    build_body_summary_and_crash(body_start, body_end);
    return 0;
}
