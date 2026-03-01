#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#define MAX_JSON_SIZE   4096
#define MAX_INPUT       256
#define MAX_MORE        16
#define MAX_MORE_STR    64

typedef struct {
    int  len;
    char input[MAX_INPUT];
    char more_data[MAX_MORE][MAX_MORE_STR];
    int  more_count;
} Parsed;


int looks_like_plaintext(const unsigned char *buf) {
    int total = 0;
    int printable = 0;

    for (int i = 0; buf[i] != '\0'; i++) {
        unsigned char c = buf[i];

        if (c == '\n' || c == '\r')
            continue;

        total++;
        if (isprint(c))
            printable++;
    }

    if (total == 0) return 0;

    double ratio = (double)printable / (double)total;
    return (ratio >= 0.8);
}



static int parse_int_field(const char *json, const char *field_name, int *out) {
    
    char *p = strstr((char *)json, field_name);
    if (!p) return -1;

    p = strchr(p, ':');
    if (!p) return -1;
    p++;

    while (*p == ' ' || *p == '\t')
        p++;

    *out = atoi(p);
    return 0;
}

static int parse_string_field(const char *json, const char *field_name,
                              char *out, size_t out_size) {
    char *p = strstr((char *)json, field_name);
    if (!p) return -1;

    p = strchr(p, ':');
    if (!p) return -1;

    
    p = strchr(p, '"');
    if (!p) return -1;
    p++; 

    char *q = strchr(p, '"');
    if (!q) return -1;

    size_t n = (size_t)(q - p);
    if (n >= out_size)
        n = out_size - 1;

    memcpy(out, p, n);
    out[n] = '\0';
    return 0;
}

static int parse_more_data_array(const char *json, Parsed *out) {
    char *p = strstr((char *)json, "\"more_data\"");
    if (!p) {
        out->more_count = 0;
        return 0; 
    }

    p = strchr(p, '[');
    if (!p) {
        out->more_count = 0;
        return -1;
    }
    p++; 

    int count = 0;

    while (*p && count < MAX_MORE) {
        
        while (*p == ' ' || *p == '\t' || *p == ',')
            p++;

        if (*p == ']')
            break;

        if (*p != '"') {
            p++;
            continue;
        }

        p++; 
        char *q = strchr(p, '"');
        if (!q)
            break;

        size_t n = (size_t)(q - p);
        if (n >= MAX_MORE_STR)
            n = MAX_MORE_STR - 1;

        memcpy(out->more_data[count], p, n);
        out->more_data[count][n] = '\0';

        count++;
        p = q + 1;
    }

    out->more_count = count;
    return 0;
}

static int parse_json(const char *json, Parsed *out) {
    memset(out, 0, sizeof(*out));

    
    if (parse_int_field(json, "\"len\"", &out->len) != 0) {
        fprintf(stderr, "[warn] could not parse len\n");
    }

    
    if (parse_string_field(json, "\"input\"", out->input, sizeof(out->input)) != 0) {
        fprintf(stderr, "[warn] could not parse input\n");
    }

    
    parse_more_data_array(json, out);

    return 0;
}



typedef struct {
    char workbuf[64];      
    unsigned long crash_ptr;
} Frame;

static void dangerous_build_and_crash(const Parsed *p) {
    unsigned long safe_target = 0x12345678ul;
    Frame f;

    f.crash_ptr = (unsigned long)&safe_target;

    f.workbuf[0] = '\0';

    for (int i = 0; i < p->len; i++) {
        strcat(f.workbuf, p->input);  
    }

    for (int i = 0; i < p->more_count; i++) {
        strcat(f.workbuf, p->more_data[i]);  
    }

    
    if (looks_like_plaintext((unsigned char *)f.workbuf)) {
        puts("[+] Combined string looks like plaintext.");
    } else {
        puts("[-] Combined string does NOT look like plaintext.");
    }

    
    unsigned long *ptr = (unsigned long *)f.crash_ptr;
    *ptr = 0xdeadbeef;

    
}

int main(void) {
    char json[MAX_JSON_SIZE];
    size_t n = fread(json, 1, sizeof(json) - 1, stdin);
    json[n] = '\0';

    Parsed p;
    parse_json(json, &p);

    puts("Input found");
    dangerous_build_and_crash(&p);

    puts("Done.");
    return 0;
}
