#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#define MAX_JSON      8192
#define MAX_CHUNKS    32
#define MAX_CHUNK_LEN 128

typedef struct {
    int  total_len;
    char chunks[MAX_CHUNKS][MAX_CHUNK_LEN];
    int  num_chunks;
} Parsed;

typedef struct {
    char buf[64];           
    unsigned long crash_ptr; 
} Frame;

static void skip_ws(char **p) {
    while (**p && isspace((unsigned char)**p)) {
        (*p)++;
    }
}

static int parse_int_field(const char *json, const char *field_name, int *out) {
    char *p = strstr((char *)json, field_name);
    if (!p) return -1;

    p = strchr(p, ':');
    if (!p) return -1;
    p++;

    skip_ws(&p);
    *out = atoi(p);
    return 0;
}

static int parse_chunks_array(const char *json, Parsed *out) {
    char *p = strstr((char *)json, "\"chunks\"");
    if (!p) {
        out->num_chunks = 0;
        return 0;  
    }

    p = strchr(p, '[');
    if (!p) {
        out->num_chunks = 0;
        return -1;
    }
    p++; 

    int count = 0;

    while (*p && count < MAX_CHUNKS) {
        skip_ws(&p);

        if (*p == ']') {
            break;
        }

        if (*p == ',') {
            p++;
            continue;
        }

        if (*p != '"') {
            p++;
            continue;
        }

        p++; 
        char *start = p;
        char *end   = strchr(p, '"');
        if (!end) break;

        size_t n = (size_t)(end - start);
        if (n >= MAX_CHUNK_LEN) n = MAX_CHUNK_LEN - 1;

        memcpy(out->chunks[count], start, n);
        out->chunks[count][n] = '\0';

        count++;
        p = end + 1;
    }

    out->num_chunks = count;
    return 0;
}

static void parse_json(const char *json, Parsed *out) {
    memset(out, 0, sizeof(*out));

    if (parse_int_field(json, "\"total_len\"", &out->total_len) != 0) {
        fprintf(stderr, "[warn] could not parse total_len, default 0\n");
        out->total_len = 0;
    }

    parse_chunks_array(json, out);
}

static void process(const Parsed *p) {
    unsigned long safe_target = 0x12345678ul;
    Frame f;

    f.crash_ptr = (unsigned long)&safe_target;
    memset(f.buf, 0, sizeof(f.buf));

    char combined[1024];
    memset(combined, 0, sizeof(combined));

    
    for (int i = 0; i < p->num_chunks; i++) {
        size_t cur_len = strlen(combined);
        size_t remain  = sizeof(combined) - cur_len - 1;

        strncat(combined, p->chunks[i], remain);
    }

    size_t actual_len = strlen(combined);

    
    size_t copy_len = 0;
    if (p->total_len > 0) {
        copy_len = (size_t)p->total_len;
    }

    printf("JSON7 total-length\n");
 

    if (copy_len > 0) {
        
        memcpy(f.buf, combined, copy_len);
    }

    printf("looks like you entered something \n", f.crash_ptr);

    
    unsigned long *ptr = (unsigned long *)f.crash_ptr;
    *ptr = 0xdeadbeef;

    printf("Thank you for your input \n", safe_target);
}

int main(void) {
    char json[MAX_JSON];
    size_t n = fread(json, 1, sizeof(json) - 1, stdin);
    json[n] = '\0';

    Parsed p;
    parse_json(json, &p);

    process(&p);

    return 0;
}
