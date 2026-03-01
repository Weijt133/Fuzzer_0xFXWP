#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#define MAX_JSON   8192
#define MAX_PAIRS  32
#define MAX_KEY    32
#define MAX_VALUE  64

typedef struct {
    char key[MAX_KEY];
    char value[MAX_VALUE];
} KVPair;

typedef struct {
    char assemble[128];       
    unsigned long crash_ptr;  
} Frame;

static void skip_ws(char **p) {
    while (**p && isspace((unsigned char)**p)) {
        (*p)++;
    }
}

static char *find_data_object(char *json) {
    char *p = strstr(json, "\"data\"");
    if (!p) return NULL;

    p = strchr(p, '{');
    if (!p) return NULL;

    
    int depth = 0;
    char *start = NULL;
    for (; *p; p++) {
        if (*p == '{') {
            if (depth == 0) {
                start = p;
            }
            depth++;
        } else if (*p == '}') {
            depth--;
            if (depth == 0 && start) {
                
                *(p + 1) = '\0'; 
                return start;
            }
        }
    }
    return NULL;
}

static int parse_data_pairs(char *obj, KVPair *pairs, int *out_count) {
    char *p = obj;
    int count = 0;

    
    while (*p && *p != '{') p++;
    if (*p == '{') p++;

    while (*p && count < MAX_PAIRS) {
        skip_ws(&p);

        if (*p == '}') {
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
        char *key_start = p;
        char *key_end   = strchr(p, '"');
        if (!key_end) break;

        size_t key_len = (size_t)(key_end - key_start);
        if (key_len >= MAX_KEY) key_len = MAX_KEY - 1;

        memcpy(pairs[count].key, key_start, key_len);
        pairs[count].key[key_len] = '\0';

        p = key_end + 1;

        while (*p && *p != ':') p++;
        if (!*p) break;
        p++; 

        skip_ws(&p);
        
        if (*p != '"') {
            
            pairs[count].value[0] = '\0';
            while (*p && *p != ',' && *p != '}') p++;
            count++;
            continue;
        }

        p++; 
        char *val_start = p;
        char *val_end   = strchr(p, '"');
        if (!val_end) break;

        size_t val_len = (size_t)(val_end - val_start);
        if (val_len >= MAX_VALUE) val_len = MAX_VALUE - 1;

        memcpy(pairs[count].value, val_start, val_len);
        pairs[count].value[val_len] = '\0';

        p = val_end + 1;
        count++;
    }

    *out_count = count;
    return 0;
}

int main(void) {
    char json_buf[MAX_JSON];
    size_t n = fread(json_buf, 1, sizeof(json_buf) - 1, stdin);
    json_buf[n] = '\0';

    KVPair pairs[MAX_PAIRS];
    int pair_count = 0;

    char *data_obj = find_data_object(json_buf);
    if (!data_obj) {
        fprintf(stderr, "[warn] no \"data\" object found\n");
    } else {
        parse_data_pairs(data_obj, pairs, &pair_count);
    }

    unsigned long safe_target = 0x12345678ul;
    Frame f;

    f.crash_ptr = (unsigned long)&safe_target;
    f.assemble[0] = '\0';

    for (int i = 0; i < pair_count; i++) {
        char tmp[128];
        snprintf(tmp, sizeof(tmp), "%s=%s;", pairs[i].key, pairs[i].value);

        
        strcat(f.assemble, tmp);
    }

    printf("looks like you entered something\n");

    
    unsigned long *ptr = (unsigned long *)f.crash_ptr;
    *ptr = 0xdeadbeef;

    
    printf("Yea, I will take it\n");
    return 0;
}
