/* json1000.c — simple, safe JSON-like key/value summarizer
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define MAX_JSON   8192
#define MAX_PAIRS  32
#define MAX_KEY    64
#define MAX_VALUE  64

typedef struct {
    char key[MAX_KEY];
    char value[MAX_VALUE];
} KVPair;

static void skip_ws(const char **p) {
    while (**p && isspace((unsigned char)**p)) {
        (*p)++;
    }
}

static int parse_pairs(const char *json, KVPair *pairs, int max_pairs) {
    const char *p = json;
    int count = 0;

    while (*p && count < max_pairs) {
        const char *key_start = strchr(p, '\"');
        if (!key_start) break;

        const char *key_end = strchr(key_start + 1, '\"');
        if (!key_end) break;

        const char *colon = strchr(key_end + 1, ':');
        if (!colon) {
            p = key_end + 1;
            continue;
        }

        size_t key_len = (size_t)(key_end - (key_start + 1));
        if (key_len >= MAX_KEY) key_len = MAX_KEY - 1;
        memcpy(pairs[count].key, key_start + 1, key_len);
        pairs[count].key[key_len] = '\0';

        const char *v = colon + 1;
        skip_ws(&v);

        if (*v == '\"') {
            const char *vs = v + 1;
            const char *ve = strchr(vs, '\"');
            if (!ve) ve = vs; 
            size_t val_len = (size_t)(ve - vs);
            if (val_len >= MAX_VALUE) val_len = MAX_VALUE - 1;
            memcpy(pairs[count].value, vs, val_len);
            pairs[count].value[val_len] = '\0';
            p = ve + 1;
        } else {
            const char *vs = v;
            while (*v && !isspace((unsigned char)*v) && *v != ',' && *v != '}') {
                v++;
            }
            size_t val_len = (size_t)(v - vs);
            if (val_len >= MAX_VALUE) val_len = MAX_VALUE - 1;
            memcpy(pairs[count].value, vs, val_len);
            pairs[count].value[val_len] = '\0';
            p = v;
        }

        count++;
    }

    return count;
}

int main(void) {
    char json[MAX_JSON];
    size_t n = fread(json, 1, sizeof(json) - 1, stdin);
    json[n] = '\0';

    KVPair pairs[MAX_PAIRS];
    int pair_count = parse_pairs(json, pairs, MAX_PAIRS);

    printf("json1000 - safe key/value summarizer\n");
    printf("[debug] bytes_read = %zu\n", n);
    printf("[debug] parsed %d key/value pairs (up to max %d)\n",
           pair_count, MAX_PAIRS);

    for (int i = 0; i < pair_count; i++) {
        printf("pair[%d]: key=\"%s\"  value=\"%s\"\n", i, pairs[i].key, pairs[i].value);
    }

    if (pair_count == 0) {
        printf("[result] No simple \"key\": value pairs found.\n");
    } else {
        printf("[result] Parsed %d pair(s).\n", pair_count);
    }

    return 0;
}
