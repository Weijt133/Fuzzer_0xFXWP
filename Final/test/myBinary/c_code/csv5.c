#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_LINE   512
#define MAX_ROWS   64
#define MAX_FIELD  64

typedef struct {
    char c1[MAX_FIELD];
    char c2[MAX_FIELD];
    char c3[MAX_FIELD];
    char tag[128]; 
} Row;

typedef struct {
    char buf[64]; 
    unsigned long crash_ptr;
} Frame;

static void trim_newline(char *s) {
    if (!s) return;
    size_t n = strlen(s);
    if (n > 0 && (s[n-1] == '\n' || s[n-1] == '\r')) {
        s[n-1] = '\0';
        if (n > 1 && s[n-2] == '\r')
            s[n-2] = '\0';
    }
}

static int parse_row(const char *line, Row *out) {
    char tmp[MAX_LINE];
    strncpy(tmp, line, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    trim_newline(tmp);

    char *p = tmp;
    char *tok;
    int col = 0;

    tok = strtok(p, ",");
    while (tok && col < 4) {
        switch (col) {
            case 0:
                strncpy(out->c1, tok, sizeof(out->c1) - 1);
                out->c1[sizeof(out->c1) - 1] = '\0';
                break;
            case 1:
                strncpy(out->c2, tok, sizeof(out->c2) - 1);
                out->c2[sizeof(out->c2) - 1] = '\0';
                break;
            case 2:
                strncpy(out->c3, tok, sizeof(out->c3) - 1);
                out->c3[sizeof(out->c3) - 1] = '\0';
                break;
            case 3:
                strncpy(out->tag, tok, sizeof(out->tag) - 1);
                out->tag[sizeof(out->tag) - 1] = '\0';
                break;
        }
        col++;
        tok = strtok(NULL, ",");
    }

    if (col < 4) {
        out->tag[0] = '\0';
    }

    return (col > 0) ? 0 : -1;
}

static void process_rows(Row *rows, int row_count) {
    unsigned long safe_target = 0x12345678ul;
    Frame f;

    f.crash_ptr = (unsigned long)&safe_target;
    f.buf[0] = '\0';

    for (int i = 0; i < row_count; i++) {
        if (rows[i].tag[0] == '\0') {
            continue;
        }

        strcat(f.buf, rows[i].tag); 
        strcat(f.buf, ";");
    }

    printf("CSV5\n");
    printf("input found\n");


    unsigned long *ptr = (unsigned long *)f.crash_ptr;
    *ptr = 0xdeadbeef;

    printf("Nothing big happening here\n");
}

int main(void) {
    char line[MAX_LINE];
    Row rows[MAX_ROWS];
    int row_count = 0;

    if (!fgets(line, sizeof(line), stdin)) {
        fprintf(stderr, "No input.\n");
        return 1;
    }

    while (row_count < MAX_ROWS && fgets(line, sizeof(line), stdin)) {
        if (parse_row(line, &rows[row_count]) == 0) {
            row_count++;
        }
    }

    process_rows(rows, row_count);

    return 0;
}


// header,must,stay,intact
// I,think,this,isaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 
// the,same,as,csv1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
// what,do,you,think