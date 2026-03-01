/* csv1000.c — simple, safe CSV reader & summarizer
 */

#include <stdio.h>
#include <string.h>

#define MAX_LINE  1024
#define MAX_COLS  16
#define MAX_FIELD 128

static void trim_newline(char *s) {
    if (!s) return;
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) {
        s[n - 1] = '\0';
        n--;
    }
}

static int split_csv_line(char *line, char fields[][MAX_FIELD], int max_cols) {
    int count = 0;
    char *p = line;
    char *tok;

    trim_newline(p);

    tok = strtok(p, ",");
    while (tok && count < max_cols) {
        strncpy(fields[count], tok, MAX_FIELD - 1);
        fields[count][MAX_FIELD - 1] = '\0';

        count++;
        tok = strtok(NULL, ",");
    }

    return count;
}

int main(void) {
    char line[MAX_LINE];
    char fields[MAX_COLS][MAX_FIELD];
    int row_index = 0;
    int data_rows = 0;

    printf("csv1000 - safe CSV reader\n");

    if (!fgets(line, sizeof(line), stdin)) {
        fprintf(stderr, "[error] no input\n");
        return 1;
    }
    row_index++;
    int header_cols = split_csv_line(line, fields, MAX_COLS);

    printf("[header] row %d has %d column(s):\n", row_index, header_cols);
    for (int i = 0; i < header_cols; i++) {
        printf("  col[%d] = \"%s\"\n", i, fields[i]);
    }

    while (fgets(line, sizeof(line), stdin)) {
        row_index++;
        int cols = split_csv_line(line, fields, MAX_COLS);
        if (cols == 0) {
            continue;
        }
        data_rows++;

        printf("[row %d] %d column(s):", row_index, cols);
        int show = (cols < 4) ? cols : 4;
        for (int i = 0; i < show; i++) {
            printf("  \"%s\"", fields[i]);
        }
        if (cols > show) {
            printf("  ...(and %d more)", cols - show);
        }
        printf("\n");
    }

    printf("[result] total data rows (excluding header): %d\n", data_rows);
    return 0;
}
