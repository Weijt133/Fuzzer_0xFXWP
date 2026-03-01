#include <stdio.h>
#include <stdlib.h>

#define MAX_NODES 128

typedef struct {
    int has;
    int next;
} Node;

static Node nodes[MAX_NODES];

void deep_walk(int id) {
    int padding[1024];
    for (int i = 0; i < 1024; i++) {
        padding[i] = id;
    }

    if (id < 0 || id >= MAX_NODES) {
        return;
    }
    if (!nodes[id].has) {
        return;
    }

    int next = nodes[id].next;

    if (next == -1) {
        return;
    }

    deep_walk(next);

    padding[0] = id;
}

int main(void) {
    char line[256];
    int start_id = -1;

    while (fgets(line, sizeof(line), stdin)) {
        int id, next;
        if (sscanf(line, "%d,%d", &id, &next) == 2) {
            if (id >= 0 && id < MAX_NODES) {
                nodes[id].has  = 1;
                nodes[id].next = next;
                if (start_id < 0) {
                    start_id = id;
                }
            }
        }
    }

    printf("Let's do a deep walk\n");
    if (start_id < 0) {
        printf("[warn] no valid rows parsed, exiting.\n");
        return 0;
    }


    deep_walk(start_id);

    printf("finished deep_walk without problem.\n");
    return 0;
}

// cat << 'EOF' | ./csv6
// 0,1
// 1,0
// EOF