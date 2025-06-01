#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define MAX_LINE 512

void disable_kptr_restrict() {
    FILE *f = fopen("/proc/sys/kernel/kptr_restrict", "w");
    if (f == NULL) {
        perror("Failed to open /proc/sys/kernel/kptr_restrict (permission denied?)");
        return;
    }
    if (fprintf(f, "0\n") < 0) {
        perror("Failed to write to /proc/sys/kernel/kptr_restrict");
    } else {
        printf("[+] kptr_restrict temporarily disabled.\n");
    }
    fclose(f);
}

void find_address(const char *func) {
    FILE *file = fopen("/proc/kallsyms", "r");
    if (!file) {
        perror("Failed to open /proc/kallsyms");
        return;
    }

    char line[MAX_LINE];
    int found = 0;

    while (fgets(line, sizeof(line), file)) {
        unsigned long addr;
        char type;
        char name[256];

        if (sscanf(line, "%lx %c %s", &addr, &type, name) == 3) {
            if (strcmp(name, func) == 0) {
                printf("Function: %-20s Address: 0x%lx\n", func, addr);
                found = 1;
                break;
            }
        }
    }

    if (!found) {
        printf("Function: %-20s not found.\n", func);
    }

    fclose(file);
}

int main(int argc, char *argv[]) {
    printf("Sysmk 0.1v\n");
    if (argc != 2) {
        printf("Usage: %s <function_name>\n", argv[0]);
        return 1;
    }

    const char *func = argv[1];

    printf("[*] Trying to disable kptr_restrict...\n");
    disable_kptr_restrict();

    printf("[*] Searching for '%s'...\n", func);
    find_address(func);

    return 0;
}
