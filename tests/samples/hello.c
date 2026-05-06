#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int check_code(const char *value) {
    int sum = 0;
    for (size_t i = 0; value[i] != '\0'; i++) {
        sum += (unsigned char)value[i] * (int)(i + 3);
    }
    return sum == 1416;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        puts("usage: hello <code>");
        return 2;
    }
    if (check_code(argv[1])) {
        puts("ok");
        return 0;
    }
    puts("nope");
    return 1;
}

