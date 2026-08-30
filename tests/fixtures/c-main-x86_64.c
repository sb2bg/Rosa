#include <stdint.h>

int main(int argc, char **argv) {
    if (argc != 3 || argv == 0 || argv[1] == 0 || argv[2] == 0 ||
        argv[1][0] != 'r' || argv[2][0] != 'j') {
        return 1;
    }

    uint64_t value = (uint64_t)(argc - 3);
    do {
        ++value;
        // Keep the loop visible to the optimizer while requiring no runtime
        // support or guest-memory access.
        __asm__ volatile("" : "+r"(value));
    } while (value != 20000000);

    return value == 20000000 ? 42 : 1;
}
