#include <stdint.h>
#include <stdio.h>

enum {
    limit = 1000000,
    rounds = 10,
};

static uint8_t composite[limit + 1];

__attribute__((noinline)) static uint64_t sieve(uint8_t mark,
                                                uint32_t *prime_count) {
    for (uint32_t prime = 2; prime <= limit / prime; ++prime) {
        if (composite[prime] == mark) {
            continue;
        }
        for (uint32_t multiple = prime * prime; multiple <= limit;
             multiple += prime) {
            composite[multiple] = mark;
        }
    }

    uint32_t count = 0;
    uint64_t sum = 0;
#pragma clang loop vectorize(disable)
#pragma clang loop interleave(disable)
    for (uint32_t candidate = 2; candidate <= limit; ++candidate) {
        if (composite[candidate] != mark) {
            ++count;
            sum += candidate;
        }
    }
    *prime_count = count;
    return sum;
}

int main(void) {
    uint64_t checksum = 0;
    uint64_t sum = 0;
    uint32_t count = 0;
    for (uint32_t round = 1; round <= rounds; ++round) {
        sum = sieve((uint8_t)round, &count);
        checksum = checksum * UINT64_C(0x9e3779b185ebca87) + sum + count;
    }

    printf("sieve limit=%d rounds=%d primes=%u sum=%llu checksum=%llu\n",
           limit, rounds, count, (unsigned long long)sum,
           (unsigned long long)checksum);
    return count == 78498 && sum == UINT64_C(37550402023) ? 0 : 1;
}
