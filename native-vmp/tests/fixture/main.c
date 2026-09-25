#include "mocika_native_vmp.h"

#include <stdint.h>
#include <stdio.h>

MOCIKA_VMP static int32_t protected_score(int32_t value, int32_t rounds) {
    int32_t result = value;
    for (int32_t i = 0; i < rounds; ++i) {
        result = (result * 13 + i) ^ (result >> 3);
    }
    return result;
}

static int32_t reference_score(int32_t value, int32_t rounds) {
    int32_t result = value;
    for (int32_t i = 0; i < rounds; ++i) {
        result = (result * 13 + i) ^ (result >> 3);
    }
    return result;
}

int main(void) {
    for (int32_t value = 1; value < 40; ++value) {
        for (int32_t rounds = 0; rounds < 12; ++rounds) {
            if (protected_score(value, rounds) != reference_score(value, rounds)) {
                return 1;
            }
        }
    }
    puts("Mocika Native VMP self-test passed");
    return 0;
}
