#include "mocika_native_vmp.h"

MOCIKA_VMP int unsupported_pointer_load(const int *value) {
    return *value + 1;
}

