#ifndef MOCIKA_NATIVE_VMP_H
#define MOCIKA_NATIVE_VMP_H

#include <stddef.h>
#include <stdint.h>

#if defined(__clang__)
#define MOCIKA_VMP __attribute__((annotate("mocika_vmp"), noinline))
#else
#error "Mocika Native VMP requires Clang/LLVM"
#endif

#ifdef __cplusplus
extern "C" {
#endif

uint64_t mocika_vmp_exec_i64(const uint8_t *program,
                             uint32_t program_size,
                             const uint64_t *arguments,
                             uint32_t argument_count,
                             uint32_t *ok);

#ifdef __cplusplus
}
#endif

#endif

