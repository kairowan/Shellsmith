#pragma once

#include <cstdint>
#include <vector>
#include <unordered_map>
#include "common/runtime_state.h"

namespace protector::codeitem {

/**
 * Binary format (little-endian):
 *   u16 version (=2, 3, or 4)
 *   u16 dex_count
 *   u32 dex_offsets[dex_count]
 *   for each dex:
 *     [v4] u32 dex_number   // real classesN ordinal (0-based)
 *     u16 method_count
 *     for each method:
 *       u32 method_idx
 *       u32 plain_insns_size
 *       u32 enc_size
 *       [v3+] u32 flags   // bit0 = PVM1, bit1 = TRUE_VMP (PVM2)
 *       u8  enc[enc_size]   // AES-GCM: nonce(12)||ct||tag(16)
 */
bool parse(const uint8_t* data, size_t size,
           std::vector<uint8_t>& owned_blob,
           std::unordered_map<int, std::unordered_map<uint32_t, CodeItem*>>& out_map);

} // namespace protector::codeitem
