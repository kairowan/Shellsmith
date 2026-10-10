#include "codeitem/multi_dex_code.h"
#include "common/log.h"
#include <cstdint>
#include <cstring>

namespace protector::codeitem {

static uint16_t read_u16(const uint8_t* p) {
    uint16_t v;
    memcpy(&v, p, 2);
    return v;
}

static uint32_t read_u32(const uint8_t* p) {
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}

static void clear_map(std::unordered_map<int, std::unordered_map<uint32_t, CodeItem*>>& out_map) {
    for (auto& dex : out_map) {
        for (auto& kv : dex.second) {
            delete kv.second;
        }
    }
    out_map.clear();
}

static bool add_overflow(size_t a, size_t b, size_t* out) {
    if (a > SIZE_MAX - b) return true;
    *out = a + b;
    return false;
}

bool parse(const uint8_t* data, size_t size,
           std::vector<uint8_t>& owned_blob,
           std::unordered_map<int, std::unordered_map<uint32_t, CodeItem*>>& out_map) {
    if (data == nullptr || size < 4) {
        PLOGE("code.bin too small");
        return false;
    }
    owned_blob.assign(data, data + size);
    uint8_t* buf = owned_blob.data();

    uint16_t version = read_u16(buf);
    uint16_t dex_count = read_u16(buf + 2);
    PLOGI("code.bin version=%u dex_count=%u size=%zu", version, dex_count, size);
    if (version != 2 && version != 3 && version != 4) {
        PLOGE("unsupported code.bin version %u (need 2, 3, or 4)", version);
        return false;
    }
    const bool has_flags = (version >= 3);
    const bool has_dex_number = (version >= 4);
    const size_t method_hdr = has_flags ? 16u : 12u;

    if (dex_count == 0) {
        // Packer may write empty v4 when no methods were hollowed (DEX still encrypted in zip).
        clear_map(out_map);
        PLOGI("code.bin has zero dex blobs (encrypt-only / no hollow)");
        return true;
    }
    if (size < static_cast<size_t>(4 + dex_count * 4)) {
        PLOGE("invalid dex_count");
        return false;
    }

    clear_map(out_map);
    for (uint16_t i = 0; i < dex_count; i++) {
        uint32_t off32 = read_u32(buf + 4 + i * 4);
        size_t off = off32;
        if (off > size || size - off < 2) {
            PLOGE("dex[%u] offset out of range: %u", i, off32);
            clear_map(out_map);
            return false;
        }
        size_t cursor = off;
        uint32_t dex_number = i;
        if (has_dex_number) {
            if (size - cursor < 4 + 2) {
                PLOGE("dex[%u] missing dex_number", i);
                clear_map(out_map);
                return false;
            }
            dex_number = read_u32(buf + cursor);
            cursor += 4;
        }
        uint16_t method_count = read_u16(buf + cursor);
        if (add_overflow(cursor, 2, &cursor)) {
            clear_map(out_map);
            return false;
        }
        auto& method_map = out_map[static_cast<int>(dex_number)];
        for (uint16_t m = 0; m < method_count; m++) {
            size_t need_hdr = 0;
            if (add_overflow(cursor, method_hdr, &need_hdr) || need_hdr > size) {
                PLOGE("dex[%u] method header OOB at %zu", i, cursor);
                clear_map(out_map);
                return false;
            }
            uint32_t method_idx = read_u32(buf + cursor);
            uint32_t plain_size = read_u32(buf + cursor + 4);
            uint32_t enc_size = read_u32(buf + cursor + 8);
            uint32_t flags = has_flags ? read_u32(buf + cursor + 12) : 0;
            cursor = need_hdr;
            size_t need_insns = 0;
            if (add_overflow(cursor, enc_size, &need_insns) || need_insns > size) {
                PLOGE("dex[%u] method enc OOB idx=%u size=%u", i, method_idx, enc_size);
                clear_map(out_map);
                return false;
            }
            if (plain_size == 0 || enc_size < 12 + 16) {
                PLOGE("dex[%u] method bad sizes idx=%u plain=%u enc=%u",
                      i, method_idx, plain_size, enc_size);
                clear_map(out_map);
                return false;
            }
            auto* item = new CodeItem();
            item->method_idx = method_idx;
            item->plain_insns_size = plain_size;
            item->insns_size = enc_size;
            item->flags = flags;
            item->insns = buf + cursor;
            auto it = method_map.find(method_idx);
            if (it != method_map.end()) {
                delete it->second;
                it->second = item;
            } else {
                method_map[method_idx] = item;
            }
            cursor = need_insns;
        }
        PLOGI("dex_number=%u (slot %u) methods loaded: %zu",
              dex_number, i, method_map.size());
    }
    if (out_map.empty()) {
        return false;
    }
    return true;
}

} // namespace protector::codeitem
