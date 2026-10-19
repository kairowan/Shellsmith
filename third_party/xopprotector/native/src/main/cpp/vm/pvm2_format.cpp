#include "vm/pvm2_format.h"
#include "common/log.h"
#include "common/secure_memory.h"

#include <algorithm>
#include <cstring>

namespace protector::vm {

Pvm2Image::~Pvm2Image() { wipe(); }

void Pvm2Image::wipe() noexcept {
    for (auto* pool : {&strings, &methods, &fields, &types}) {
        for (auto& value : *pool) secure_wipe(value.data(), value.size());
        std::vector<std::string>().swap(*pool);
    }
    wipe_vector(code);
    wipe_vector(reg_map);
    wipe_vector(argument_types);
    wipe_vector(handlers);
    secure_wipe(inv_map.data(), inv_map.size());
    secure_wipe(&imm_key, sizeof(imm_key));
    valid = false;
    clear_after_use = false;
}

size_t Pvm2Image::plaintext_bytes() const noexcept {
    size_t bytes = sizeof(*this) + code.capacity() + reg_map.capacity() + argument_types.capacity()
            + handlers.capacity() * sizeof(Pvm2Handler);
    for (const auto* pool : {&strings, &methods, &fields, &types}) {
        bytes += pool->capacity() * sizeof(std::string);
        for (const auto& value : *pool) bytes += value.capacity() + 1;
    }
    // 包含字符串内联存储的保守重复计数；不代表进程 RSS 或分配器元数据。
    return bytes;
}

static uint16_t read_u16(const uint8_t* p) {
    uint16_t v;
    memcpy(&v, p, 2);
    return v;
}

static bool read_string_pool(const uint8_t* data, size_t size, size_t* cursor,
                             uint16_t count, std::vector<std::string>* out) {
    out->clear();
    out->reserve(count);
    for (uint16_t i = 0; i < count; i++) {
        if (*cursor + 2 > size) {
            return false;
        }
        uint16_t len = read_u16(data + *cursor);
        *cursor += 2;
        if (*cursor + len > size) {
            return false;
        }
        out->emplace_back(reinterpret_cast<const char*>(data + *cursor), len);
        *cursor += len;
    }
    return true;
}

static bool read_index_pool(const uint8_t* data, size_t size, size_t* cursor,
                            uint16_t count, const std::vector<std::string>& strings,
                            std::vector<std::string>* out) {
    out->clear();
    out->reserve(count);
    for (uint16_t i = 0; i < count; i++) {
        if (*cursor + 2 > size) {
            return false;
        }
        uint16_t idx = read_u16(data + *cursor);
        *cursor += 2;
        if (idx >= strings.size()) {
            PLOGE("PVM2 pool idx OOB %u >= %zu", idx, strings.size());
            return false;
        }
        out->push_back(strings[idx]);
    }
    return true;
}

static void set_identity_map(Pvm2Image* out) {
    out->has_morph = false;
    out->isa_id = 0;
    out->imm_key = 0;
    out->scratch_extra = 1;
    for (int i = 0; i < 256; i++) {
        out->inv_map[static_cast<size_t>(i)] = static_cast<uint8_t>(i);
    }
}

bool parse_pvm2(const uint8_t* data, size_t size, Pvm2Image* out) {
    if (out == nullptr) return false;
    out->wipe();
    // 所有失败出口（含已填充部分池）都清理；成功由 CodeItem 生命周期接管。
    struct ParseCleanup {
        Pvm2Image* image;
        ~ParseCleanup() { if (!image->valid) image->wipe(); }
    } cleanup{out};
    if (data == nullptr || size < 18) return false;
    set_identity_map(out);

    if (memcmp(data, "PVM2", 4) != 0) {
        PLOGE("PVM2 bad magic");
        return false;
    }

    out->version = read_u16(data + 4);
    out->reg_count = read_u16(data + 6);
    out->ins_size = read_u16(data + 8);
    out->handler_count = read_u16(data + 10);
    out->code_size = read_u16(data + 12);
    out->ret_kind = data[14];
    out->isa_id = data[15];
    uint16_t str_count = read_u16(data + 16);

    if (out->version != PVM2_VERSION_V1 && out->version != PVM2_VERSION_V2
            && out->version != PVM2_VERSION_V3 && out->version != PVM2_VERSION_V4
            && out->version != PVM2_VERSION_V5 && out->version != PVM2_VERSION_V6
            && out->version != PVM2_VERSION_V7 && out->version != PVM2_VERSION_V8 && out->version != PVM2_VERSION_V9) {
        PLOGE("PVM2 unsupported version %u", out->version);
        return false;
    }
    if (out->reg_count == 0 || out->reg_count > 256) {
        PLOGE("PVM2 bad reg_count %u", out->reg_count);
        return false;
    }
    if (out->version >= PVM2_VERSION_V3 && out->isa_id >= PVM2_ISA_COUNT) {
        PLOGE("PVM2 bad isa_id %u", out->isa_id);
        return false;
    }
    if (out->version < PVM2_VERSION_V2) {
        out->scratch_extra = 0;
    } else if (out->version < PVM2_VERSION_V5) {
        out->scratch_extra = 1;
    }

    size_t cursor = 18;
    if (out->version >= PVM2_VERSION_V7) {
        if (cursor >= size || data[cursor] > 1) return false;
        out->clear_after_use = data[cursor++] == 1;
    }
    if (!read_string_pool(data, size, &cursor, str_count, &out->strings)) {
        PLOGE("PVM2 strings truncated");
        return false;
    }

    if (out->version >= PVM2_VERSION_V2) {
        if (cursor + 2 > size) {
            return false;
        }
        uint16_t method_count = read_u16(data + cursor);
        cursor += 2;
        if (!read_index_pool(data, size, &cursor, method_count, out->strings, &out->methods)) {
            PLOGE("PVM2 method pool truncated");
            return false;
        }

        if (cursor + 2 > size) {
            return false;
        }
        uint16_t field_count = read_u16(data + cursor);
        cursor += 2;
        if (!read_index_pool(data, size, &cursor, field_count, out->strings, &out->fields)) {
            PLOGE("PVM2 field pool truncated");
            return false;
        }

        if (cursor + 2 > size) {
            return false;
        }
        uint16_t type_count = read_u16(data + cursor);
        cursor += 2;
        if (!read_index_pool(data, size, &cursor, type_count, out->strings, &out->types)) {
            PLOGE("PVM2 type pool truncated");
            return false;
        }

        if (out->version >= PVM2_VERSION_V3) {
            if (cursor + 1 > size) {
                return false;
            }
            uint8_t op_count = data[cursor++];
            // v3 morph tables are 40 ops; v4+ use PVM2_OP_COUNT (50).
            bool op_count_ok = (op_count == PVM2_OP_COUNT_V3 || op_count == PVM2_OP_COUNT);
            if (!op_count_ok || cursor + op_count > size) {
                PLOGE("PVM2 bad morph table op_count=%u", op_count);
                return false;
            }
            for (int i = 0; i < 256; i++) {
                out->inv_map[static_cast<size_t>(i)] = 0xFF;
            }
            for (uint8_t canonical = 0; canonical < op_count; canonical++) {
                uint8_t wire = data[cursor + canonical];
                if (out->inv_map[wire] != 0xFF) {
                    PLOGE("PVM2 morph collision wire=%u", wire);
                    return false;
                }
                out->inv_map[wire] = canonical;
            }
            cursor += op_count;
            out->has_morph = true;
            if (out->version >= PVM2_VERSION_V5) {
                if (cursor + 5 > size) {
                    PLOGE("PVM2 v5 morph extras truncated");
                    return false;
                }
                out->scratch_extra = data[cursor++];
                if (out->scratch_extra < 1 || out->scratch_extra > 3) {
                    PLOGE("PVM2 bad scratch_extra %u", out->scratch_extra);
                    return false;
                }
                int32_t key;
                memcpy(&key, data + cursor, 4);
                cursor += 4;
                out->imm_key = key;
                if (out->version >= PVM2_VERSION_V6) {
                    if (cursor + 1 > size) {
                        PLOGE("PVM2 v6 register map truncated");
                        return false;
                    }
                    uint8_t reg_map_count = data[cursor++];
                    if (reg_map_count != out->reg_count || cursor + reg_map_count > size) {
                        PLOGE("PVM2 bad register map count=%u regs=%u",
                              reg_map_count, out->reg_count);
                        return false;
                    }
                    std::array<bool, 256> seen{};
                    out->reg_map.assign(data + cursor, data + cursor + reg_map_count);
                    cursor += reg_map_count;
                    for (uint8_t physical : out->reg_map) {
                        if (physical >= out->reg_count || seen[physical]) {
                            PLOGE("PVM2 invalid register permutation");
                            return false;
                        }
                        seen[physical] = true;
                    }
                }
            }
        }

        if (out->version >= PVM2_VERSION_V8) {
            if (cursor >= size) return false;
            uint8_t count = data[cursor++];
            if (count > size - cursor) return false;
            out->argument_types.assign(data + cursor, data + cursor + count);
            cursor += count;
            unsigned slots = 0;
            for (uint8_t kind : out->argument_types) {
                if (kind != 'I' && kind != 'J' && kind != 'Z' && kind != 'F' && kind != 'D' && kind != 'L') return false;
                slots += kind == 'J' || kind == 'D' ? 2 : 1;
            }
            if (slots != out->ins_size || slots + out->scratch_extra > out->reg_count) return false;
        }

        out->handlers.resize(out->handler_count);
        std::vector<bool> seen_priorities(out->handler_count, false);
        for (uint16_t i = 0; i < out->handler_count; i++) {
            const size_t handler_size = out->version >= PVM2_VERSION_V6 ? 10u : 8u;
            if (cursor + handler_size > size) {
                PLOGE("PVM2 handlers truncated");
                return false;
            }
            Pvm2Handler h;
            h.start = read_u16(data + cursor);
            h.end = read_u16(data + cursor + 2);
            h.handler_pc = read_u16(data + cursor + 4);
            h.catch_type_idx = read_u16(data + cursor + 6);
            if (out->version >= PVM2_VERSION_V6) {
                uint16_t priority = read_u16(data + cursor + 8);
                if (priority >= out->handler_count || seen_priorities[priority]) {
                    PLOGE("PVM2 bad handler priority %u", priority);
                    return false;
                }
                seen_priorities[priority] = true;
                out->handlers[priority] = h;
            } else {
                out->handlers[i] = h;
            }
            cursor += handler_size;
        }
    } else if (out->handler_count != 0) {
        PLOGE("PVM2 v1 unexpected handler_count %u", out->handler_count);
        return false;
    }

    if (cursor + out->code_size != size) {
        PLOGE("PVM2 code truncated");
        return false;
    }
    out->code.assign(data + cursor, data + cursor + out->code_size);
    out->valid = true;
    return true;
}

} // namespace protector::vm
