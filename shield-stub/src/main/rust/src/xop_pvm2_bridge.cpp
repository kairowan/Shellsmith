#include "codeitem/multi_dex_code.h"
#include "common/runtime_state.h"
#include "crypto/aes.h"
#include "vm/pvm2_interp.h"
#include "vm/pvm2_format.h"

#include <jni.h>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace protector::risk {

// Mocika owns the process RASP gate. The embedded interpreter only observes the
// shared degraded bit and never starts Xop's second detector/heartbeat lifecycle.
bool vmp_allowed() {
    auto& state = runtime_state();
    return state.inited.load(std::memory_order_acquire)
            && !state.environment_degraded.load(std::memory_order_acquire);
}

void so_guard_check() {}

} // namespace protector::risk

extern "C" bool mocika_xop_pvm2_init(const uint8_t* code, size_t code_len,
                                      const uint8_t* key, size_t key_len) {
    if (code == nullptr || code_len == 0 || key == nullptr || key_len != 16) {
        return false;
    }
    auto& state = protector::runtime_state();
    std::lock_guard<std::mutex> lock(state.mutex);
    state.inited.store(false, std::memory_order_release);
    protector::vm::clear_true_vmp_lru();
    for (auto& dex : state.code_map) {
        for (auto& method : dex.second) {
            delete method.second;
        }
    }
    state.code_map.clear();
    state.code_blob.clear();
    state.config.insns_aes_key.assign(key, key + key_len);
    state.config.vmp_lru = 32;
    state.environment_degraded.store(false, std::memory_order_release);
    if (!protector::codeitem::parse(
                code, code_len, state.code_blob, state.code_map)) {
        state.config.insns_aes_key.clear();
        return false;
    }
    for (const auto& dex : state.code_map) {
        for (const auto& method : dex.second) {
            if (method.second == nullptr || method.second->flags != protector::vm::FLAG_TRUE_VMP) {
                state.config.insns_aes_key.clear();
                return false;
            }
        }
    }
    if (!protector::vm::prepare_true_vmp_images()) {
        state.config.insns_aes_key.clear();
        return false;
    }
    state.inited.store(true, std::memory_order_release);
    return true;
}

extern "C" jobject mocika_xop_pvm2_interpret(JNIEnv* env, jint dex_index,
                                               jint method_index, jobjectArray args) {
    if (env == nullptr) {
        return nullptr;
    }
    return protector::vm::interpret(
            env, dex_index, static_cast<uint32_t>(method_index), args);
}

extern "C" bool mocika_pas1_decrypt(const uint8_t* key, size_t key_len,
                                      const uint8_t* data, size_t data_len,
                                      uint8_t* output, size_t output_len) {
    constexpr size_t overhead = 4 + protector::crypto::GCM_NONCE_LEN
            + protector::crypto::GCM_TAG_LEN;
    if (key == nullptr || key_len != 16 || data == nullptr || data_len < overhead
            || output == nullptr || output_len != data_len - overhead
            || std::memcmp(data, "PAS1", 4) != 0) {
        return false;
    }
    return protector::crypto::aes128_gcm_decrypt(
            key, data + 4, data_len - 4, output, output_len);
}

extern "C" bool mocika_aes128_gcm_decrypt(const uint8_t* key, size_t key_len,
                                             const uint8_t* data, size_t data_len,
                                             uint8_t* output, size_t output_len) {
    constexpr size_t overhead = protector::crypto::GCM_NONCE_LEN
            + protector::crypto::GCM_TAG_LEN;
    if (key == nullptr || key_len != 16 || data == nullptr || data_len < overhead
            || output == nullptr || output_len != data_len - overhead) {
        return false;
    }
    return protector::crypto::aes128_gcm_decrypt(
            key, data, data_len, output, output_len);
}
