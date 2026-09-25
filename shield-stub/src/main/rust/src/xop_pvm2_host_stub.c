#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool mocika_xop_pvm2_init(const uint8_t* code, size_t code_len,
                          const uint8_t* key, size_t key_len) {
    (void)code;
    (void)code_len;
    (void)key;
    (void)key_len;
    return false;
}

bool mocika_pas1_decrypt(const uint8_t* key, size_t key_len,
                         const uint8_t* data, size_t data_len,
                         uint8_t* output, size_t output_len) {
    (void)key; (void)key_len; (void)data; (void)data_len; (void)output; (void)output_len;
    return false;
}

bool mocika_aes128_gcm_decrypt(const uint8_t* key, size_t key_len,
                               const uint8_t* data, size_t data_len,
                               uint8_t* output, size_t output_len) {
    (void)key; (void)key_len; (void)data; (void)data_len; (void)output; (void)output_len;
    return false;
}

void* mocika_xop_pvm2_interpret(void* env, int dex_index, int method_index, void* args) {
    (void)env;
    (void)dex_index;
    (void)method_index;
    (void)args;
    return NULL;
}
