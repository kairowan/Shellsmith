// 直接编译生产解释器，覆盖缓存内部竞争；不以宿主占位实现代替 Native 检查。
#include "common/protector_macro.h"
// 宿主 Mach-O 无 Android ELF section，其他生产代码保持原样。
#undef PROTECTOR_ENCRYPT
#define PROTECTOR_ENCRYPT
#include "vm/pvm2_interp.cpp"
#include "codeitem/multi_dex_code.h"
#include <cassert>
#include <cstdio>
#include <thread>
#include <barrier>
#include <fstream>
#include <iterator>
#include <algorithm>

extern "C" bool mocika_xop_pvm2_init(const uint8_t*, size_t, const uint8_t*, size_t);
extern "C" void mocika_xop_pvm2_block();
using namespace protector;
using namespace protector::vm;

static void u16(std::vector<uint8_t>& v, uint16_t n) { v.push_back(n); v.push_back(n >> 8); }
static void u32(std::vector<uint8_t>& v, uint32_t n) { u16(v, n); u16(v, n >> 16); }

static std::vector<uint8_t> image(bool large = false) {
    std::vector<uint8_t> v{'P','V','M','2'};
    u16(v, 1); u16(v, 1); u16(v, 0); u16(v, 0); u16(v, 8);
    v.push_back(RET_I); v.push_back(0); u16(v, large ? 150 : 0);
    if (large) for (int i = 0; i < 150; i++) { u16(v, 60000); v.insert(v.end(), 60000, 'x'); }
    v.push_back(OP_CONST); v.push_back(0); u32(v, 42); v.push_back(OP_RETURN); v.push_back(0);
    return v;
}

static std::vector<uint8_t> record(const std::vector<uint8_t>& plain, const uint8_t* key, int nonce_id) {
    uint8_t nonce[12]{}; nonce[0] = nonce_id; nonce[1] = nonce_id >> 8;
    std::vector<uint8_t> enc(plain.size() + 28);
    size_t written = 0;
    assert(crypto::aes128_gcm_encrypt(key, nonce, plain.data(), plain.size(), enc.data(), enc.size(), &written));
    assert(written == enc.size());
    return enc;
}

static void check_aes_vectors(const std::string& directory) {
    std::ifstream input(directory + "/aes-vectors.bin", std::ios::binary);
    assert(input);
    for (int i = 0; i < 73; i++) {
        uint8_t key[16], size[4];
        input.read(reinterpret_cast<char*>(key), 16);
        input.read(reinterpret_cast<char*>(size), 4);
        size_t length = (uint32_t(size[0]) << 24) | (uint32_t(size[1]) << 16) | (uint32_t(size[2]) << 8) | size[3];
        assert(input && length <= 4097);
        std::vector<uint8_t> plain(length + 1), enc(length + 28), decoded(length + 1, 0xa5), encoded(length + 28);
        input.read(reinterpret_cast<char*>(plain.data()), length);
        input.read(reinterpret_cast<char*>(enc.data()), enc.size()); assert(input);
        assert(crypto::aes128_gcm_decrypt(key, enc.data(), enc.size(), decoded.data(), length));
        assert(!memcmp(plain.data(), decoded.data(), length) && decoded[length] == 0xa5);
        size_t written = 0;
        assert(crypto::aes128_gcm_encrypt(key, enc.data(), plain.data(), length, encoded.data(), encoded.size(), &written));
        assert(written == enc.size() && encoded == enc);
        std::vector<uint8_t> ctr(length + 1, 0xa5), ctr_expected(length);
        input.read(reinterpret_cast<char*>(ctr_expected.data()), length); assert(input);
        crypto::aes128_ctr_crypt(key, plain.data(), ctr.data(), length);
        assert(std::equal(ctr_expected.begin(), ctr_expected.end(), ctr.begin()) && ctr[length] == 0xa5);
        crypto::aes128_ctr_crypt(key, ctr.data(), ctr.data(), length);
        assert(!memcmp(ctr.data(), plain.data(), length) && ctr[length] == 0xa5);
        auto inplace = enc;
        assert(crypto::aes128_gcm_decrypt(key, inplace.data(), inplace.size(), inplace.data() + 12, length));
        assert(!memcmp(inplace.data() + 12, plain.data(), length));
        for (size_t changed : {size_t(0), size_t(12), enc.size() - 1}) {
            auto broken = enc; broken[changed] ^= 1;
            std::fill(decoded.begin(), decoded.end(), 0xa5);
            assert(!crypto::aes128_gcm_decrypt(key, broken.data(), broken.size(), decoded.data(), length));
            assert(std::all_of(decoded.begin(), decoded.end(), [](uint8_t c) { return c == 0xa5; }));
        }
        key[0] ^= 1;
        assert(!crypto::aes128_gcm_decrypt(key, enc.data(), enc.size(), decoded.data(), length));
        assert(std::all_of(decoded.begin(), decoded.end(), [](uint8_t c) { return c == 0xa5; }));
    }
    assert(input.peek() == std::ifstream::traits_type::eof());
    puts("AES-GCM/CTR：73 组独立 JCE 向量、空输入/分块边界、原地处理、认证失败不写输出通过");
}

int main(int argc, char** argv) {
    assert(crypto::aes_self_test());
    if (argc > 1 && std::string(argv[1]) != "block-before-init") check_aes_vectors(argv[1]);
    uint8_t key[16]{};
    uint8_t boundary[32]; memset(boundary, 0xa5, sizeof(boundary));
    size_t written = 123;
    assert(!crypto::aes128_gcm_decrypt(nullptr, boundary, 28, boundary, 0));
    assert(!crypto::aes128_gcm_encrypt(key, key, boundary, SIZE_MAX, boundary, sizeof(boundary), &written));
    assert(!crypto::aes128_gcm_encrypt(key, key, boundary, 5, boundary, sizeof(boundary), &written));
    assert(!crypto::aes128_gcm_encrypt(key, key, boundary, 0, boundary, 27, &written));
    assert(written == 123 && std::all_of(std::begin(boundary), std::end(boundary), [](uint8_t c) { return c == 0xa5; }));
    const auto plain = image();
    std::vector<uint8_t> code;
    u16(code, 4); u16(code, 1); u32(code, 8); u32(code, 2); u16(code, argc > 1 && std::string(argv[1]) != "block-before-init" ? 188 : 98);
    for (int i = 0; i < (argc > 1 && std::string(argv[1]) != "block-before-init" ? 188 : 98); i++) {
        auto bytes = plain;
        if (i >= 98) {
            std::ifstream input(std::string(argv[1]) + "/image" + std::to_string(i - 98) + ".bin", std::ios::binary);
            bytes.assign(std::istreambuf_iterator<char>(input), {});
            assert(bytes.size() > 18 && bytes[4] == PVM2_VERSION_V9 && bytes[15] == (i - 98) % 3 && bytes[18] == (i >= 101 ? 1 : 0));
        }
        if (i == 97) { bytes[16] = 1; } // 认证成功、字符串池截断
        auto enc = record(bytes, key, i);
        if (i >= 98) {
            std::ifstream input(std::string(argv[1]) + "/image" + std::to_string(i - 98) + ".gcm", std::ios::binary);
            enc.assign(std::istreambuf_iterator<char>(input), {});
            assert(enc.size() == bytes.size() + 28);
        }
        if (i == 96) enc.back() ^= 1; // 认证失败
        u32(code, i); u32(code, bytes.size()); u32(code, enc.size()); u32(code, FLAG_TRUE_VMP);
        code.insert(code.end(), enc.begin(), enc.end());
    }
    if (argc > 1 && std::string(argv[1]) == "block-before-init") {
        mocika_xop_pvm2_block();
        assert(!mocika_xop_pvm2_init(code.data(), code.size(), key, 16));
        assert(!runtime_state().inited);
        puts("初始化前阻断不可恢复：通过");
        return 0;
    }
    // 容器拒绝重叠偏移、重复索引、尾部数据、伪造明文长度。
    for (int fault = 0; fault < 4; fault++) {
        auto broken = code;
        if (fault == 0) broken[4] = 7;
        if (fault == 1) broken[14 + 16 + plain.size() + 28] = 0;
        if (fault == 2) broken.push_back(0);
        if (fault == 3) broken[18] ^= 1;
        assert(!mocika_xop_pvm2_init(broken.data(), broken.size(), key, 16));
        assert(runtime_state().code_map.empty());
        assert(runtime_state().config.insns_aes_key.empty());
    }
    assert(mocika_xop_pvm2_init(code.data(), code.size(), key, 16));
    auto& items = runtime_state().code_map.at(2);
    CodeItem* first = items.at(0);
    {
        VmpUsePin pin, recursive;
        assert(acquire_vmp(first, pin));
        assert(acquire_vmp(first, recursive));
        assert(first->vm_image.empty() && first->vm_image.capacity() == 0);
        assert(first->parsed_vm->code[0] == OP_CONST);
        clear_true_vmp_lru();
        assert(true_vmp_cache_stats().pins == 2);
        assert(mocika_xop_pvm2_init(code.data(), code.size(), key, 16));
        auto changed = code; changed.back() ^= 1;
        assert(!mocika_xop_pvm2_init(changed.data(), changed.size(), key, 16));
        assert(items.at(0) == first);
    }
    for (int i : {96, 97}) {
        VmpUsePin pin;
        assert(!acquire_vmp(items.at(i), pin));
        assert(items.at(i)->vm_image.capacity() == 0 && !items.at(i)->parsed_vm);
    }
    Pvm2Image parsed;
    auto bad = plain; bad.push_back(0);
    assert(parse_pvm2(plain.data(), plain.size(), &parsed));
    assert(!parse_pvm2(bad.data(), bad.size(), &parsed));
    assert(!parsed.valid && parsed.code.capacity() == 0 && parsed.strings.capacity() == 0);

    // 全部方法同时在用时允许临时超限，归还后必须恢复到上限。
    std::vector<std::unique_ptr<VmpUsePin>> pins;
    for (int i = 0; i < 96; i++) {
        auto pin = std::make_unique<VmpUsePin>();
        assert(acquire_vmp(items.at(i), *pin)); pins.push_back(std::move(pin));
    }
    assert(true_vmp_cache_stats().images == 96);
    pins.clear();
    assert(true_vmp_cache_stats().images <= 32);
    // 大方法超过字节预算时，最后一次归还立即清理。
    auto large = image(true);
    auto encrypted = record(large, key, 100);
    CodeItem big;
    big.insns = encrypted.data(); big.insns_size = encrypted.size(); big.plain_insns_size = large.size();
    { VmpUsePin pin; assert(acquire_vmp(&big, pin)); assert(true_vmp_cache_stats().bytes > VMP_CACHE_BYTES); }
    assert(!big.parsed_vm && big.vm_image.capacity() == 0);
    assert(true_vmp_cache_stats().bytes <= VMP_CACHE_BYTES);

    std::vector<std::thread> threads;
    for (int t = 0; t < 8; t++) threads.emplace_back([&, t] {
        for (int i = 0; i < 1000; i++) {
            VmpUsePin pin;
            CodeItem* item = items.at((i * 17 + t) % 96);
            assert(acquire_vmp(item, pin));
            std::this_thread::yield();
            assert(item->parsed_vm->valid && item->parsed_vm->code[2] == 42);
            if (i % 23 == 0) clear_true_vmp_lru();
        }
    });
    for (auto& thread : threads) thread.join();
    assert(true_vmp_cache_stats().images <= 32 && true_vmp_cache_stats().pins == 0);

    // 宿主 JVM 实际 JNI 返回值与错误路径；不等同于 Android ART 设备验收。
    JavaVM* jvm = nullptr; JNIEnv* env = nullptr;
    JavaVMOption options[] = {{const_cast<char*>("-Xmx128m"), nullptr},
            {const_cast<char*>("-XX:-UseCompressedOops"), nullptr},
            {const_cast<char*>("-XX:-UseCompressedClassPointers"), nullptr}};
    JavaVMInitArgs args{}; args.version = JNI_VERSION_1_6; args.nOptions = 3; args.options = options;
    assert(JNI_CreateJavaVM(&jvm, reinterpret_cast<void**>(&env), &args) == JNI_OK);
    jobject result = interpret(env, 2, 0, nullptr);
    assert(result && !env->ExceptionCheck());
#if defined(MOCIKA_PVM2_PROFILE)
    assert(g_pvm2_profile == nullptr);
    const auto& profiled = g_pvm2_profile_sums.at(uint64_t(2) << 32);
    assert(profiled.calls == 1 && profiled.times.total >= profiled.times.execute);
    assert(profiled.times.acquire >= profiled.times.decrypt + profiled.times.parse);
    {
        Pvm2ProfileCall outer(2, 1000);
        auto* previous = g_pvm2_profile;
        { Pvm2ProfileCall nested(2, 1001); assert(g_pvm2_profile != previous); }
        assert(g_pvm2_profile == previous);
    }
    assert(g_pvm2_profile == nullptr);
#endif
    jclass integer = env->FindClass("java/lang/Integer");
    assert(env->CallIntMethod(result, env->GetMethodID(integer, "intValue", "()I")) == 42);
    env->DeleteLocalRef(result);
    for (int i = 98; i < 101; i++) {
        result = interpret(env, 2, i, nullptr);
        assert(result && !env->ExceptionCheck());
        assert(env->CallIntMethod(result, env->GetMethodID(integer, "intValue", "()I")) == 42);
        env->DeleteLocalRef(result);
    }
    // 普通方法保留缓存，必保方法在 JNI 正常返回和抛异常时都必须清理。
    for (int i = 98; i < 101; i++) assert(items.at(i)->parsed_vm);
    for (int i = 101; i < 107; i++) {
        for (int invocation = 0; invocation < 2; invocation++) {
            result = interpret(env, 2, i, nullptr);
            if (i < 104) {
                assert(result && !env->ExceptionCheck());
                assert(env->CallIntMethod(result, env->GetMethodID(integer, "intValue", "()I")) == 42);
                env->DeleteLocalRef(result);
            } else {
                assert(!result && env->ExceptionCheck()); env->ExceptionClear();
            }
            assert(!items.at(i)->parsed_vm && items.at(i)->vm_image.capacity() == 0);
            assert(g_vmp_lru.pos.count(items.at(i)) == 0);
        }
    }
#if defined(MOCIKA_PVM2_PROFILE)
    const auto& required_profile = g_pvm2_profile_sums.at((uint64_t(2) << 32) | 101);
    assert(required_profile.calls == 2 && required_profile.times.decrypt > 0
            && required_profile.times.parse > 0 && required_profile.times.release > 0);
    assert(required_profile.times.total >= required_profile.times.acquire
            + required_profile.times.execute + required_profile.times.release);
#endif
    // 六种比较、两种控制流、三种 ISA；独立按 C++ 比较结果核对整数边界。
    const int values[] = {INT32_MIN, -1, 0, 1, INT32_MAX};
    jmethodID box = env->GetStaticMethodID(integer, "valueOf", "(I)Ljava/lang/Integer;");
    jmethodID unbox = env->GetMethodID(integer, "intValue", "()I");
    jobjectArray parameters = env->NewObjectArray(2, integer, nullptr);
    for (int i = 107; i < 143; i++) for (int a : values) for (int b : values) {
        jobject left = env->CallStaticObjectMethod(integer, box, a);
        jobject right = env->CallStaticObjectMethod(integer, box, b);
        env->SetObjectArrayElement(parameters, 0, left);
        env->SetObjectArrayElement(parameters, 1, right);
        env->DeleteLocalRef(left); env->DeleteLocalRef(right);
        result = interpret(env, 2, i, parameters);
        const bool expected[] = {a == b, a != b, a < b, a >= b, a > b, a <= b};
        assert(result && !env->ExceptionCheck());
        assert(env->CallIntMethod(result, unbox) == expected[(i - 107) / 6]);
        env->DeleteLocalRef(result);
        assert(!items.at(i)->parsed_vm);
    }
    env->DeleteLocalRef(parameters);
    puts("结构变换试验：六种比较/两种控制流/三种 ISA 共 900 次 JNI 边界对照通过");
    // 同一生产编译器与解释器串联，覆盖 null、类型不匹配、正常值和 catch 中再次调用。
    jclass objectClass = env->FindClass("java/lang/Object");
    jobjectArray receiverArgs = env->NewObjectArray(1, objectClass, nullptr);
    jobject wrongType = env->CallStaticObjectMethod(integer, box, 73);
    jobject stringValue = env->NewStringUTF("seven77");
    jobject inputs[] = {nullptr, wrongType, stringValue};
    for (int id = 143; id < 149; id++) for (int repeat = 0; repeat < 50; repeat++) for (int value = 0; value < 3; value++) {
        env->SetObjectArrayElement(receiverArgs, 0, inputs[value]);
        result = interpret(env, 2, id, receiverArgs);
        const int expected = id < 146 ? (value == 1 ? 4 : 7) : (value == 2 ? 7 : -1);
        assert(result && !env->ExceptionCheck());
        assert(env->CallIntMethod(result, unbox) == expected);
        env->DeleteLocalRef(result);
        assert(!items.at(id)->parsed_vm);
    }
    env->DeleteLocalRef(wrongType); env->DeleteLocalRef(stringValue);
    env->DeleteLocalRef(receiverArgs); env->DeleteLocalRef(objectClass);
    puts("接收者推导：两种语义/三种 ISA 共 900 次 JNI 正常与异常路径对照通过");
    jobject wrappers[] = {box_int(env, 11), box_long(env, INT64_MIN), box_bool(env, true),
        box_float(env, -0.0f), box_double(env, 1.25), nullptr};
    jobject sentinel = box_int(env, 1234567);
    jobjectArray tailArgs = env->NewObjectArray(2, objectClass = env->FindClass("java/lang/Object"), nullptr);
    for (int id = 152; id < 155; id++) for (jobject wrapper : wrappers) {
        env->SetObjectArrayElement(tailArgs, 0, wrapper); env->SetObjectArrayElement(tailArgs, 1, sentinel);
        result = interpret(env, 2, id, tailArgs);
        assert(result && !env->ExceptionCheck() && env->CallIntMethod(result, unbox) == 1234567);
        env->DeleteLocalRef(result);
    }
    jobjectArray mixedArgs = env->NewObjectArray(5, objectClass, nullptr);
    int indices[] = {1, 4, 3, 2, 0};
    for (int i = 0; i < 5; i++) env->SetObjectArrayElement(mixedArgs, i, wrappers[indices[i]]);
    for (int id = 149; id < 152; id++) {
        result = interpret(env, 2, id, mixedArgs);
        assert(result && !env->ExceptionCheck() && env->CallIntMethod(result, unbox) == 11);
        env->DeleteLocalRef(result);
    }
    // 错误数量、错装箱及基本类型 null 必须返回异常，不能触发 JNI 错误调用。
    for (int id = 149; id < 152; id++) {
        assert(!interpret(env, 2, id, tailArgs) && env->ExceptionCheck()); env->ExceptionClear();
        env->SetObjectArrayElement(mixedArgs, 0, wrappers[0]);
        assert(!interpret(env, 2, id, mixedArgs) && env->ExceptionCheck()); env->ExceptionClear();
        env->SetObjectArrayElement(mixedArgs, 0, nullptr);
        assert(!interpret(env, 2, id, mixedArgs) && env->ExceptionCheck()); env->ExceptionClear();
    }
    // 不同 JNI 句柄指向同一对象时，引用相等与返回值必须保持 Java 身份语义。
    jobjectArray unary = env->NewObjectArray(1, objectClass, nullptr);
    jintArray array = env->NewIntArray(3);
    jstring text = env->NewStringUTF("reference");
    jstring equalText = env->NewStringUTF("reference");
    jobject alias = env->NewLocalRef(text);
    jobject references[] = {nullptr, wrappers[0], wrappers[1], wrappers[2], wrappers[3], wrappers[4], array, text, equalText, alias};
    int referenceChecks = 0;
    for (int isa = 0; isa < 3; isa++) {
        for (jobject left : references) {
            env->SetObjectArrayElement(unary, 0, left);
            result = interpret(env, 2, 155 + isa, unary);
            assert(!env->ExceptionCheck() && env->IsSameObject(result, left));
            if (result) env->DeleteLocalRef(result);
            result = interpret(env, 2, 164 + isa, unary);
            assert(result && !env->ExceptionCheck() && env->CallIntMethod(result, unbox) == (left == nullptr));
            env->DeleteLocalRef(result); referenceChecks += 2;
            for (jobject right : references) {
                env->SetObjectArrayElement(tailArgs, 0, left); env->SetObjectArrayElement(tailArgs, 1, right);
                result = interpret(env, 2, 158 + isa, tailArgs);
                assert(!env->ExceptionCheck() && env->IsSameObject(result, left ? left : right));
                if (result) env->DeleteLocalRef(result);
                result = interpret(env, 2, 161 + isa, tailArgs);
                assert(result && !env->ExceptionCheck() && env->CallIntMethod(result, unbox) == env->IsSameObject(left, right));
                env->DeleteLocalRef(result); referenceChecks += 2;
            }
        }
        for (jobject value : {static_cast<jobject>(array), static_cast<jobject>(nullptr)}) {
            env->SetObjectArrayElement(unary, 0, value);
            result = interpret(env, 2, 167 + isa, unary);
            assert(!env->ExceptionCheck() && env->IsSameObject(result, value));
            if (result) env->DeleteLocalRef(result);
            referenceChecks++;
        }
    }
    assert(referenceChecks == 666);
    for (int id = 155; id < 170; id++) assert(!items.at(id)->parsed_vm);
    env->DeleteLocalRef(unary); env->DeleteLocalRef(array); env->DeleteLocalRef(text);
    env->DeleteLocalRef(equalText); env->DeleteLocalRef(alias);
    puts("引用叶子方法：三种 ISA 共 666 次透传、空值选择、身份比较、数组引用及清理验证通过");
    // 继承类/接口方法沿用相同跳板参数布局，this 不能和首个业务参数混淆。
    jclass arithmetic = env->FindClass("java/lang/ArithmeticException");
    jclass nullPointer = env->FindClass("java/lang/NullPointerException");
    jobject thrown = env->NewObject(arithmetic, env->GetMethodID(arithmetic, "<init>", "()V"));
    jobjectArray instanceArgs = env->NewObjectArray(2, objectClass, nullptr);
    jobjectArray thisOnly = env->NewObjectArray(1, objectClass, nullptr);
    int compatibilityChecks = 0;
    for (int isa = 0; isa < 3; isa++) for (jobject receiver : {sentinel, wrappers[0]}) {
        assert(receiver);
        env->SetObjectArrayElement(instanceArgs, 0, receiver);
        env->SetObjectArrayElement(thisOnly, 0, receiver);
        result = interpret(env, 2, 182 + isa, thisOnly);
        assert(!env->ExceptionCheck() && env->IsSameObject(result, receiver));
        env->DeleteLocalRef(result); compatibilityChecks++;
        for (jobject argument : {receiver, thrown, static_cast<jobject>(nullptr)}) {
            env->SetObjectArrayElement(instanceArgs, 1, argument);
            result = interpret(env, 2, 185 + isa, instanceArgs);
            assert(!env->ExceptionCheck() && env->IsSameObject(result, argument));
            if (result) env->DeleteLocalRef(result);
            compatibilityChecks++;
        }
        for (int kind = 0; kind < 3; kind++) for (int divisor : {INT32_MIN, -3, 0, 1, 2, INT32_MAX}) {
            jobject argument = env->CallStaticObjectMethod(integer, box, divisor);
            env->SetObjectArrayElement(instanceArgs, 1, argument); env->DeleteLocalRef(argument);
            result = interpret(env, 2, 170 + kind * 3 + isa, instanceArgs);
            if (kind == 1 && divisor == 0) {
                assert(!result && env->ExceptionCheck());
                jthrowable error = env->ExceptionOccurred(); env->ExceptionClear();
                assert(env->IsInstanceOf(error, arithmetic)); env->DeleteLocalRef(error);
            } else {
                int expected = kind == 2 ? (divisor == 0 ? 42 : 40 / divisor + 2) : (divisor == 0 ? -7 : 12 / divisor);
                assert(result && !env->ExceptionCheck() && env->CallIntMethod(result, unbox) == expected);
                env->DeleteLocalRef(result);
            }
            compatibilityChecks++;
        }
        for (jobject argument : {thrown, static_cast<jobject>(nullptr)}) {
            env->SetObjectArrayElement(instanceArgs, 1, argument);
            result = interpret(env, 2, 179 + isa, instanceArgs);
            assert(!result && env->ExceptionCheck());
            jthrowable error = env->ExceptionOccurred(); env->ExceptionClear();
            assert(argument ? env->IsSameObject(error, argument) : env->IsInstanceOf(error, nullPointer));
            env->DeleteLocalRef(error); compatibilityChecks++;
        }
    }
    assert(compatibilityChecks == 144);
    for (int id = 170; id < 188; id++) assert(!items.at(id)->parsed_vm && items.at(id)->vm_image.capacity() == 0);
    env->DeleteLocalRef(arithmetic); env->DeleteLocalRef(nullPointer); env->DeleteLocalRef(thrown);
    env->DeleteLocalRef(instanceArgs); env->DeleteLocalRef(thisOnly);
    puts("继承与异常方法：三种 ISA 共 144 次 this/参数身份、捕获优先级、不匹配异常传播、finally 清理及重抛身份检查通过");
    for (jobject wrapper : wrappers) if (wrapper) env->DeleteLocalRef(wrapper);
    env->DeleteLocalRef(sentinel); env->DeleteLocalRef(tailArgs); env->DeleteLocalRef(mixedArgs); env->DeleteLocalRef(objectClass);
    puts("声明参数类型：5 种包装引用、null、混合宽参数、数量/类型错误拒绝通过");
    env->DeleteLocalRef(integer);
    CodeItem* required = items.at(101);
    {
        VmpUsePin outer;
        assert(acquire_vmp(required, outer));
        { VmpUsePin recursive; assert(acquire_vmp(required, recursive)); }
        assert(required->parsed_vm && required->vmp_in_use == 1);
    }
    assert(!required->parsed_vm);
    std::barrier required_sync(2);
    std::thread required_thread([&] {
        VmpUsePin pin; assert(acquire_vmp(required, pin));
        required_sync.arrive_and_wait(); required_sync.arrive_and_wait();
        assert(required->parsed_vm && required->vmp_in_use == 1);
    });
    {
        VmpUsePin pin; assert(acquire_vmp(required, pin));
        required_sync.arrive_and_wait();
        assert(required->parsed_vm && required->vmp_in_use == 2);
    }
    required_sync.arrive_and_wait(); required_thread.join();
    assert(!required->parsed_vm && g_vmp_lru.pos.count(required) == 0);
    threads.clear();
    for (int t = 0; t < 8; t++) threads.emplace_back([&] {
        for (int i = 0; i < 1000; i++) {
            VmpUsePin pin; assert(acquire_vmp(required, pin));
            std::this_thread::yield();
            assert(required->parsed_vm->valid && required->parsed_vm->clear_after_use);
        }
    });
    for (auto& thread : threads) thread.join();
    assert(!required->parsed_vm && g_vmp_lru.pos.count(required) == 0);

    // v6 仍按有限缓存解析；未知、缺失策略及未来版本必须拒绝。
    std::ifstream policy_input(std::string(argv[1]) + "/image3.bin", std::ios::binary);
    std::vector<uint8_t> policy_image(std::istreambuf_iterator<char>(policy_input), {});
    assert(parse_pvm2(policy_image.data(), policy_image.size(), &parsed) && parsed.clear_after_use);
    auto legacy = policy_image;
    legacy[4] = 8;
    assert(parse_pvm2(legacy.data(), legacy.size(), &parsed) && parsed.clear_after_use);
    // 此样本参数为空，类型表在虚拟指令前只有一个 count 字节。
    size_t args_offset = legacy.size() - (size_t(legacy[12]) | (size_t(legacy[13]) << 8)) - 1;
    legacy.erase(legacy.begin() + args_offset);
    legacy[4] = 7;
    assert(parse_pvm2(legacy.data(), legacy.size(), &parsed) && parsed.clear_after_use);
    legacy.erase(legacy.begin() + 18); legacy[4] = 6;
    assert(parse_pvm2(legacy.data(), legacy.size(), &parsed) && !parsed.clear_after_use);
    for (int fault = 0; fault < 3; fault++) {
        auto broken = policy_image;
        if (fault == 0) broken[18] = 2;
        if (fault == 1) broken.resize(18);
        if (fault == 2) broken[4] = PVM2_VERSION_V9 + 1;
        assert(!parse_pvm2(broken.data(), broken.size(), &parsed));
        assert(!parsed.valid && !parsed.clear_after_use && parsed.code.capacity() == 0);
    }
    // 参数表属于镜像解析边界：未知类型、宽度不匹配、错误数量、截断都拒绝。
    std::ifstream typed_input(std::string(argv[1]) + "/image45.bin", std::ios::binary);
    std::vector<uint8_t> typed_image(std::istreambuf_iterator<char>(typed_input), {});
    const size_t typed_offset = typed_image.size()
        - (size_t(typed_image[12]) | (size_t(typed_image[13]) << 8))
        - (size_t(typed_image[10]) | (size_t(typed_image[11]) << 8)) * 10 - 2;
    assert(typed_image[typed_offset] == 1 && typed_image[typed_offset + 1] == 'L');
    for (int fault = 0; fault < 4; fault++) {
        auto broken = typed_image;
        if (fault == 0) broken[typed_offset + 1] = 'V';
        if (fault == 1) broken[typed_offset + 1] = 'J';
        if (fault == 2) broken[typed_offset] = 0;
        if (fault == 3) broken.resize(typed_offset + 1);
        assert(!parse_pvm2(broken.data(), broken.size(), &parsed));
    }
    assert(!interpret(env, 2, 96, nullptr) && env->ExceptionCheck()); env->ExceptionClear();

    std::barrier sync(2);
    std::thread executing([&] {
        VmpUsePin pin; assert(acquire_vmp(first, pin));
        sync.arrive_and_wait(); sync.arrive_and_wait();
        assert(first->parsed_vm && first->parsed_vm->code[2] == 42);
        VmpUsePin refused; assert(!acquire_vmp(first, refused));
    });
    sync.arrive_and_wait();
    mocika_xop_pvm2_block();
    assert(true_vmp_cache_stats().pins == 1);
    assert(!mocika_xop_pvm2_init(code.data(), code.size(), key, 16));
    assert(!interpret(env, 2, 0, nullptr) && env->ExceptionCheck()); env->ExceptionClear();
    sync.arrive_and_wait(); executing.join();
    auto stats = true_vmp_cache_stats();
    assert(stats.images == 0 && stats.bytes == 0 && stats.pins == 0);
    for (auto& pair : items) assert(!pair.second->parsed_vm && pair.second->vm_image.capacity() == 0);
    printf("认证/解析失败、递归、8 线程竞争、字节预算、JNI 执行、必保方法正常/异常/并发退出清理、阻断清理：通过；缓存峰值 %zu 字节（包含大方法压力样本）\n", stats.peak_bytes);
    assert(jvm->DestroyJavaVM() == JNI_OK);
    // 生产方法表保持进程生命周期；测试退出前释放以便检查宿主泄漏。
    for (auto& pair : items) delete pair.second;
    runtime_state().code_map.clear();
}
