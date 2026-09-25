#include <jni.h>

#if defined(MOCIKA_NATIVE_VMP_ENABLED)
#include "mocika_native_vmp.h"
#define MOCIKA_PROTECTED_SCORE MOCIKA_VMP
#else
#define MOCIKA_PROTECTED_SCORE
#endif

MOCIKA_PROTECTED_SCORE static jint protected_score(jint value) {
    jint result = value;
    for (jint round = 0; round < 4; ++round) {
        result = (result * 17 + round) ^ (result >> 2);
    }
    return result;
}

JNIEXPORT jint JNICALL
Java_dev_mocika_shield_featurefixture_conditional_ConditionalProbe_nativeScore(
        JNIEnv *env, jclass type, jint value) {
    (void)env;
    (void)type;
    return protected_score(value);
}
