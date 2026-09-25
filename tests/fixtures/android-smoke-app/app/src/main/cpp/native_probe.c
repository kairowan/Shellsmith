#include <jni.h>
#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>
#include <string.h>

JNIEXPORT jint JNICALL
Java_dev_mocika_shield_smoke_NativeProbe_nativeValue(
        JNIEnv *env, jclass type, jobject java_asset_manager) {
    (void) type;
    AAssetManager *manager = AAssetManager_fromJava(env, java_asset_manager);
    if (manager == NULL) return -1;
    AAsset *asset = AAssetManager_open(manager, "native/probe.txt", AASSET_MODE_BUFFER);
    if (asset == NULL) return -2;
    const char expected[] = "native-pas2-ok\n";
    char value[sizeof(expected)] = {0};
    int read = AAsset_read(asset, value, sizeof(expected) - 1);
    AAsset_close(asset);
    return read == (int) sizeof(expected) - 1
            && memcmp(value, expected, sizeof(expected) - 1) == 0 ? 73 : -3;
}
