use jni::sys::{jint, jobject, jobjectArray, JNIEnv as RawJniEnv};

extern "C" {
    fn mocika_xop_pvm2_init(
        code: *const u8,
        code_len: usize,
        key: *const u8,
        key_len: usize,
    ) -> bool;
    fn mocika_xop_pvm2_interpret(
        env: *mut RawJniEnv,
        dex_index: jint,
        method_index: jint,
        args: jobjectArray,
    ) -> jobject;
}

pub fn initialize(code: &[u8], key: &[u8; 16]) -> Result<(), String> {
    let ok = unsafe { mocika_xop_pvm2_init(code.as_ptr(), code.len(), key.as_ptr(), key.len()) };
    if ok {
        Ok(())
    } else {
        Err("Xop PVM2 runtime initialization failed".to_string())
    }
}

pub unsafe fn interpret(
    env: *mut RawJniEnv,
    dex_index: jint,
    method_index: jint,
    args: jobjectArray,
) -> jobject {
    unsafe { mocika_xop_pvm2_interpret(env, dex_index, method_index, args) }
}
