use std::sync::Mutex;

static KEY: Mutex<Option<[u8; 16]>> = Mutex::new(None);

extern "C" {
    fn mocika_pas1_decrypt(
        key: *const u8,
        key_len: usize,
        data: *const u8,
        data_len: usize,
        output: *mut u8,
        output_len: usize,
    ) -> bool;
}

pub fn initialize(key: [u8; 16]) -> Result<(), String> {
    *KEY.lock()
        .map_err(|_| "PAS2 key state poisoned".to_string())? = Some(key);
    Ok(())
}

pub fn decrypt(chunk: &[u8]) -> Result<Vec<u8>, String> {
    if chunk.len() < 4 + 12 + 16 || &chunk[..4] != b"PAS1" {
        return Err("invalid PAS1 chunk".to_string());
    }
    let output_len = chunk.len() - 4 - 12 - 16;
    let key = KEY
        .lock()
        .map_err(|_| "PAS2 key state poisoned".to_string())?
        .ok_or_else(|| "PAS2 key is not initialized".to_string())?;
    let mut output = vec![0u8; output_len];
    let ok = unsafe {
        mocika_pas1_decrypt(
            key.as_ptr(),
            key.len(),
            chunk.as_ptr(),
            chunk.len(),
            output.as_mut_ptr(),
            output.len(),
        )
    };
    if ok {
        Ok(output)
    } else {
        Err("PAS2 chunk authentication failed".to_string())
    }
}
