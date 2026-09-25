use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;

pub fn derive_key(ikm: &[u8], nonce: &[u8; 12], cert_fingerprint: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(nonce), ikm);
    let mut okm = [0u8; 32];
    hk.expand(cert_fingerprint, &mut okm)
        .expect("HKDF expand 长度固定为 32，不会失败");
    okm
}

/// DEXB v6 的包裹密钥。证书指纹和 build_id 都是包内公开材料，因此这不是
/// 客户端秘密存储；它只避免把完整 IKM 直接暴露在头部，降低自动化静态扫描
/// 的命中率。高价值授权秘密必须放在服务端或可信执行环境。
pub fn derive_envelope_key(cert_fingerprint: &[u8], build_id: &[u8; 16]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(build_id), cert_fingerprint);
    let mut okm = [0u8; 32];
    hk.expand(b"mocika-shield/dexb/v6/envelope", &mut okm)
        .expect("HKDF expand 长度固定为 32，不会失败");
    okm
}

/// Per-build AES-128 key used by the embedded Xop PVM2 method images.
/// It is derived from the same DEXB build material and never stored as plaintext in the APK.
pub fn derive_xop_pvm2_key(ikm: &[u8], cert_fingerprint: &[u8]) -> [u8; 16] {
    let hk = Hkdf::<Sha256>::new(Some(cert_fingerprint), ikm);
    let mut okm = [0u8; 16];
    hk.expand(b"mocika-shield/xop-pvm2/v1", &mut okm)
        .expect("HKDF expand length is fixed at 16");
    okm
}

pub fn derive_assets_pas2_key(ikm: &[u8], cert_fingerprint: &[u8]) -> [u8; 16] {
    let hk = Hkdf::<Sha256>::new(Some(cert_fingerprint), ikm);
    let mut okm = [0u8; 16];
    hk.expand(b"mocika-shield/assets-pas2/v1", &mut okm)
        .expect("HKDF expand length is fixed at 16");
    okm
}

pub fn derive_native_so_key(ikm: &[u8], cert_fingerprint: &[u8]) -> [u8; 16] {
    let hk = Hkdf::<Sha256>::new(Some(cert_fingerprint), ikm);
    let mut okm = [0u8; 16];
    hk.expand(b"mocika-shield/native-so/v1", &mut okm)
        .expect("HKDF expand length is fixed at 16");
    okm
}

pub fn encrypt(plaintext: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from_slice(nonce);
    cipher
        .encrypt(nonce, plaintext)
        .expect("ChaCha20-Poly1305 加密不会因内存外原因失败")
}

#[cfg(test)]
pub fn decrypt(ciphertext: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "ChaCha20-Poly1305 解密失败：数据已损坏或密钥不匹配".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    fn random_nonce() -> [u8; 12] {
        let mut n = [0u8; 12];
        rand::rng().fill_bytes(&mut n);
        n
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let ikm = b"test-key-for-unit-test";
        let nonce = random_nonce();
        let fp = b"AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899";
        let key = derive_key(ikm, &nonce, fp);
        let plaintext = b"hello mocika shield dex payload";

        let ciphertext = encrypt(plaintext, &key, &nonce);
        assert_ne!(ciphertext, plaintext);

        let cipher = chacha20poly1305::ChaCha20Poly1305::new((&key).into());
        let n = chacha20poly1305::Nonce::from_slice(&nonce);
        let decrypted = cipher.decrypt(n, ciphertext.as_ref()).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn tampered_ciphertext_fails_decryption() {
        let ikm = b"another-key";
        let nonce = random_nonce();
        let fp = b"AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899";
        let key = derive_key(ikm, &nonce, fp);
        let plaintext = b"sensitive dex data";

        let mut ciphertext = encrypt(plaintext, &key, &nonce);
        ciphertext[0] ^= 0xFF;

        let cipher = chacha20poly1305::ChaCha20Poly1305::new((&key).into());
        let n = chacha20poly1305::Nonce::from_slice(&nonce);
        assert!(cipher.decrypt(n, ciphertext.as_ref()).is_err());
    }

    #[test]
    fn different_nonces_produce_different_keys() {
        let ikm = b"same-key-material";
        let fp = b"AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899";
        let nonce1 = [0u8; 12];
        let nonce2 = [1u8; 12];
        assert_ne!(derive_key(ikm, &nonce1, fp), derive_key(ikm, &nonce2, fp));
    }

    #[test]
    fn different_fingerprints_produce_different_keys() {
        let ikm = b"same-key-material";
        let nonce = [0u8; 12];
        let fp1 = b"AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899";
        let fp2 = b"0011223344556677889900AABBCCDDEEFF00112233445566778899AABBCCDDEE";
        assert_ne!(derive_key(ikm, &nonce, fp1), derive_key(ikm, &nonce, fp2));
    }

    #[test]
    fn xop_pvm2_key_is_bound_to_certificate() {
        let ikm = b"same-key-material";
        assert_ne!(
            derive_xop_pvm2_key(ikm, b"cert-a"),
            derive_xop_pvm2_key(ikm, b"cert-b")
        );
    }

    #[test]
    fn assets_key_is_domain_separated() {
        assert_ne!(
            derive_assets_pas2_key(b"ikm", b"cert"),
            derive_xop_pvm2_key(b"ikm", b"cert")
        );
        assert_ne!(
            derive_native_so_key(b"ikm", b"cert"),
            derive_assets_pas2_key(b"ikm", b"cert")
        );
    }

    #[test]
    fn decrypt_rejects_tampered_ciphertext() {
        let ikm = b"test-key";
        let nonce = [9u8; 12];
        let key = derive_key(ikm, &nonce, b"certificate");
        let mut ciphertext = encrypt(b"payload", &key, &nonce);
        ciphertext[0] ^= 0x01;
        assert!(decrypt(&ciphertext, &key, &nonce).is_err());
    }
}
