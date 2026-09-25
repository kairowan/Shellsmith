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

pub fn derive_envelope_key(cert_fingerprint: &[u8], build_id: &[u8; 16]) -> [u8; 32] {
    // cert_fingerprint 与 build_id 均随包公开；该层只提高静态扫描成本，
    // 不提供客户端秘密存储能力。
    let hk = Hkdf::<Sha256>::new(Some(build_id), cert_fingerprint);
    let mut okm = [0u8; 32];
    hk.expand(b"mocika-shield/dexb/v6/envelope", &mut okm)
        .expect("HKDF expand 长度固定为 32，不会失败");
    okm
}

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

    #[test]
    fn different_nonces_produce_different_keys() {
        let ikm = b"same-ikm";
        let fp = b"AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899";
        let n1 = [0u8; 12];
        let n2 = [1u8; 12];
        assert_ne!(derive_key(ikm, &n1, fp), derive_key(ikm, &n2, fp));
    }

    #[test]
    fn different_fingerprints_produce_different_keys() {
        let ikm = b"same-ikm";
        let nonce = [0u8; 12];
        let fp1 = b"AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899";
        let fp2 = b"0011223344556677889900AABBCCDDEEFF00112233445566778899AABBCCDDEE";
        assert_ne!(derive_key(ikm, &nonce, fp1), derive_key(ikm, &nonce, fp2));
    }

    #[test]
    fn decrypt_is_symmetric_with_encrypt() {
        use chacha20poly1305::aead::Aead as _;
        let ikm = b"test-key";
        let nonce = [42u8; 12];
        let fp = b"AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899";
        let key = derive_key(ikm, &nonce, fp);

        let plaintext = b"dex payload data";
        let cipher = ChaCha20Poly1305::new((&key).into());
        let n = Nonce::from_slice(&nonce);
        let ciphertext = cipher.encrypt(n, plaintext.as_ref()).unwrap();

        let decrypted = decrypt(&ciphertext, &key, &nonce).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn tampered_ciphertext_returns_error() {
        use chacha20poly1305::aead::Aead as _;
        let ikm = b"key";
        let nonce = [7u8; 12];
        let fp = b"fingerprint";
        let key = derive_key(ikm, &nonce, fp);

        let plaintext = b"data";
        let cipher = ChaCha20Poly1305::new((&key).into());
        let n = Nonce::from_slice(&nonce);
        let mut ciphertext = cipher.encrypt(n, plaintext.as_ref()).unwrap();
        ciphertext[0] ^= 0xFF;

        assert!(decrypt(&ciphertext, &key, &nonce).is_err());
    }

    #[test]
    fn xop_key_is_certificate_bound() {
        assert_ne!(
            derive_xop_pvm2_key(b"ikm", b"cert-a"),
            derive_xop_pvm2_key(b"ikm", b"cert-b")
        );
    }

    #[test]
    fn assets_key_is_domain_separated_from_pvm2() {
        assert_ne!(
            derive_assets_pas2_key(b"ikm", b"cert"),
            derive_xop_pvm2_key(b"ikm", b"cert")
        );
    }

    #[test]
    fn native_so_key_is_domain_separated() {
        assert_ne!(
            derive_native_so_key(b"ikm", b"cert"),
            derive_assets_pas2_key(b"ikm", b"cert")
        );
        assert_ne!(
            derive_native_so_key(b"ikm", b"cert"),
            derive_xop_pvm2_key(b"ikm", b"cert")
        );
    }
}
