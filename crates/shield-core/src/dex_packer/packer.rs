use anyhow::{Context, Result};
use rand::RngCore;
use std::fs;
use std::io::Write;
use std::path::Path;

use super::crypto;

struct DexMeta {
    name: String,
    original_size: u32,
    data: Vec<u8>,
}

pub struct DexPacker {
    dex_files: Vec<DexMeta>,
    total_original_size: usize,
    total_compressed_size: usize,
    compression_layers: u8,
}

impl DexPacker {
    pub fn new() -> Self {
        Self {
            dex_files: Vec::new(),
            total_original_size: 0,
            total_compressed_size: 0,
            compression_layers: 1,
        }
    }

    pub fn set_compression_layers(&mut self, layers: u8) -> Result<()> {
        if !(1..=3).contains(&layers) {
            anyhow::bail!("DEXB 压缩层数必须在 1..=3 内，实际为 {layers}");
        }
        self.compression_layers = layers;
        Ok(())
    }

    pub fn add_dex(&mut self, dex_path: &Path, name: &str) -> Result<()> {
        self.add_entry(dex_path, name)
    }

    pub fn add_entry(&mut self, path: &Path, name: &str) -> Result<()> {
        let dex_data = fs::read(path).with_context(|| format!("无法读取文件: {:?}", path))?;
        let file_size = dex_data.len();

        let compressed = zstd::encode_all(&dex_data[..], 19).context("Zstd 压缩失败")?;
        let compressed_size = compressed.len();

        self.total_original_size += file_size;
        self.total_compressed_size += compressed_size;

        let ratio = 100.0 * compressed_size as f32 / file_size as f32;
        println!(
            "  ✓ {}: {} -> {} bytes ({:.1}%)",
            name, file_size, compressed_size, ratio
        );

        self.dex_files.push(DexMeta {
            name: name.to_string(),
            original_size: file_size as u32,
            data: compressed,
        });
        Ok(())
    }

    pub fn pack(&self, output_path: &Path, ikm: &[u8], signature: &str) -> Result<()> {
        if ikm.is_empty() {
            anyhow::bail!("IKM 不能为空");
        }
        if self.dex_files.is_empty() {
            anyhow::bail!("没有 DEX 文件可打包");
        }
        let sig_bytes = signature.as_bytes();
        if sig_bytes.len() > u8::MAX as usize {
            anyhow::bail!("签名指纹长度不能超过255字节");
        }
        if ikm.len() > u8::MAX as usize {
            anyhow::bail!("IKM 长度不能超过255字节");
        }

        let mut build_id = [0u8; 16];
        rand::rng().fill_bytes(&mut build_id);
        let mut wrap_nonce = [0u8; 12];
        rand::rng().fill_bytes(&mut wrap_nonce);
        let mut nonce = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce);
        // HKDF info 字段传入签名指纹，将密钥与 APK 证书绑定
        let derived_key = crypto::derive_key(ikm, &nonce, sig_bytes);
        let envelope_key = crypto::derive_envelope_key(sig_bytes, &build_id);
        let wrapped_ikm = crypto::encrypt(ikm, &envelope_key, &wrap_nonce);

        let mut encoded = Vec::with_capacity(self.dex_files.len());
        for meta in &self.dex_files {
            let mut data = meta.data.clone();
            for _ in 1..self.compression_layers {
                data = zstd::encode_all(&data[..], 19).context("Zstd 多层压缩失败")?;
            }
            encoded.push(data);
        }

        let mut plaintext = Vec::new();
        for (index, meta) in self.dex_files.iter().enumerate() {
            let name_bytes = meta.name.as_bytes();
            plaintext.push(name_bytes.len() as u8);
            plaintext.extend_from_slice(name_bytes);
            let encoded_size = encoded
                .get(index)
                .map(|data| data.len())
                .ok_or_else(|| anyhow::anyhow!("DEX 多层压缩索引错误"))?;
            let encoded_size =
                u32::try_from(encoded_size).context("DEX 多层压缩后单文件超过 4GiB")?;
            plaintext.extend_from_slice(&encoded_size.to_le_bytes());
            plaintext.extend_from_slice(&meta.original_size.to_le_bytes());
        }
        for data in &encoded {
            plaintext.extend_from_slice(data);
        }

        let ciphertext = crypto::encrypt(&plaintext, &derived_key, &nonce);

        let dex_count = self.dex_files.len() as u32;
        // DEXB v6 头部：magic + version + dex_count + flags
        //   + signature + build_id + wrap_nonce + wrapped_ikm + payload_nonce → 密文。
        // IKM 仍需在设备侧恢复，但不再以明文形式出现在头部。
        let mut out = Vec::with_capacity(
            4 + 4
                + 4
                + 4
                + 1
                + sig_bytes.len()
                + 16
                + 12
                + 2
                + wrapped_ikm.len()
                + 12
                + ciphertext.len(),
        );
        out.extend_from_slice(b"DEXB");
        out.extend_from_slice(&6u32.to_le_bytes());
        out.extend_from_slice(&dex_count.to_le_bytes());
        out.extend_from_slice(&(self.compression_layers as u32).to_le_bytes());
        out.push(sig_bytes.len() as u8);
        out.extend_from_slice(sig_bytes);
        out.extend_from_slice(&build_id);
        out.extend_from_slice(&wrap_nonce);
        out.extend_from_slice(&(wrapped_ikm.len() as u16).to_le_bytes());
        out.extend_from_slice(&wrapped_ikm);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);

        let mut file = fs::File::create(output_path)
            .with_context(|| format!("无法创建输出文件: {:?}", output_path))?;
        file.write_all(&out).context("写入文件失败")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fake_dex(content: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(content).unwrap();
        f
    }

    fn parse_bin(
        raw: &[u8],
        ikm: &[u8],
        signature: &str,
    ) -> (u32, u32, u32, Vec<(String, u32, u32)>) {
        use chacha20poly1305::aead::{Aead, KeyInit};

        assert_eq!(&raw[0..4], b"DEXB", "magic 不匹配");
        let version = u32::from_le_bytes(raw[4..8].try_into().unwrap());
        assert_eq!(version, 6, "version 应为 6");
        let dex_count = u32::from_le_bytes(raw[8..12].try_into().unwrap());
        let flags = u32::from_le_bytes(raw[12..16].try_into().unwrap());
        let sig_len = raw[16] as usize;
        let sig_offset = 17usize;
        let build_id_offset = sig_offset + sig_len;
        let build_id: [u8; 16] = raw[build_id_offset..build_id_offset + 16]
            .try_into()
            .unwrap();
        let wrap_nonce_offset = build_id_offset + 16;
        let wrap_nonce: [u8; 12] = raw[wrap_nonce_offset..wrap_nonce_offset + 12]
            .try_into()
            .unwrap();
        let wrapped_len_offset = wrap_nonce_offset + 12;
        let wrapped_len = u16::from_le_bytes(
            raw[wrapped_len_offset..wrapped_len_offset + 2]
                .try_into()
                .unwrap(),
        ) as usize;
        let wrapped_offset = wrapped_len_offset + 2;
        let nonce_offset = wrapped_offset + wrapped_len;
        let nonce: [u8; 12] = raw[nonce_offset..nonce_offset + 12].try_into().unwrap();

        let envelope_key = crypto::derive_envelope_key(signature.as_bytes(), &build_id);
        let unwrapped_ikm = crypto::decrypt(
            &raw[wrapped_offset..wrapped_offset + wrapped_len],
            &envelope_key,
            &wrap_nonce,
        )
        .unwrap();
        assert_eq!(unwrapped_ikm, ikm);
        let derived_key = crypto::derive_key(&unwrapped_ikm, &nonce, signature.as_bytes());
        let cipher = chacha20poly1305::ChaCha20Poly1305::new((&derived_key).into());
        let n = chacha20poly1305::Nonce::from_slice(&nonce);
        let plaintext = cipher
            .decrypt(n, &raw[nonce_offset + 12..])
            .expect("ChaCha20 解密失败");

        let mut pos = 0;
        let mut metas = Vec::new();
        for _ in 0..dex_count {
            let name_len = plaintext[pos] as usize;
            pos += 1;
            let name = String::from_utf8(plaintext[pos..pos + name_len].to_vec()).unwrap();
            pos += name_len;
            let compressed_size = u32::from_le_bytes(plaintext[pos..pos + 4].try_into().unwrap());
            pos += 4;
            let original_size = u32::from_le_bytes(plaintext[pos..pos + 4].try_into().unwrap());
            pos += 4;
            metas.push((name, compressed_size, original_size));
        }
        (version, dex_count, flags, metas)
    }

    #[test]
    fn single_dex_pack_format_roundtrip() {
        let fake_dex_data = vec![0xDEu8, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00];
        let tmp_dex = make_fake_dex(&fake_dex_data);

        let mut packer = DexPacker::new();
        packer.add_dex(tmp_dex.path(), "classes.dex").unwrap();

        let tmp_out = tempfile::NamedTempFile::new().unwrap();
        let ikm = b"random32bytesikmmaterialhere!!!";
        let signature = "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899";
        packer.pack(tmp_out.path(), ikm, signature).unwrap();

        let raw = fs::read(tmp_out.path()).unwrap();
        assert!(!raw.is_empty());

        let (_, dex_count, flags, metas) = parse_bin(&raw, ikm, signature);
        assert_eq!(dex_count, 1);
        assert_eq!(flags, 1, "默认应使用单层压缩");
        assert_eq!(metas[0].0, "classes.dex");
        assert_eq!(
            metas[0].2,
            fake_dex_data.len() as u32,
            "original_size 不匹配"
        );
    }

    #[test]
    fn multi_dex_count_field_correct() {
        let tmp1 = make_fake_dex(b"dex1");
        let tmp2 = make_fake_dex(b"dex2-longer-data");

        let mut packer = DexPacker::new();
        packer.add_dex(tmp1.path(), "classes.dex").unwrap();
        packer.add_dex(tmp2.path(), "classes2.dex").unwrap();

        let tmp_out = tempfile::NamedTempFile::new().unwrap();
        let ikm = b"random32bytesikmmaterialhere!!!";
        let signature = "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899";
        packer.pack(tmp_out.path(), ikm, signature).unwrap();

        let raw = fs::read(tmp_out.path()).unwrap();
        let (_, dex_count, flags, metas) = parse_bin(&raw, ikm, signature);
        assert_eq!(dex_count, 2);
        assert_eq!(flags, 1);
        assert_eq!(metas[0].0, "classes.dex");
        assert_eq!(metas[1].0, "classes2.dex");
    }

    #[test]
    fn empty_ikm_returns_error() {
        let tmp_dex = make_fake_dex(b"data");
        let mut packer = DexPacker::new();
        packer.add_dex(tmp_dex.path(), "classes.dex").unwrap();

        let tmp_out = tempfile::NamedTempFile::new().unwrap();
        assert!(packer.pack(tmp_out.path(), b"", "").is_err());
    }

    #[test]
    fn no_dex_files_returns_error() {
        let packer = DexPacker::new();
        let tmp_out = tempfile::NamedTempFile::new().unwrap();
        assert!(packer.pack(tmp_out.path(), b"key", "").is_err());
    }

    #[test]
    fn compression_layers_are_encoded_in_v6_flags() {
        let tmp_dex = make_fake_dex(b"multi-layer-dex-data");
        let mut packer = DexPacker::new();
        packer.set_compression_layers(3).unwrap();
        packer.add_dex(tmp_dex.path(), "classes.dex").unwrap();

        let tmp_out = tempfile::NamedTempFile::new().unwrap();
        packer
            .pack(tmp_out.path(), b"random-ikm", "CERT-FINGERPRINT")
            .unwrap();
        let raw = fs::read(tmp_out.path()).unwrap();
        let (_, _, flags, metas) = parse_bin(&raw, b"random-ikm", "CERT-FINGERPRINT");
        assert_eq!(flags, 3);
        assert!(metas[0].1 > 0);
    }
}
