//! 显式业务资源的构建校验和认证容器。历史 PAS2 使用独立的读取路径。

use anyhow::{ensure, Context, Result};
use ring::{aead, rand::SecureRandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

const MAGIC: &[u8; 4] = b"SSR1";
const CHUNK_SIZE: usize = 64 * 1024;
const MAX_RESOURCE_SIZE: u64 = 16 * 1024 * 1024;
const MAX_TOTAL_SIZE: u64 = 64 * 1024 * 1024;
const MAX_MANIFEST_SIZE: u64 = 256 * 1024;
const MAX_RESOURCES: usize = 256;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
pub const RESOURCE_DIRECTORY: &str = "shellsmith-resources";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    resources: Vec<Resource>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Resource {
    id: String,
    source: String,
    group: String,
    version: u32,
    read: ReadMode,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReadMode {
    Stream,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResourceEvidence {
    pub id: String,
    pub group: String,
    pub version: u32,
    pub ciphertext_sha256: String,
}

struct PreparedResource {
    resource: Resource,
    plaintext_size: u64,
    plaintext_sha256: [u8; 32],
    ciphertext_len: u64,
    evidence: ResourceEvidence,
}

pub struct PreparedResources {
    build_id: [u8; 16],
    groups: BTreeMap<String, [u8; 32]>,
    resources: Vec<PreparedResource>,
    index_sha256: Option<[u8; 32]>,
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-_".contains(&byte))
}

fn relative_source(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || b"\\:".contains(&byte))
        && value.split('/').all(|part| {
            !part.is_empty()
                && part.trim() == part
                && part != "."
                && part != ".."
                && !part.eq_ignore_ascii_case(RESOURCE_DIRECTORY)
        })
}

fn regular_file(root: &Path, relative: &str) -> Result<File> {
    let mut path = root.to_owned();
    let mut components = relative.split('/').peekable();
    while let Some(component) = components.next() {
        path.push(component);
        let metadata = path.symlink_metadata().context("找不到必保资源")?;
        ensure!(!metadata.is_symlink(), "必保资源路径含符号链接");
        if components.peek().is_none() {
            ensure!(metadata.is_file(), "必保资源必须是普通文件");
        } else {
            ensure!(metadata.is_dir(), "必保资源父目录无效");
        }
    }
    let file = File::open(path).context("无法打开必保资源")?;
    ensure!(file.metadata()?.is_file(), "必保资源必须是普通文件");
    Ok(file)
}

fn random_bytes<const N: usize>(rng: &impl SecureRandom) -> Result<[u8; N]> {
    let mut value = [0; N];
    rng.fill(&mut value)
        .map_err(|_| anyhow::anyhow!("无法读取系统随机源"))?;
    Ok(value)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl PreparedResources {
    /// 从可丢弃的工作副本读取资源，密文写入独立暂存目录。
    pub fn prepare(manifest_path: &Path, root: &Path, destination: &Path) -> Result<Self> {
        ensure!(
            manifest_path.symlink_metadata()?.is_file(),
            "资源清单必须是普通文件"
        );
        ensure!(root.symlink_metadata()?.is_dir(), "必保资源根目录无效");
        let mut raw = Vec::new();
        File::open(manifest_path)?
            .take(MAX_MANIFEST_SIZE + 1)
            .read_to_end(&mut raw)?;
        ensure!(raw.len() as u64 <= MAX_MANIFEST_SIZE, "资源清单过大");
        let manifest: Manifest = serde_json::from_slice(&raw).context("无法解析资源清单")?;
        ensure!(manifest.version == 1, "不支持的资源清单版本");
        ensure!(
            (1..=MAX_RESOURCES).contains(&manifest.resources.len()),
            "必保资源数量超限"
        );
        let mut ids = HashSet::new();
        let mut sources = HashSet::new();
        let mut total = 0;
        let mut validated = Vec::with_capacity(manifest.resources.len());
        for resource in manifest.resources {
            ensure!(
                identifier(&resource.id) && identifier(&resource.group),
                "资源或组 ID 无效"
            );
            ensure!(
                resource.version > 0 && matches!(resource.read, ReadMode::Stream),
                "资源版本或读取方式无效"
            );
            ensure!(relative_source(&resource.source), "必保资源路径无效");
            ensure!(
                ids.insert(resource.id.clone()) && sources.insert(resource.source.to_lowercase()),
                "必保资源 ID 或路径重复"
            );
            let input = regular_file(root, &resource.source)?;
            let size = input.metadata()?.len();
            ensure!(
                (1..=MAX_RESOURCE_SIZE).contains(&size),
                "必保资源大小超限：{}",
                resource.id
            );
            total += size;
            ensure!(total <= MAX_TOTAL_SIZE, "必保资源总大小超限");
            validated.push((resource, input, size));
        }

        let rng = ring::rand::SystemRandom::new();
        let build_id = random_bytes(&rng)?;
        let mut groups = BTreeMap::new();
        let mut resources = Vec::with_capacity(validated.len());
        fs::create_dir(destination).context("无法创建独立密文目录")?;
        for (resource, mut input, plaintext_size) in validated {
            if !groups.contains_key(&resource.group) {
                groups.insert(resource.group.clone(), random_bytes(&rng)?);
            }
            let mut plain = Vec::new();
            (&mut input)
                .take(plaintext_size + 1)
                .read_to_end(&mut plain)?;
            ensure!(
                plain.len() as u64 == plaintext_size,
                "读取时必保资源大小发生变化"
            );
            let sealed =
                seal_resource(&rng, &build_id, &resource, &groups[&resource.group], &plain)?;
            let evidence = ResourceEvidence {
                id: resource.id.clone(),
                group: resource.group.clone(),
                version: resource.version,
                ciphertext_sha256: hex(&Sha256::digest(&sealed)),
            };
            let filename = format!("{}.ssr", resource.id);
            File::create_new(destination.join(filename))?.write_all(&sealed)?;
            resources.push(PreparedResource {
                resource,
                plaintext_size,
                plaintext_sha256: Sha256::digest(&plain).into(),
                ciphertext_len: sealed.len() as u64,
                evidence,
            });
        }
        Ok(Self {
            build_id,
            groups,
            resources,
            index_sha256: None,
        })
    }

    pub fn build_id(&self) -> String {
        hex(&self.build_id)
    }

    pub fn group_keys(&self) -> impl Iterator<Item = (&str, &[u8; 32])> {
        self.groups.iter().map(|(group, key)| (group.as_str(), key))
    }

    pub fn evidence(&self) -> impl Iterator<Item = &ResourceEvidence> {
        self.resources.iter().map(|resource| &resource.evidence)
    }

    pub(crate) fn index_digest(&self) -> Option<String> {
        self.index_sha256.as_ref().map(|digest| hex(digest))
    }

    pub(crate) fn register_android(
        &mut self,
        endpoint: &str,
        api_key: &str,
        destination: &Path,
    ) -> Result<()> {
        let build_id = self.build_id();
        let mut tokens = BTreeMap::new();
        for (group, key) in self.group_keys() {
            let token = crate::remote_key::register_resource_group(
                endpoint, api_key, &build_id, group, key,
            )?;
            tokens.insert(group, token);
        }
        let resources: BTreeMap<_, _> = self
            .evidence()
            .map(|entry| {
                (
                    entry.id.as_str(),
                    serde_json::json!({"group": entry.group, "version": entry.version}),
                )
            })
            .collect();
        let index = serde_json::to_vec(&serde_json::json!({
            "version": 1, "build_id": build_id, "server_url": endpoint.trim_end_matches('/'),
            "groups": tokens, "resources": resources,
        }))?;
        File::create_new(destination.join("index.json"))?.write_all(&index)?;
        self.index_sha256 = Some(Sha256::digest(&index).into());
        Ok(())
    }

    pub fn remove_originals(&self, root: &Path) -> Result<()> {
        for prepared in &self.resources {
            let mut file = regular_file(root, &prepared.resource.source)?;
            let digest = digest_bounded(&mut file, prepared.plaintext_size)?;
            ensure!(
                digest == prepared.plaintext_sha256,
                "必保资源在暂存期间发生变化"
            );
        }
        for prepared in &self.resources {
            fs::remove_file(root.join(&prepared.resource.source))?;
        }
        Ok(())
    }

    /// ZIP 前缀由外层 APK/IPA 校验获得。检验密文摘要以及同内容明文副本。
    pub fn verify_zip(&self, path: &Path, prefix: &str) -> Result<()> {
        let mut archive = crate::protection_report::checked_archive(path)?;
        let expected: BTreeMap<_, _> = self
            .resources
            .iter()
            .map(|prepared| {
                (
                    format!("{prefix}{RESOURCE_DIRECTORY}/{}.ssr", prepared.resource.id),
                    prepared,
                )
            })
            .collect();
        let originals: HashSet<_> = self
            .resources
            .iter()
            .map(|prepared| format!("{prefix}{}", prepared.resource.source))
            .collect();
        let mut found = HashSet::new();
        let index_name = format!("{prefix}{RESOURCE_DIRECTORY}/index.json");
        let mut index_found = false;
        for i in 0..archive.len() {
            let mut entry = archive.by_index(i)?;
            let name = entry.name()?;
            ensure!(
                !originals.contains(name.as_ref()),
                "最终产物保留必保资源原路径"
            );
            if let Some(prepared) = expected.get(name.as_ref()) {
                ensure!(
                    found.insert(prepared.resource.id.as_str()),
                    "最终产物密文条目重复"
                );
                let digest = digest_bounded(&mut entry, prepared.ciphertext_len)?;
                ensure!(
                    hex(&digest) == prepared.evidence.ciphertext_sha256,
                    "最终产物密文摘要不匹配"
                );
                continue;
            }
            if name == index_name && self.index_sha256.is_some() {
                ensure!(
                    !index_found && entry.size() <= MAX_MANIFEST_SIZE,
                    "最终产物资源索引无效"
                );
                let size = entry.size();
                ensure!(
                    Some(digest_bounded(&mut entry, size)?) == self.index_sha256,
                    "最终产物资源索引已改变"
                );
                index_found = true;
            }
            let size = entry.size();
            if self
                .resources
                .iter()
                .any(|prepared| prepared.plaintext_size == size)
            {
                let digest = digest_bounded(&mut entry, size)?;
                ensure!(
                    !self
                        .resources
                        .iter()
                        .any(|prepared| prepared.plaintext_sha256 == digest),
                    "最终产物含必保资源明文副本"
                );
            }
        }
        ensure!(found.len() == expected.len(), "最终产物缺少必保密文条目");
        ensure!(
            self.index_sha256.is_none() || index_found,
            "最终产物缺少资源索引"
        );
        Ok(())
    }
}

pub(crate) fn verify_android_evidence(artifact: &Path, report: &serde_json::Value) -> Result<()> {
    #[derive(Deserialize)]
    struct Evidence {
        format: u32,
        index_sha256: String,
        resources: Vec<ResourceEvidence>,
    }
    let evidence: Evidence =
        serde_json::from_value(report.clone()).context("业务资源保护报告无效")?;
    ensure!(
        evidence.format == 1 && (1..=MAX_RESOURCES).contains(&evidence.resources.len()),
        "业务资源保护报告版本或条目数无效"
    );
    let prefix = format!("assets/{RESOURCE_DIRECTORY}/");
    let mut expected = BTreeMap::from([(format!("{prefix}index.json"), evidence.index_sha256)]);
    for resource in evidence.resources {
        ensure!(identifier(&resource.id), "报告中的业务资源 ID 无效");
        ensure!(
            expected
                .insert(
                    format!("{prefix}{}.ssr", resource.id),
                    resource.ciphertext_sha256
                )
                .is_none(),
            "业务资源保护报告条目重复"
        );
    }
    let mut archive = crate::protection_report::checked_archive(artifact)?;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let name = entry.name()?;
        if !name.starts_with(&prefix) || entry.is_dir() {
            continue;
        }
        let digest = expected
            .remove(name.as_ref())
            .context("业务资源条目重复或未经核验")?;
        let size = entry.size();
        let max = MAX_RESOURCE_SIZE + (MAX_RESOURCE_SIZE / CHUNK_SIZE as u64) * 28 + 256;
        ensure!(
            size <= max && hex(&digest_bounded(&mut entry, size)?) == digest,
            "业务资源或索引在产物处理中改变"
        );
    }
    ensure!(expected.is_empty(), "最终产物缺少已验证的业务资源");
    Ok(())
}

fn digest_bounded(input: &mut impl Read, length: u64) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    let read = std::io::copy(&mut input.take(length + 1), &mut hash)?;
    ensure!(read == length, "资源实际长度与预期不一致");
    Ok(hash.finalize().into())
}

fn seal_resource(
    rng: &impl SecureRandom,
    build: &[u8; 16],
    resource: &Resource,
    key: &[u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_256_GCM, key)
            .map_err(|_| anyhow::anyhow!("资源密钥无效"))?,
    );
    let mut header = MAGIC.to_vec();
    header.extend_from_slice(build);
    header.push(resource.group.len() as u8);
    header.extend_from_slice(resource.group.as_bytes());
    header.push(resource.id.len() as u8);
    header.extend_from_slice(resource.id.as_bytes());
    header.extend_from_slice(&resource.version.to_be_bytes());
    header.extend_from_slice(&(plaintext.len() as u64).to_be_bytes());
    let mut output = header.clone();
    let mut aad = header;
    let sequence_position = aad.len();
    aad.extend_from_slice(&[0; 4]);
    for (index, bytes) in plaintext.chunks(CHUNK_SIZE).enumerate() {
        aad[sequence_position..].copy_from_slice(&(index as u32).to_be_bytes());
        let nonce = random_bytes::<NONCE_LEN>(rng)?;
        let mut chunk = bytes.to_vec();
        let tag = cipher
            .seal_in_place_separate_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(&aad),
                &mut chunk,
            )
            .map_err(|_| anyhow::anyhow!("资源认证加密失败"))?;
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&chunk);
        output.extend_from_slice(tag.as_ref());
    }
    debug_assert_eq!(
        output.len(),
        sequence_position
            + plaintext.len()
            + plaintext.len().div_ceil(CHUNK_SIZE) * (NONCE_LEN + TAG_LEN)
    );
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zip::{write::SimpleFileOptions, ZipWriter};

    #[test]
    fn 必保资源分片认证与最终产物验证() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().join("input");
        fs::create_dir(&root)?;
        let plaintext = vec![0xA7; CHUNK_SIZE + 17];
        fs::write(root.join("rules.json"), &plaintext)?;
        let manifest = temporary.path().join("resources.json");
        fs::write(&manifest, br#"{"version":1,"resources":[{"id":"rules","group":"policy","source":"rules.json","version":3,"read":"stream"}]}"#)?;
        let output = temporary.path().join(RESOURCE_DIRECTORY);
        let prepared = PreparedResources::prepare(&manifest, &root, &output)?;
        let sealed = fs::read(output.join("rules.ssr"))?;
        let (_, group) = prepared.group_keys().next().unwrap();
        let cipher =
            aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, group).unwrap());
        let header_length = 4 + 16 + 1 + 6 + 1 + 5 + 4 + 8;
        let header = &sealed[..header_length];
        let mut ciphertext = &sealed[header_length..];
        for (index, expected) in plaintext.chunks(CHUNK_SIZE).enumerate() {
            let size = NONCE_LEN + expected.len() + TAG_LEN;
            let (record, remaining) = ciphertext.split_at(size);
            ciphertext = remaining;
            let mut aad = header.to_vec();
            aad.extend_from_slice(&(index as u32).to_be_bytes());
            let mut encrypted = record[NONCE_LEN..].to_vec();
            let nonce = aead::Nonce::try_assume_unique_for_key(&record[..NONCE_LEN]).unwrap();
            assert_eq!(
                cipher
                    .open_in_place(nonce, aead::Aad::from(&aad), &mut encrypted)
                    .unwrap(),
                expected
            );
            aad[header_length - 4] ^= 1;
            let mut modified = record[NONCE_LEN..].to_vec();
            let nonce = aead::Nonce::try_assume_unique_for_key(&record[..NONCE_LEN]).unwrap();
            assert!(cipher
                .open_in_place(nonce, aead::Aad::from(&aad), &mut modified)
                .is_err());
        }
        assert!(ciphertext.is_empty());
        prepared.remove_originals(&root)?;
        assert!(!root.join("rules.json").exists());
        let archive = temporary.path().join("final.apk");
        for duplicate in [false, true] {
            let mut zip = ZipWriter::new(File::create(&archive)?);
            zip.start_file(
                "assets/shellsmith-resources/rules.ssr",
                SimpleFileOptions::default(),
            )?;
            zip.write_all(&sealed)?;
            if duplicate {
                zip.start_file("renamed.json", SimpleFileOptions::default())?;
                zip.write_all(&plaintext)?;
            }
            zip.finish()?;
            assert_eq!(prepared.verify_zip(&archive, "assets/").is_err(), duplicate);
        }
        assert!(PreparedResources::prepare(&manifest, &root, &output).is_err());
        Ok(())
    }
}
