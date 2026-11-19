use anyhow::{Context, Result};
use rand::{rngs::OsRng, TryRngCore};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

use crate::protect::dex::patch_dex_header;

const SUPPORTED_SCHEME: u32 = 1;
const MAX_ATTEMPTS: usize = 64;
const RESERVED_LIBRARY_NAMES: &[&str] = &[
    "libandroid.so",
    "libc.so",
    "libdl.so",
    "liblog.so",
    "libm.so",
    "libmocikashield.so",
];

// 只使用审查过的中性组合；设备批准运行时包含独立的 `module` 字符串，
// 因此候选必须排在它之前。实际 string_ids 边界仍在替换前复验。
// 所有主体均为 16 个小写 ASCII 字母。
const ALIAS_BODIES: &[&str] = &[
    "modularcorecache",
    "modulardatacache",
    "modularbasecache",
    "modularutilcache",
    "modularappcachex",
    "modularjnicachex",
    "modularapicachex",
    "modularruntimeid",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NativeAliasProtocol {
    pub(crate) canonical_file_name: String,
    pub(crate) placeholder: String,
    pub(crate) name_length: usize,
}

impl NativeAliasProtocol {
    pub(crate) fn parse(metadata: &str) -> Result<Self> {
        let canonical_file_name = parse_json_string_field(metadata, "native_library")
            .context("metadata.json 缺少 native_library")?;
        let placeholder = parse_json_string_field(metadata, "native_name_placeholder")
            .context("metadata.json 缺少 native_name_placeholder")?;
        let name_length = parse_json_u32_field(metadata, "native_name_length")
            .context("metadata.json 缺少 native_name_length")? as usize;
        let scheme = parse_json_u32_field(metadata, "native_name_scheme")
            .context("metadata.json 缺少 native_name_scheme")?;

        if scheme != SUPPORTED_SCHEME {
            anyhow::bail!("不支持的 Native 名称协议版本: {scheme}");
        }
        if canonical_file_name != "libmocikashield.so" {
            anyhow::bail!("Native 规范库名称不受支持: {canonical_file_name}");
        }
        if name_length != 16 || placeholder.len() != name_length {
            anyhow::bail!(
                "Native 名称协议长度不一致: placeholder={}, length={name_length}",
                placeholder.len()
            );
        }
        if !is_lower_ascii_name(&placeholder) {
            anyhow::bail!("Native 名称占位符必须只包含小写 ASCII 字母");
        }

        Ok(Self {
            canonical_file_name,
            placeholder,
            name_length,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NativeAlias {
    body: String,
}

#[derive(Debug, Default)]
pub(crate) struct OriginalNativeLibraries {
    pub(crate) abis: HashSet<String>,
    file_names: HashSet<String>,
}

#[derive(Debug)]
pub(crate) struct InjectedNativeRuntime {
    pub(crate) alias_file_name: String,
    pub(crate) injected_abis: HashSet<String>,
    pub(crate) placeholder: String,
    pub(crate) canonical_file_name: String,
    /// 各 ABI 下壳库的明文 SHA-256（小写十六进制）。壳库在打包中只改名不改字节，
    /// 该摘要写入 manifest 后由运行时在加载前比对。
    pub(crate) shell_digests: std::collections::BTreeMap<String, String>,
}

impl NativeAlias {
    pub(crate) fn generate(original: &OriginalNativeLibraries) -> Result<Self> {
        let mut random = OsRng;
        let start = random
            .try_next_u64()
            .context("系统安全随机源不可用，无法生成 Native 别名")? as usize
            % ALIAS_BODIES.len();
        Self::select_from(start, &original.file_names)
    }

    fn select_from(start: usize, existing_file_names: &HashSet<String>) -> Result<Self> {
        let reserved: HashSet<&str> = RESERVED_LIBRARY_NAMES.iter().copied().collect();
        for offset in 0..ALIAS_BODIES.len().min(MAX_ATTEMPTS) {
            let body = ALIAS_BODIES[(start + offset) % ALIAS_BODIES.len()];
            let file_name = format!("lib{body}.so");
            let normalized = file_name.to_ascii_lowercase();
            if !existing_file_names.contains(&normalized) && !reserved.contains(normalized.as_str())
            {
                return Ok(Self {
                    body: body.to_string(),
                });
            }
        }
        anyhow::bail!("无法在 {MAX_ATTEMPTS} 次尝试内生成无冲突的 Native 别名")
    }

    pub(crate) fn body(&self) -> &str {
        &self.body
    }

    pub(crate) fn file_name(&self) -> String {
        format!("lib{}.so", self.body)
    }
}

pub(crate) fn inspect_original_apk(apk_path: &Path) -> Result<OriginalNativeLibraries> {
    let file = fs::File::open(apk_path).context("打开原始 APK 扫描 Native 库失败")?;
    let mut archive = zip::ZipArchive::new(file).context("解析原始 APK 失败")?;
    let mut result = OriginalNativeLibraries::default();
    let mut normalized_paths = HashSet::new();
    for index in 0..archive.len() {
        let entry = archive.by_index(index)?;
        let name = entry.name()?.to_string();
        if !name.starts_with("lib/") || !name.to_ascii_lowercase().ends_with(".so") {
            continue;
        }
        if name.contains('\\') || name.split('/').any(|part| part == "." || part == "..") {
            anyhow::bail!("原始 APK 存在异常 Native 库路径: {name}");
        }
        let normalized_path = name.to_ascii_lowercase();
        if !normalized_paths.insert(normalized_path) {
            anyhow::bail!("原始 APK 存在大小写不敏感的重复 Native 路径: {name}");
        }
        let mut parts = name.split('/');
        let _lib = parts.next();
        let abi = parts.next().unwrap_or("");
        let file_name = parts.next().unwrap_or("");
        if abi.is_empty() || file_name.is_empty() || parts.next().is_some() {
            anyhow::bail!("原始 APK 存在异常 Native 库路径: {name}");
        }
        if file_name.eq_ignore_ascii_case("libmocikashield.so") {
            anyhow::bail!("原始 APK 已包含 Native 规范库名称，无法安全生成别名");
        }
        result.abis.insert(abi.to_string());
        result.file_names.insert(file_name.to_ascii_lowercase());
    }
    Ok(result)
}

pub(crate) fn map_resource_path(
    path: &str,
    canonical_file_name: &str,
    alias_file_name: &str,
) -> String {
    if path.starts_with("lib/") && path.rsplit('/').next() == Some(canonical_file_name) {
        let parent = path
            .rsplit_once('/')
            .map(|(parent, _)| parent)
            .unwrap_or("");
        format!("{parent}/{alias_file_name}")
    } else {
        path.to_string()
    }
}

pub(crate) fn verify_in_apk(apk_path: &Path, runtime: &InjectedNativeRuntime) -> Result<()> {
    use std::io::Read as _;

    let file = fs::File::open(apk_path).context("打开加固 APK 进行 Native 别名复验失败")?;
    let mut archive = zip::ZipArchive::new(file).context("解析加固 APK 失败")?;
    let mut found_abis = HashSet::new();
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let name = entry.name()?.to_string();
        let base_name = name.rsplit('/').next().unwrap_or("");
        if base_name.eq_ignore_ascii_case(&runtime.canonical_file_name) {
            anyhow::bail!("加固 APK 仍包含 Native 规范库名称: {name}");
        }
        if base_name.eq_ignore_ascii_case(&runtime.alias_file_name) && name.starts_with("lib/") {
            if let Some(abi) = name.split('/').nth(1) {
                found_abis.insert(abi.to_string());
            }
        }
        if name == "classes.dex" {
            let mut dex = Vec::new();
            entry.read_to_end(&mut dex)?;
            if dex
                .windows(runtime.placeholder.len())
                .any(|bytes| bytes == runtime.placeholder.as_bytes())
            {
                anyhow::bail!("加固 APK 的 Stub DEX 仍包含 Native 名称占位符");
            }
        }
    }
    if found_abis != runtime.injected_abis {
        anyhow::bail!(
            "Native 别名 ABI 复验失败: 期望 {:?}，实际 {:?}",
            runtime.injected_abis,
            found_abis
        );
    }
    Ok(())
}

pub(crate) fn patch_stub_dex(
    dex_path: &Path,
    protocol: &NativeAliasProtocol,
    alias: &NativeAlias,
) -> Result<()> {
    if alias.body().len() != protocol.name_length {
        anyhow::bail!("Native 别名长度与资源协议不一致");
    }

    let mut dex = fs::read(dex_path).context("读取 Stub DEX 失败")?;
    if dex.len() < 36 {
        anyhow::bail!("Stub DEX 过短，无法读取 file_size");
    }
    let logical_size = u32::from_le_bytes(dex[32..36].try_into().unwrap()) as usize;
    if logical_size < 36 || logical_size > dex.len() {
        anyhow::bail!("Stub DEX file_size 非法: {logical_size}");
    }

    let placeholder = protocol.placeholder.as_bytes();
    let matches: Vec<usize> = dex[..logical_size]
        .windows(placeholder.len())
        .enumerate()
        .filter_map(|(index, value)| (value == placeholder).then_some(index))
        .collect();
    if matches.len() != 1 {
        anyhow::bail!(
            "Stub DEX 中 Native 名称占位符应出现一次，实际出现 {} 次",
            matches.len()
        );
    }

    let start = matches[0];
    validate_alias_order(&dex[..logical_size], start, alias.body().as_bytes())?;
    dex[start..start + placeholder.len()].copy_from_slice(alias.body().as_bytes());
    fs::write(dex_path, dex).context("写回 Stub DEX Native 别名失败")?;
    patch_dex_header(dex_path).context("修复 Stub DEX header 失败")
}

fn validate_alias_order(dex: &[u8], start: usize, alias: &[u8]) -> Result<()> {
    anyhow::ensure!(dex.len() >= 112, "Stub DEX 缺少完整头部");
    let count = u32::from_le_bytes(dex[56..60].try_into().unwrap()) as usize;
    let offset = u32::from_le_bytes(dex[60..64].try_into().unwrap()) as usize;
    let table = offset
        .checked_add(count.checked_mul(4).context("Stub DEX 字符串表溢出")?)
        .and_then(|end| dex.get(offset..end))
        .context("Stub DEX 字符串表越界")?;
    let string_start = |index: usize| -> Result<usize> {
        let entry = table
            .get(index * 4..index * 4 + 4)
            .context("Stub DEX 字符串索引越界")?;
        let offset = u32::from_le_bytes(entry.try_into().unwrap()) as usize;
        let length_size = dex
            .get(offset..)
            .context("Stub DEX 字符串越界")?
            .iter()
            .take(5)
            .position(|byte| byte & 0x80 == 0)
            .context("Stub DEX 字符串长度无效")?
            + 1;
        Ok(offset + length_size)
    };
    let index = (0..count)
        .find(|&index| string_start(index).ok() == Some(start))
        .context("Native 占位符不是独立的 DEX 字符串")?;
    anyhow::ensure!(
        dex.get(start + alias.len()) == Some(&0),
        "Native 占位符不是完整的 DEX 字符串"
    );
    for neighbor in [
        index.checked_sub(1),
        (index + 1 < count).then_some(index + 1),
    ]
    .into_iter()
    .flatten()
    {
        let bytes = dex
            .get(string_start(neighbor)?..)
            .context("Stub DEX 字符串越界")?;
        let value = bytes
            .get(
                ..bytes
                    .iter()
                    .position(|&byte| byte == 0)
                    .context("Stub DEX 字符串未终止")?,
            )
            .context("Stub DEX 字符串越界")?;
        // ponytail: 当前相邻字符串都是 ASCII；遇到新的 MUTF-8 边界时先拒绝，不能按 UTF-8 猜测 UTF-16 排序。
        anyhow::ensure!(value.is_ascii(), "Native 别名遇到未支持的 DEX 排序边界");
        anyhow::ensure!(
            if neighbor < index {
                value < alias
            } else {
                alias < value
            },
            "Native 别名超出 Stub DEX 字符串排序边界"
        );
    }
    Ok(())
}

fn is_lower_ascii_name(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_lowercase())
}

fn parse_json_string_field(json: &str, field: &str) -> Option<String> {
    let needle = format!("\"{field}\"");
    let after_key = &json[json.find(&needle)? + needle.len()..];
    let after_quote = after_key
        .trim_start()
        .strip_prefix(':')?
        .trim_start()
        .strip_prefix('"')?;
    let end = after_quote.find('"')?;
    Some(after_quote[..end].to_string())
}

fn parse_json_u32_field(json: &str, field: &str) -> Option<u32> {
    let needle = format!("\"{field}\"");
    let after_key = &json[json.find(&needle)? + needle.len()..];
    let value = after_key.trim_start().strip_prefix(':')?.trim_start();
    let end = value
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(value.len());
    value[..end].parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn protocol() -> NativeAliasProtocol {
        NativeAliasProtocol {
            canonical_file_name: "libmocikashield.so".to_string(),
            placeholder: "mocikanativeslot".to_string(),
            name_length: 16,
        }
    }

    #[test]
    fn all_alias_candidates_follow_contract() {
        assert!(ALIAS_BODIES.len() >= 8);
        let mut unique = HashSet::new();
        for body in ALIAS_BODIES {
            assert!(unique.insert(*body), "重复候选: {body}");
            assert_eq!(body.len(), 16, "非法候选: {body}");
            assert!(is_lower_ascii_name(body), "非法候选: {body}");
            assert!(
                body.starts_with("modular") && *body < "module",
                "候选超出 DEX 字典序安全区间: {body}"
            );
            for forbidden in ["mocika", "shield", "protect", "packer", "shell", "bugly"] {
                assert!(!body.contains(forbidden), "候选包含禁用词: {body}");
            }
            for role in ["native", "common", "module", "engine", "runtime", "support"] {
                assert!(
                    !(body.starts_with(role) && body.ends_with(role)),
                    "候选首尾角色词重复: {body}"
                );
            }
        }
    }

    #[test]
    fn protocol_parses_required_fields() {
        let metadata = r#"{
            "native_library": "libmocikashield.so",
            "native_name_placeholder": "mocikanativeslot",
            "native_name_length": 16,
            "native_name_scheme": 1
        }"#;
        assert_eq!(NativeAliasProtocol::parse(metadata).unwrap(), protocol());
    }

    #[test]
    fn protocol_rejects_missing_or_unsupported_scheme() {
        let missing = r#"{"native_library":"libmocikashield.so"}"#;
        assert!(NativeAliasProtocol::parse(missing).is_err());
        let unsupported = r#"{
            "native_library":"libmocikashield.so",
            "native_name_placeholder":"mocikanativeslot",
            "native_name_length":16,
            "native_name_scheme":2
        }"#;
        assert!(NativeAliasProtocol::parse(unsupported).is_err());
    }

    #[test]
    fn selection_skips_case_insensitive_conflicts() {
        let mut existing = HashSet::new();
        existing.insert("libmodularcorecache.so".to_string());
        let alias = NativeAlias::select_from(0, &existing).unwrap();
        assert_eq!(alias.body(), "modulardatacache");
    }

    #[test]
    fn selection_fails_when_all_candidates_conflict() {
        let existing = ALIAS_BODIES
            .iter()
            .map(|body| format!("lib{body}.so"))
            .collect();
        assert!(NativeAlias::select_from(0, &existing).is_err());
    }

    #[test]
    fn patch_replaces_exactly_one_placeholder() {
        let dir = tempfile::tempdir().unwrap();
        let dex_path = dir.path().join("classes.dex");
        let mut dex = vec![0u8; 124];
        dex[0..8].copy_from_slice(b"dex\n035\0");
        dex[56..60].copy_from_slice(&3u32.to_le_bytes());
        dex[60..64].copy_from_slice(&112u32.to_le_bytes());
        for (index, value) in ["mocika_runtime", "mocikanativeslot", "module"]
            .iter()
            .enumerate()
        {
            let offset = dex.len() as u32;
            dex[112 + index * 4..116 + index * 4].copy_from_slice(&offset.to_le_bytes());
            dex.push(value.len() as u8);
            dex.extend_from_slice(value.as_bytes());
            dex.push(0);
        }
        let size = dex.len() as u32;
        dex[32..36].copy_from_slice(&size.to_le_bytes());
        fs::write(&dex_path, dex).unwrap();

        let original = fs::read(&dex_path).unwrap();
        let bad_alias = NativeAlias {
            body: "modulecorebridge".into(),
        };
        assert!(patch_stub_dex(&dex_path, &protocol(), &bad_alias).is_err());
        assert_eq!(
            fs::read(&dex_path).unwrap(),
            original,
            "排序失败不能写坏原文件"
        );
        let alias = NativeAlias::select_from(0, &HashSet::new()).unwrap();
        patch_stub_dex(&dex_path, &protocol(), &alias).unwrap();
        let patched = fs::read(&dex_path).unwrap();
        assert!(patched
            .windows(16)
            .any(|item| item == alias.body().as_bytes()));
        assert!(!patched.windows(16).any(|item| item == b"mocikanativeslot"));
    }

    #[test]
    fn patch_rejects_missing_or_repeated_placeholder() {
        let dir = tempfile::tempdir().unwrap();
        let dex_path = dir.path().join("classes.dex");
        let mut dex = vec![0u8; 96];
        dex[32..36].copy_from_slice(&(96u32).to_le_bytes());
        fs::write(&dex_path, &dex).unwrap();
        let alias = NativeAlias::select_from(0, &HashSet::new()).unwrap();
        assert!(patch_stub_dex(&dex_path, &protocol(), &alias).is_err());

        dex[40..56].copy_from_slice(b"mocikanativeslot");
        dex[64..80].copy_from_slice(b"mocikanativeslot");
        fs::write(&dex_path, dex).unwrap();
        assert!(patch_stub_dex(&dex_path, &protocol(), &alias).is_err());
    }
}
