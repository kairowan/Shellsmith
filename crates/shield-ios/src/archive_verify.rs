use crate::confidential;
use crate::project_inspect::IosCheck;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::Command;
use zip::ZipArchive;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveVerification {
    pub app_path: PathBuf,
    pub bundle_id: Option<String>,
    pub executable: Option<String>,
    pub talsec_framework_present: bool,
    pub privacy_manifest_present: bool,
    pub talsec_dsym_matches: Option<bool>,
    pub selected_literal_count: usize,
    pub checks: Vec<IosCheck>,
}

pub fn verify_archive(
    archive: &Path,
    confidential_config: Option<&Path>,
    expect_rasp: bool,
    expected_team_id: &str,
    expected_bundle_ids: &[String],
) -> Result<ArchiveVerification> {
    if !archive.is_dir() {
        anyhow::bail!("Xcode Archive 不存在：{}", archive.display());
    }
    let applications = archive.join("Products").join("Applications");
    let apps = directories_with_extension(&applications, "app")?;
    let app_path = match apps.as_slice() {
        [app] => app.clone(),
        [] => anyhow::bail!("Archive 中没有 .app"),
        _ => anyhow::bail!("Archive 中存在多个主 .app，无法确定验证对象"),
    };
    let mut checks = Vec::new();
    let signature = Command::new("codesign")
        .args(["--verify", "--deep", "--strict", "--verbose=2"])
        .arg(&app_path)
        .output()
        .context("启动 codesign 验证失败")?;
    if signature.status.success() {
        checks.push(IosCheck::ready(
            "codesign",
            "应用和嵌入框架签名严格验证通过",
        ));
    } else {
        checks.push(IosCheck::blocked(
            "codesign",
            format!(
                "签名严格验证失败：{}",
                concise(&String::from_utf8_lossy(&signature.stderr))
            ),
            None,
        ));
    }

    let plist = read_plist_json(&app_path.join("Info.plist"))?;
    let bundle_id = plist
        .get("CFBundleIdentifier")
        .and_then(Value::as_str)
        .map(str::to_string);
    let executable = plist
        .get("CFBundleExecutable")
        .and_then(Value::as_str)
        .map(str::to_string);
    checks.push(if bundle_id.is_some() && executable.is_some() {
        IosCheck::ready("bundle_metadata", "Bundle ID 和主可执行文件元数据完整")
    } else {
        IosCheck::blocked(
            "bundle_metadata",
            "Info.plist 缺少 Bundle ID 或主可执行文件",
            None,
        )
    });

    if let Some(bundle_id) = &bundle_id {
        checks.push(
            if expected_bundle_ids.is_empty() || expected_bundle_ids.contains(bundle_id) {
                IosCheck::ready("bundle_id", format!("产物 Bundle ID 已确认：{bundle_id}"))
            } else {
                IosCheck::blocked(
                    "bundle_id",
                    format!("产物 Bundle ID {bundle_id} 不在配置允许列表中"),
                    None,
                )
            },
        );
    }
    let signature_metadata = codesign_metadata(&app_path)?;
    checks.push(
        if signature_metadata
            .team_id
            .as_deref()
            .is_some_and(|value| value == expected_team_id)
        {
            IosCheck::ready("team_id", "产物签名 Team ID 与配置一致")
        } else {
            IosCheck::blocked(
                "team_id",
                format!(
                    "产物签名 Team ID 不匹配：{}",
                    signature_metadata.team_id.as_deref().unwrap_or("无法读取")
                ),
                None,
            )
        },
    );
    let entitlements = Command::new("codesign")
        .args(["-d", "--entitlements", ":-"])
        .arg(&app_path)
        .output()
        .context("读取签名 Entitlements 失败")?;
    checks.push(
        if entitlements.status.success() && !entitlements.stdout.is_empty() {
            IosCheck::ready("entitlements", "已读取并验证签名 Entitlements")
        } else {
            IosCheck::blocked("entitlements", "无法读取签名 Entitlements", None)
        },
    );
    checks.push(if app_path.join("embedded.mobileprovision").is_file() {
        IosCheck::ready("provisioning", "应用包含 embedded.mobileprovision")
    } else {
        IosCheck::warning(
            "provisioning",
            "应用未包含 embedded.mobileprovision；macOS/Catalyst 或特定分发方式可忽略，iOS 开发/Ad Hoc 导出必须复核",
            None,
        )
    });
    if let Some(executable) = &executable {
        let architectures = macho_architectures(&app_path.join(executable))?;
        checks.push(if architectures.iter().any(|value| value == "arm64") {
            IosCheck::ready("architecture", "主可执行文件包含 arm64")
        } else {
            IosCheck::blocked(
                "architecture",
                format!("主可执行文件缺少 arm64：{}", architectures.join(", ")),
                None,
            )
        });
    }

    let frameworks = app_path.join("Frameworks");
    let talsec_framework = frameworks.join("TalsecRuntime.framework");
    let talsec_framework_present = talsec_framework.is_dir();
    let privacy_manifest_present = talsec_framework.join("PrivacyInfo.xcprivacy").is_file();
    if talsec_framework_present {
        checks.push(IosCheck::ready(
            "freerasp_linked",
            "TalsecRuntime.framework 已嵌入应用",
        ));
        checks.push(if privacy_manifest_present {
            IosCheck::ready(
                "privacy_manifest",
                "freeRASP PrivacyInfo.xcprivacy 已包含在产物中",
            )
        } else {
            IosCheck::blocked(
                "privacy_manifest",
                "TalsecRuntime.framework 缺少 PrivacyInfo.xcprivacy",
                None,
            )
        });
    } else if expect_rasp {
        checks.push(IosCheck::blocked(
            "freerasp_linked",
            "当前保护档要求 freeRASP，但 Archive 中没有 TalsecRuntime.framework",
            Some("https://github.com/talsec/Free-RASP-iOS/issues/55"),
        ));
    }
    let talsec_dsym_matches = if talsec_framework_present {
        Some(verify_talsec_dsym(archive, &talsec_framework)?)
    } else {
        None
    };
    if let Some(matches) = talsec_dsym_matches {
        checks.push(if matches {
            IosCheck::ready("freerasp_dsym", "TalsecRuntime dSYM UUID 与产物匹配")
        } else {
            IosCheck::warning(
                "freerasp_dsym",
                "Archive 缺少匹配的 TalsecRuntime dSYM；上传 App Store 前从对应 freeRASP Release 获取",
                Some("https://github.com/talsec/Free-RASP-iOS/releases"),
            )
        });
    }

    let selected_literals = confidential_config
        .map(confidential::selected_literals)
        .transpose()?
        .unwrap_or_default();
    if !selected_literals.is_empty() {
        let executable_path = executable
            .as_deref()
            .map(|name| app_path.join(name))
            .context("无法定位主可执行文件以验证敏感字符串")?;
        let binary = fs::read(&executable_path)
            .with_context(|| format!("读取主可执行文件失败：{}", executable_path.display()))?;
        let leaked = selected_literals
            .iter()
            .filter(|literal| contains_bytes(&binary, literal))
            .count();
        checks.push(if leaked == 0 {
            IosCheck::ready(
                "confidential_literals",
                format!(
                    "已验证 {} 个选择性敏感字符串未以连续明文出现",
                    selected_literals.len()
                ),
            )
        } else {
            IosCheck::blocked(
                "confidential_literals",
                format!("发现 {leaked} 个选择性敏感字符串仍以连续明文出现"),
                None,
            )
        });
    }
    Ok(ArchiveVerification {
        app_path,
        bundle_id,
        executable,
        talsec_framework_present,
        privacy_manifest_present,
        talsec_dsym_matches,
        selected_literal_count: selected_literals.len(),
        checks,
    })
}

#[derive(Default)]
struct CodesignMetadata {
    team_id: Option<String>,
}

fn codesign_metadata(app: &Path) -> Result<CodesignMetadata> {
    let output = Command::new("codesign")
        .args(["-d", "--verbose=4"])
        .arg(app)
        .output()
        .context("读取 codesign 元数据失败")?;
    let text = String::from_utf8_lossy(&output.stderr);
    Ok(CodesignMetadata {
        team_id: text
            .lines()
            .find_map(|line| line.trim().strip_prefix("TeamIdentifier="))
            .map(str::to_string),
    })
}

fn macho_architectures(binary: &Path) -> Result<Vec<String>> {
    let output = Command::new("lipo")
        .arg("-archs")
        .arg(binary)
        .output()
        .context("读取 Mach-O 架构失败")?;
    if !output.status.success() {
        anyhow::bail!("lipo 无法读取主可执行文件架构");
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .map(str::to_string)
        .collect())
}

pub(crate) fn find_single_ipa(export_directory: &Path) -> Result<PathBuf> {
    let mut ipa_files = Vec::new();
    for entry in fs::read_dir(export_directory)
        .with_context(|| format!("读取 IPA 导出目录失败：{}", export_directory.display()))?
    {
        let path = entry?.path();
        if path.extension().and_then(|value| value.to_str()) == Some("ipa") {
            ipa_files.push(path);
        }
    }
    let ipa = match ipa_files.as_slice() {
        [ipa] => ipa.clone(),
        [] => anyhow::bail!("xcodebuild 导出成功但没有生成 IPA"),
        _ => anyhow::bail!("导出目录包含多个 IPA，无法确定主产物"),
    };
    validate_ipa_structure(&ipa)?;
    Ok(ipa)
}

fn validate_ipa_structure(path: &Path) -> Result<()> {
    let file = File::open(path)?;
    let mut archive = ZipArchive::new(file).context("IPA 不是有效 ZIP")?;
    let mut has_info = false;
    let mut has_executable_container = false;
    for index in 0..archive.len() {
        let entry = archive.by_index(index)?;
        let name = entry.name();
        if name.starts_with("Payload/") && name.ends_with(".app/Info.plist") {
            has_info = true;
        }
        if name.starts_with("Payload/") && name.contains(".app/") {
            has_executable_container = true;
        }
    }
    if !has_info || !has_executable_container {
        anyhow::bail!("IPA 缺少 Payload/*.app/Info.plist");
    }
    Ok(())
}

fn read_plist_json(path: &Path) -> Result<Value> {
    let output = Command::new("plutil")
        .args(["-convert", "json", "-o", "-"])
        .arg(path)
        .output()
        .context("启动 plutil 失败")?;
    if !output.status.success() {
        anyhow::bail!(
            "读取 Info.plist 失败：{}",
            concise(&String::from_utf8_lossy(&output.stderr))
        );
    }
    serde_json::from_slice(&output.stdout).context("解析 Info.plist JSON 失败")
}

fn verify_talsec_dsym(archive: &Path, framework: &Path) -> Result<bool> {
    let binary = framework.join("TalsecRuntime");
    let binary_uuids = macho_uuids(&binary)?;
    let dsym_root = archive.join("dSYMs").join("TalsecRuntime.framework.dSYM");
    if !dsym_root.is_dir() {
        return Ok(false);
    }
    let dsym_binary = dsym_root
        .join("Contents")
        .join("Resources")
        .join("DWARF")
        .join("TalsecRuntime");
    if !dsym_binary.is_file() {
        return Ok(false);
    }
    let dsym_uuids = macho_uuids(&dsym_binary)?;
    Ok(!binary_uuids.is_empty() && binary_uuids.is_subset(&dsym_uuids))
}

fn macho_uuids(path: &Path) -> Result<BTreeSet<String>> {
    let output = Command::new("dwarfdump")
        .arg("--uuid")
        .arg(path)
        .output()
        .context("启动 dwarfdump 失败")?;
    if !output.status.success() {
        return Ok(BTreeSet::new());
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().nth(1))
        .map(|value| value.to_ascii_uppercase())
        .collect())
}

fn directories_with_extension(root: &Path, extension: &str) -> Result<Vec<PathBuf>> {
    let mut result = Vec::new();
    for entry in fs::read_dir(root)
        .with_context(|| format!("读取 Archive 应用目录失败：{}", root.display()))?
    {
        let path = entry?.path();
        if path.is_dir() && path.extension().and_then(|value| value.to_str()) == Some(extension) {
            result.push(path);
        }
    }
    Ok(result)
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn concise(value: &str) -> String {
    value
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .take(8)
        .collect::<Vec<_>>()
        .join("；")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn validates_minimal_ipa_shape() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        {
            let mut zip = zip::ZipWriter::new(temp.reopen().unwrap());
            zip.start_file(
                "Payload/Demo.app/Info.plist",
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
            zip.write_all(b"plist").unwrap();
            zip.finish().unwrap();
        }
        assert!(validate_ipa_structure(temp.path()).is_ok());
    }

    #[test]
    fn byte_search_handles_short_inputs() {
        assert!(contains_bytes(b"abc-secret-xyz", b"secret"));
        assert!(!contains_bytes(b"abc", b"long-secret"));
    }
}
