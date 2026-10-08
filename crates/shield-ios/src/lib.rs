mod archive_verify;
mod confidential;
mod freerasp;
mod project_inspect;
mod project_patch;
mod signing;
mod xcodebuild;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{atomic::AtomicBool, Arc};

pub use archive_verify::{verify_archive, ArchiveVerification};
pub use project_inspect::{inspect_ios_project, IosCheck, IosCheckSeverity, IosProjectInspection};

pub const SWIFT_CONFIDENTIAL_VERSION: &str = "0.5.2";
pub const SWIFT_CONFIDENTIAL_PLUGIN_VERSION: &str = "0.5.2";
pub const FREERASP_IOS_VERSION: &str = "7.1.4";
pub const IOS_REPORT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum IosProtectionProfile {
    Compat,
    #[default]
    Balanced,
    Strict,
}

impl IosProtectionProfile {
    pub fn uses_confidential(self) -> bool {
        !matches!(self, Self::Compat)
    }

    pub fn uses_rasp(self) -> bool {
        !matches!(self, Self::Compat)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Compat => "compat",
            Self::Balanced => "balanced",
            Self::Strict => "strict",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IosProjectConfig {
    pub path: PathBuf,
    pub scheme: String,
    #[serde(default = "release_configuration")]
    pub configuration: String,
    pub team_id: String,
    #[serde(default)]
    pub bundle_ids: Vec<String>,
    #[serde(default)]
    pub entrypoint: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IosProtectionConfig {
    #[serde(default)]
    pub profile: IosProtectionProfile,
    #[serde(default = "default_true")]
    pub is_prod: bool,
    #[serde(default)]
    pub app_attest_endpoint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IosConfidentialConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub config: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IosRaspConfig {
    #[serde(default = "default_rasp_provider")]
    pub provider: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub watcher_mail: Option<String>,
    #[serde(default = "default_critical_threats")]
    pub critical: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellsmithIosConfig {
    pub project: IosProjectConfig,
    #[serde(default)]
    pub protection: IosProtectionConfig,
    #[serde(default)]
    pub confidential: Option<IosConfidentialConfig>,
    #[serde(default)]
    pub rasp: Option<IosRaspConfig>,
}

impl ShellsmithIosConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("读取 iOS 配置失败：{}", path.display()))?;
        let mut config: Self = toml::from_str(&content)
            .with_context(|| format!("解析 iOS 配置失败：{}", path.display()))?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        if config.project.path.is_relative() {
            config.project.path = base.join(&config.project.path);
        }
        if let Some(entrypoint) = &mut config.project.entrypoint {
            if entrypoint.is_relative() {
                let project_root = config
                    .project
                    .path
                    .parent()
                    .context("iOS 工程路径缺少源码根目录")?;
                *entrypoint = project_root.join(&*entrypoint);
            }
        }
        if let Some(confidential) = &mut config.confidential {
            if confidential.config.is_relative() {
                confidential.config = base.join(&confidential.config);
            }
        }
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.project.scheme.trim().is_empty() {
            anyhow::bail!("iOS scheme 不能为空");
        }
        if self.project.configuration.trim().is_empty() {
            anyhow::bail!("iOS configuration 不能为空");
        }
        if self.project.team_id.len() != 10
            || !self
                .project
                .team_id
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        {
            anyhow::bail!("Apple Team ID 必须是 10 位大写字母或数字");
        }
        if self.project.bundle_ids.is_empty() {
            anyhow::bail!("至少需要一个 iOS Bundle ID");
        }
        for bundle_id in &self.project.bundle_ids {
            validate_bundle_id(bundle_id)?;
        }
        if self.confidential_enabled() {
            let confidential = self
                .confidential
                .as_ref()
                .expect("confidential_enabled implies a configuration");
            if !confidential.config.is_file() {
                anyhow::bail!(
                    "Swift Confidential 配置不存在：{}",
                    confidential.config.display()
                );
            }
        }
        if self.protection.profile.uses_rasp() {
            let rasp = self
                .rasp
                .as_ref()
                .filter(|item| item.enabled)
                .ok_or_else(|| anyhow::anyhow!("balanced/strict 必须启用 iOS RASP"))?;
            if rasp.provider != "freerasp" {
                anyhow::bail!("第一版只支持 freerasp provider");
            }
            if let Some(mail) = &rasp.watcher_mail {
                if !mail.trim().is_empty() {
                    validate_email(mail.trim())?;
                }
            }
            for threat in &rasp.critical {
                if !freerasp::KNOWN_THREATS.contains(&threat.as_str()) {
                    anyhow::bail!("未知的 freeRASP 威胁类型：{threat}");
                }
            }
        }
        if matches!(self.protection.profile, IosProtectionProfile::Strict) {
            if let Some(endpoint) = self
                .protection
                .app_attest_endpoint
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                validate_https_endpoint(endpoint)?;
            }
        }
        Ok(())
    }

    /// Swift Confidential is an optional enhancement. RASP remains active when
    /// the caller does not provide a project-specific literal configuration.
    pub fn confidential_enabled(&self) -> bool {
        self.protection.profile.uses_confidential()
            && self.confidential.as_ref().is_some_and(|item| item.enabled)
    }
}

impl Default for IosProtectionConfig {
    fn default() -> Self {
        Self {
            profile: IosProtectionProfile::Balanced,
            is_prod: true,
            app_attest_endpoint: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProtectIosOptions {
    pub config: ShellsmithIosConfig,
    pub output_dir: PathBuf,
    pub export_options: Option<PathBuf>,
    pub export_method: String,
    pub allow_provisioning_updates: bool,
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IosProgressEvent {
    pub step: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IosProtectionReport {
    pub schema_version: u32,
    pub profile: IosProtectionProfile,
    pub inspection: IosProjectInspection,
    pub output_project: Option<PathBuf>,
    pub archive: Option<PathBuf>,
    pub ipa: Option<PathBuf>,
    pub archive_verification: Option<ArchiveVerification>,
    pub checks: Vec<IosCheck>,
}

pub fn protect_ios_project<F>(
    options: &ProtectIosOptions,
    on_progress: F,
    cancel: Arc<AtomicBool>,
) -> Result<IosProtectionReport>
where
    F: Fn(IosProgressEvent) + Send + Sync,
{
    options.config.validate()?;
    signing::validate_export_request(options.export_options.as_deref(), &options.export_method)?;
    progress(
        &on_progress,
        "InspectProject",
        "正在检查 Xcode 工程和工具链",
    );
    let inspection = inspect_ios_project(
        &options.config.project.path,
        Some(&options.config.project.scheme),
    )?;
    let mut checks = inspection.checks.clone();
    project_inspect::validate_protection_target(
        &inspection,
        options.config.protection.profile,
        &options.config.project.team_id,
        &options.config.project.bundle_ids,
    )?;
    checks.extend(project_inspect::known_issue_checks(
        &inspection,
        options.config.protection.profile,
        options.config.confidential_enabled(),
    ));
    if matches!(
        options.config.protection.profile,
        IosProtectionProfile::Strict
    ) {
        let endpoint_configured = options
            .config
            .protection
            .app_attest_endpoint
            .as_deref()
            .map(str::trim)
            .is_some_and(|value| !value.is_empty());
        checks.push(if endpoint_configured {
            IosCheck::ready(
                "app_attest_endpoint",
                "已配置 App Attest 服务端地址；仍需由业务服务端完成证明和重放校验",
            )
        } else {
            IosCheck::warning(
                "app_attest_endpoint",
                "未配置 App Attest 服务端地址；本次仍执行客户端严格加固，但不包含服务端设备证明闭环",
                None,
            )
        });
    }

    if options.dry_run {
        return Ok(IosProtectionReport {
            schema_version: IOS_REPORT_SCHEMA_VERSION,
            profile: options.config.protection.profile,
            inspection,
            output_project: None,
            archive: None,
            ipa: None,
            archive_verification: None,
            checks,
        });
    }

    if !cfg!(target_os = "macos") || !inspection.xcode.available {
        anyhow::bail!("iOS Archive 需要安装完整 Xcode 的 macOS；当前环境只能执行检查或 --dry-run");
    }

    project_inspect::validate_output_location(&inspection.source_root, &options.output_dir)?;
    progress(
        &on_progress,
        "CopyProject",
        "正在创建不修改原工程的工作副本",
    );
    let working_root = project_patch::copy_project_tree(
        &inspection.source_root,
        &options.output_dir.join("project"),
        &cancel,
    )?;
    let relative_project = options
        .config
        .project
        .path
        .strip_prefix(&inspection.source_root)
        .context("工程路径不在源码根目录内")?;
    let working_project = working_root.join(relative_project);

    if options.config.confidential_enabled() || options.config.protection.profile.uses_rasp() {
        progress(
            &on_progress,
            "IntegrateProtection",
            "正在生成并接入 ShellsmithRuntime",
        );
        let target = inspection
            .primary_application_target()
            .context("没有找到可接入的 iOS 应用 target")?;
        let confidential_path = options
            .config
            .confidential
            .as_ref()
            .filter(|item| item.enabled)
            .map(|item| item.config.as_path());
        project_patch::integrate_runtime(
            &working_root,
            &working_project,
            target,
            &options.config,
            confidential_path,
        )?;
    }

    progress(
        &on_progress,
        "ResolvePackages",
        "正在解析并锁定 Swift Package 依赖",
    );
    let developer_dir = inspection.xcode.developer_dir.as_deref().map(Path::new);
    xcodebuild::resolve_packages(
        &working_project,
        &options.config.project.scheme,
        developer_dir,
        &cancel,
    )?;
    if options.config.confidential_enabled() || options.config.protection.profile.uses_rasp() {
        let package_check = verify_package_lock(
            &working_project,
            options.config.confidential_enabled(),
            options.config.protection.profile.uses_rasp(),
        )?;
        if package_check.severity == IosCheckSeverity::Blocked {
            anyhow::bail!("Swift Package 依赖检查失败：{}", package_check.message);
        }
        checks.push(package_check);
    }

    let archive = options.output_dir.join("Shellsmith.xcarchive");
    progress(&on_progress, "Archive", "正在生成 Xcode Archive");
    xcodebuild::archive(
        &working_project,
        &options.config.project,
        &archive,
        developer_dir,
        options.allow_provisioning_updates,
        &cancel,
    )?;

    let export_options = signing::prepare_export_options(
        &options.output_dir,
        options.export_options.as_deref(),
        &options.export_method,
        &options.config.project.team_id,
    )?;
    let export_dir = options.output_dir.join("export");
    progress(&on_progress, "ExportArchive", "正在导出已签名 IPA");
    xcodebuild::export_archive(
        &archive,
        &export_dir,
        &export_options,
        developer_dir,
        options.allow_provisioning_updates,
        &cancel,
    )?;
    let ipa = archive_verify::find_single_ipa(&export_dir)?;

    progress(
        &on_progress,
        "VerifyArchive",
        "正在验证签名、权限、架构和第三方框架",
    );
    let verification = verify_archive(
        &archive,
        options
            .config
            .confidential
            .as_ref()
            .filter(|item| options.config.confidential_enabled() && item.enabled)
            .map(|item| item.config.as_path()),
        options.config.protection.profile.uses_rasp(),
        &options.config.project.team_id,
        &options.config.project.bundle_ids,
    )?;
    checks.extend(verification.checks.clone());
    let report = IosProtectionReport {
        schema_version: IOS_REPORT_SCHEMA_VERSION,
        profile: options.config.protection.profile,
        inspection,
        output_project: Some(working_project),
        archive: Some(archive),
        ipa: Some(ipa),
        archive_verification: Some(verification),
        checks,
    };
    fs::write(
        options.output_dir.join("shellsmith-report.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    if report
        .checks
        .iter()
        .any(|check| check.severity == IosCheckSeverity::Blocked)
    {
        anyhow::bail!(
            "iOS 产物验证存在阻断项，详见 {}",
            options.output_dir.join("shellsmith-report.json").display()
        );
    }
    progress(&on_progress, "Complete", "iOS 保护、签名和验证已完成");
    Ok(report)
}

fn progress<F: Fn(IosProgressEvent)>(callback: &F, step: &str, message: &str) {
    callback(IosProgressEvent {
        step: step.to_string(),
        message: message.to_string(),
    });
}

fn verify_package_lock(
    root: &Path,
    require_confidential: bool,
    require_rasp: bool,
) -> Result<IosCheck> {
    let mut matches = Vec::new();
    collect_package_locks(root, 0, &mut matches)?;
    let preferred = matches
        .iter()
        .filter(|path| path.to_string_lossy().contains("swiftpm"))
        .cloned()
        .collect::<Vec<_>>();
    let selected = if preferred.len() == 1 {
        preferred
    } else {
        matches
    };
    match selected.as_slice() {
        [] => Ok(IosCheck::blocked(
            "swift_package_lock",
            "未找到 Package.resolved；无法证明 Swift Package 依赖可复现",
            None,
        )),
        [path] => {
            let bytes = fs::read(path)
                .with_context(|| format!("读取 Swift Package 锁文件失败：{}", path.display()))?;
            if bytes.is_empty() {
                return Ok(IosCheck::blocked(
                    "swift_package_lock",
                    "Package.resolved 为空",
                    None,
                ));
            }
            let document: serde_json::Value = match serde_json::from_slice(&bytes) {
                Ok(value) => value,
                Err(error) => {
                    return Ok(IosCheck::blocked(
                        "swift_package_lock",
                        format!("Package.resolved 不是有效 JSON：{error}"),
                        None,
                    ));
                }
            };
            let pins = document
                .get("pins")
                .and_then(serde_json::Value::as_array)
                .cloned()
                .unwrap_or_default();
            let has_version = |needle: &str, version: &str| {
                pins.iter().any(|pin| {
                    let identity = pin
                        .get("identity")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .to_ascii_lowercase();
                    let resolved = pin
                        .get("state")
                        .and_then(|state| state.get("version"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default();
                    identity.contains(needle) && resolved == version
                })
            };
            if require_confidential
                && (!has_version("swift-confidential", SWIFT_CONFIDENTIAL_VERSION)
                    || !has_version(
                        "swift-confidential-plugin",
                        SWIFT_CONFIDENTIAL_PLUGIN_VERSION,
                    ))
            {
                return Ok(IosCheck::blocked(
                    "swift_package_lock",
                    "Package.resolved 未锁定 Swift Confidential 主包和插件的要求版本",
                    None,
                ));
            }
            if require_rasp && !has_version("free-rasp-ios", FREERASP_IOS_VERSION) {
                return Ok(IosCheck::blocked(
                    "swift_package_lock",
                    "Package.resolved 未锁定 freeRASP iOS 的要求版本",
                    None,
                ));
            }
            let digest = Sha256::digest(&bytes);
            let hash = digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            Ok(IosCheck::ready(
                "swift_package_lock",
                format!("Package.resolved 已锁定，SHA-256：{hash}"),
            ))
        }
        _ => Ok(IosCheck::blocked(
            "swift_package_lock",
            "工作副本包含多个 Package.resolved，无法确定实际依赖锁文件",
            None,
        )),
    }
}

fn collect_package_locks(root: &Path, depth: usize, output: &mut Vec<PathBuf>) -> Result<()> {
    if depth > 5 {
        return Ok(());
    }
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        if matches!(
            name.to_str(),
            Some(".git" | ".build" | "DerivedData" | "Pods")
        ) {
            continue;
        }
        let path = entry.path();
        if path.file_name().and_then(|value| value.to_str()) == Some("Package.resolved") {
            output.push(path);
        } else if path.is_dir() {
            collect_package_locks(&path, depth + 1, output)?;
        }
    }
    Ok(())
}

fn validate_bundle_id(value: &str) -> Result<()> {
    let valid = !value.is_empty()
        && value.contains('.')
        && value.split('.').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    if !valid {
        anyhow::bail!("无效的 Bundle ID：{value}");
    }
    Ok(())
}

fn validate_email(value: &str) -> Result<()> {
    let Some((local, domain)) = value.split_once('@') else {
        anyhow::bail!("watcher_mail 格式无效");
    };
    if local.is_empty() || !domain.contains('.') || domain.starts_with('.') || domain.ends_with('.')
    {
        anyhow::bail!("watcher_mail 格式无效");
    }
    Ok(())
}

fn validate_https_endpoint(value: &str) -> Result<()> {
    let Some(authority_and_path) = value.strip_prefix("https://") else {
        anyhow::bail!("app_attest_endpoint 必须使用 https://");
    };
    let authority = authority_and_path.split('/').next().unwrap_or_default();
    if authority.is_empty()
        || authority.starts_with('.')
        || authority.ends_with('.')
        || value.chars().any(char::is_whitespace)
    {
        anyhow::bail!("app_attest_endpoint 不是有效的 HTTPS 地址");
    }
    Ok(())
}

fn release_configuration() -> String {
    "Release".to_string()
}

fn default_true() -> bool {
    true
}

fn default_rasp_provider() -> String {
    "freerasp".to_string()
}

fn default_critical_threats() -> Vec<String> {
    ["signature", "jailbreak", "debugger", "runtimeManipulation"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_allows_missing_app_attest_server() {
        let confidential = tempfile::NamedTempFile::new().unwrap();
        let config = ShellsmithIosConfig {
            project: IosProjectConfig {
                path: PathBuf::from("App.xcodeproj"),
                scheme: "App".into(),
                configuration: "Release".into(),
                team_id: "ABCDE12345".into(),
                bundle_ids: vec!["com.example.app".into()],
                entrypoint: None,
            },
            protection: IosProtectionConfig {
                profile: IosProtectionProfile::Strict,
                is_prod: true,
                app_attest_endpoint: None,
            },
            confidential: Some(IosConfidentialConfig {
                enabled: true,
                config: confidential.path().to_path_buf(),
            }),
            rasp: Some(IosRaspConfig {
                provider: "freerasp".into(),
                enabled: true,
                watcher_mail: Some("security@example.com".into()),
                critical: default_critical_threats(),
            }),
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validates_bundle_and_mail_boundaries() {
        assert!(validate_bundle_id("com.example.app").is_ok());
        assert!(validate_bundle_id("com..app").is_err());
        assert!(validate_email("security@example.com").is_ok());
        assert!(validate_email("security@example").is_err());
        assert!(validate_https_endpoint("http://example.com/attest").is_err());
        assert!(validate_https_endpoint("https://example.com/attest").is_ok());
    }

    #[test]
    fn balanced_allows_optional_confidential_and_watcher_mail() {
        let config = ShellsmithIosConfig {
            project: IosProjectConfig {
                path: PathBuf::from("App.xcodeproj"),
                scheme: "App".into(),
                configuration: "Release".into(),
                team_id: "ABCDE12345".into(),
                bundle_ids: vec!["com.example.app".into()],
                entrypoint: None,
            },
            protection: IosProtectionConfig::default(),
            confidential: None,
            rasp: Some(IosRaspConfig {
                provider: "freerasp".into(),
                enabled: true,
                watcher_mail: Some("  ".into()),
                critical: default_critical_threats(),
            }),
        };
        assert!(config.validate().is_ok());
        assert!(!config.confidential_enabled());
    }

    #[test]
    fn relative_entrypoint_uses_project_root() {
        let temp = tempfile::tempdir().unwrap();
        let config_dir = temp.path().join("configs");
        let project_root = temp.path().join("App");
        fs::create_dir_all(&config_dir).unwrap();
        fs::create_dir_all(project_root.join("App.xcodeproj")).unwrap();
        fs::create_dir_all(project_root.join("Sources")).unwrap();
        fs::write(
            project_root.join("Sources/App.swift"),
            "@main struct App {}\n",
        )
        .unwrap();
        let config_path = config_dir.join("shellsmith-ios.toml");
        fs::write(
            &config_path,
            r#"[project]
path = "../App/App.xcodeproj"
scheme = "App"
team_id = "ABCDE12345"
bundle_ids = ["com.example.app"]
entrypoint = "Sources/App.swift"

[protection]
profile = "compat"
"#,
        )
        .unwrap();

        let config = ShellsmithIosConfig::load(&config_path).unwrap();
        assert_eq!(
            config.project.entrypoint.unwrap(),
            config_dir.join("../App/Sources/App.swift")
        );
    }

    #[test]
    fn package_lock_check_requires_one_non_empty_lock() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("Package.resolved"), b"{\"pins\":[]}").unwrap();
        let check = verify_package_lock(temp.path(), false, false).unwrap();
        assert_eq!(check.code, "swift_package_lock");
        assert_eq!(check.severity, IosCheckSeverity::Ready);

        fs::write(temp.path().join("nested.lock"), b"not a package lock").unwrap();
        fs::create_dir_all(temp.path().join("Nested")).unwrap();
        fs::write(
            temp.path().join("Nested/Package.resolved"),
            b"{\"pins\":[]}",
        )
        .unwrap();
        let duplicate = verify_package_lock(temp.path(), false, false).unwrap();
        assert_eq!(duplicate.severity, IosCheckSeverity::Blocked);

        fs::remove_file(temp.path().join("Nested/Package.resolved")).unwrap();
        fs::write(
            temp.path().join("Package.resolved"),
            br#"{"pins":[
                {"identity":"swift-confidential","state":{"version":"0.5.2"}},
                {"identity":"swift-confidential-plugin","state":{"version":"0.5.2"}},
                {"identity":"free-rasp-ios","state":{"version":"7.1.4"}}
            ]}"#,
        )
        .unwrap();
        let versions = verify_package_lock(temp.path(), true, true).unwrap();
        assert_eq!(versions.severity, IosCheckSeverity::Ready);
    }
}
