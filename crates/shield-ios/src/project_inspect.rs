use crate::IosProtectionProfile;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IosCheckSeverity {
    Ready,
    Warning,
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IosCheck {
    pub code: String,
    pub severity: IosCheckSeverity,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

impl IosCheck {
    pub(crate) fn ready(code: &str, message: impl Into<String>) -> Self {
        Self::new(code, IosCheckSeverity::Ready, message, None)
    }

    pub(crate) fn warning(code: &str, message: impl Into<String>, reference: Option<&str>) -> Self {
        Self::new(code, IosCheckSeverity::Warning, message, reference)
    }

    pub(crate) fn blocked(code: &str, message: impl Into<String>, reference: Option<&str>) -> Self {
        Self::new(code, IosCheckSeverity::Blocked, message, reference)
    }

    fn new(
        code: &str,
        severity: IosCheckSeverity,
        message: impl Into<String>,
        reference: Option<&str>,
    ) -> Self {
        Self {
            code: code.to_string(),
            severity,
            message: message.into(),
            reference: reference.map(str::to_string),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct XcodeEnvironment {
    pub available: bool,
    pub version: Option<String>,
    pub developer_dir: Option<String>,
    pub diagnostic: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IosTargetInspection {
    pub name: String,
    pub product_type: String,
    pub bundle_id: Option<String>,
    pub team_id: Option<String>,
    pub deployment_target: Option<String>,
    pub project_file: Option<PathBuf>,
    pub build_library_for_distribution: bool,
}

impl IosTargetInspection {
    pub fn is_application(&self) -> bool {
        self.product_type == "com.apple.product-type.application"
            || self.product_type == "application"
    }

    pub fn is_framework(&self) -> bool {
        self.product_type.contains("framework")
            || self.product_type == "com.apple.product-type.library.dynamic"
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IosProjectInspection {
    pub project_path: PathBuf,
    pub source_root: PathBuf,
    pub kind: String,
    pub requested_scheme: Option<String>,
    pub schemes: Vec<String>,
    pub targets: Vec<IosTargetInspection>,
    pub xcode: XcodeEnvironment,
    pub checks: Vec<IosCheck>,
}

impl IosProjectInspection {
    pub fn primary_application_target(&self) -> Option<&IosTargetInspection> {
        let scheme = self.requested_scheme.as_deref();
        self.targets
            .iter()
            .find(|target| target.is_application() && Some(target.name.as_str()) == scheme)
            .or_else(|| self.targets.iter().find(|target| target.is_application()))
    }
}

pub fn inspect_ios_project(path: &Path, scheme: Option<&str>) -> Result<IosProjectInspection> {
    if !path.exists() {
        anyhow::bail!("iOS 工程不存在：{}", path.display());
    }
    let extension = path.extension().and_then(|value| value.to_str());
    let kind = match extension {
        Some("xcodeproj") => "project",
        Some("xcworkspace") => "workspace",
        _ => anyhow::bail!(
            "iOS 输入必须是 .xcodeproj 或 .xcworkspace：{}",
            path.display()
        ),
    };
    let project_path = path
        .canonicalize()
        .with_context(|| format!("解析 iOS 工程路径失败：{}", path.display()))?;
    let source_root = project_path
        .parent()
        .context("iOS 工程缺少父目录")?
        .to_path_buf();
    let xcode = inspect_xcode();
    let mut checks = vec![if xcode.available {
        IosCheck::ready(
            "xcode",
            format!(
                "已找到完整 Xcode {}",
                xcode.version.as_deref().unwrap_or("未知版本")
            ),
        )
    } else {
        IosCheck::blocked(
            "xcode",
            xcode
                .diagnostic
                .clone()
                .unwrap_or_else(|| "未找到完整 Xcode".to_string()),
            Some("https://developer.apple.com/xcode/"),
        )
    }];
    checks.extend(cocoapods_checks(&project_path));

    let (schemes, targets) = if xcode.available {
        inspect_with_xcode(
            &project_path,
            kind,
            scheme,
            xcode.developer_dir.as_deref().map(Path::new),
        )
        .unwrap_or_else(|error| {
            checks.push(IosCheck::blocked(
                "xcode_project",
                format!("Xcode 无法读取工程：{error:#}"),
                None,
            ));
            inspect_statically(&project_path, kind, scheme)
        })
    } else {
        inspect_statically(&project_path, kind, scheme)
    };

    if let Some(requested) = scheme {
        if !schemes.is_empty() && !schemes.iter().any(|item| item == requested) {
            checks.push(IosCheck::blocked(
                "scheme",
                format!("工程中没有共享 scheme：{requested}"),
                None,
            ));
        } else {
            checks.push(IosCheck::ready(
                "scheme",
                format!("已选择 scheme：{requested}"),
            ));
        }
    } else if schemes.len() == 1 {
        checks.push(IosCheck::ready(
            "scheme",
            format!("发现 scheme：{}", schemes[0]),
        ));
    } else {
        checks.push(IosCheck::warning(
            "scheme",
            "检查模式未指定 scheme；执行保护时必须明确选择",
            None,
        ));
    }

    if targets.iter().any(IosTargetInspection::is_application) {
        checks.push(IosCheck::ready(
            "application_target",
            "已找到 iOS 应用 target",
        ));
    } else if xcode.available {
        checks.push(IosCheck::blocked(
            "application_target",
            "所选 scheme 不是 iOS 应用 target；禁止把保护依赖接入 framework",
            None,
        ));
    } else {
        checks.push(IosCheck::warning(
            "application_target",
            "缺少完整 Xcode，无法确认应用 target",
            None,
        ));
    }

    Ok(IosProjectInspection {
        project_path,
        source_root,
        kind: kind.to_string(),
        requested_scheme: scheme.map(str::to_string),
        schemes,
        targets,
        xcode,
        checks,
    })
}

pub(crate) fn validate_protection_target(
    inspection: &IosProjectInspection,
    profile: IosProtectionProfile,
    expected_team_id: &str,
    expected_bundle_ids: &[String],
) -> Result<()> {
    let blockers = inspection
        .checks
        .iter()
        .filter(|check| check.severity == IosCheckSeverity::Blocked && check.code != "xcode")
        .map(|check| check.message.as_str())
        .collect::<Vec<_>>();
    if !blockers.is_empty() {
        anyhow::bail!("iOS 工程预检未通过：{}", blockers.join("；"));
    }
    if !inspection.xcode.available {
        return Ok(());
    }
    let target = inspection
        .primary_application_target()
        .context("所选 scheme 不是应用 target，不能接入 iOS 保护")?;
    match target.team_id.as_deref() {
        Some(team_id) if team_id == expected_team_id => {}
        Some(team_id) => anyhow::bail!(
            "配置 Team ID {} 与 Xcode target Team ID {} 不一致",
            expected_team_id,
            team_id
        ),
        None => anyhow::bail!("Xcode target 缺少 DEVELOPMENT_TEAM"),
    }
    if let Some(bundle_id) = target.bundle_id.as_deref() {
        if !expected_bundle_ids.iter().any(|value| value == bundle_id) {
            anyhow::bail!(
                "配置 Bundle ID 列表不包含 Xcode target 的 Bundle ID：{}",
                bundle_id
            );
        }
    } else {
        anyhow::bail!("Xcode target 缺少 PRODUCT_BUNDLE_IDENTIFIER");
    }
    if profile != IosProtectionProfile::Compat
        && (target.is_framework() || target.build_library_for_distribution)
    {
        anyhow::bail!(
            "Swift Confidential/freeRASP 只能直接接入应用 target；framework/XCFramework 接法存在已知 Archive 或嵌套 framework 问题"
        );
    }
    Ok(())
}

fn cocoapods_checks(project: &Path) -> Vec<IosCheck> {
    let Some(parent) = project.parent() else {
        return Vec::new();
    };
    let internal_workspace = parent.extension().is_some_and(|value| value == "xcodeproj");
    let root = if internal_workspace {
        parent.parent().unwrap_or(parent)
    } else {
        parent
    };
    let project_dir = if internal_workspace { parent } else { project };
    let pbx = fs::read_to_string(project_dir.join("project.pbxproj")).unwrap_or_default();
    // ponytail: 只预检入口同级的标准 Pods 布局；自定义沙盒需按 Xcode 构建设置扩展，不猜测工作区。
    let uses_pods = root.join("Podfile").is_file()
        || root.join("podfile").is_file()
        || root.join("Podfile.lock").is_file()
        || pbx.contains("PODS_ROOT")
        || pbx.contains("[CP] Check Pods Manifest.lock");
    if !uses_pods {
        return Vec::new();
    }
    let mut checks = Vec::new();
    if project
        .extension()
        .is_some_and(|value| value == "xcodeproj")
        || internal_workspace
    {
        checks.push(IosCheck::blocked(
            "cocoapods_workspace",
            "检测到 CocoaPods：请选择 pod install 生成的顶层 .xcworkspace，不能使用 .xcodeproj 或其内部 project.xcworkspace；否则 Pods 模块和预编译头依赖可能缺失",
            None,
        ));
    }
    let lock = fs::read(root.join("Podfile.lock"));
    let manifest = fs::read(root.join("Pods/Manifest.lock"));
    checks.push(match (lock, manifest, root.join("Pods/Pods.xcodeproj/project.pbxproj").is_file()) {
        (Ok(lock), Ok(manifest), true) if !lock.is_empty() && lock == manifest => IosCheck::ready(
            "cocoapods_dependencies",
            "已找到 Pods 工程，Podfile.lock 与 Pods/Manifest.lock 一致；依赖将随工作副本保留",
        ),
        (Ok(lock), Ok(manifest), true) if !lock.is_empty() && !manifest.is_empty() => IosCheck::blocked(
            "cocoapods_dependencies",
            "Podfile.lock 与 Pods/Manifest.lock 不一致：请先执行 pod install 同步依赖，再重新检查；不要使用 pod update 升级依赖",
            None,
        ),
        _ => IosCheck::blocked(
            "cocoapods_dependencies",
            format!("未找到完整的标准 CocoaPods 依赖：请在 {} 执行 pod install（使用 Gemfile 的工程执行 bundle exec pod install），再选择生成的 .xcworkspace；Shellsmith 不会自动安装或升级业务依赖", root.display()),
            None,
        ),
    });
    checks
}

pub(crate) fn known_issue_checks(
    inspection: &IosProjectInspection,
    profile: IosProtectionProfile,
    confidential_enabled: bool,
) -> Vec<IosCheck> {
    let mut checks = Vec::new();
    if confidential_enabled {
        let unsupported = inspection
            .targets
            .iter()
            .any(|target| target.is_framework() && target.build_library_for_distribution);
        checks.push(if unsupported {
            IosCheck::blocked(
                "swift_confidential_xcframework",
                "检测到 BUILD_LIBRARY_FOR_DISTRIBUTION framework；不向该 target 接入 Swift Confidential",
                Some("https://github.com/securevale/swift-confidential/issues/12"),
            )
        } else {
            IosCheck::ready(
                "swift_confidential_xcframework",
                "Swift Confidential 只接入应用 target，已避开 XCFramework Archive 冲突",
            )
        });
    }
    if profile.uses_rasp() {
        checks.push(IosCheck::ready(
            "freerasp_framework_embedding",
            "freeRASP 通过应用 target 的本地 Swift Package 直接链接，禁止嵌入到二级 framework",
        ));
        checks.push(IosCheck::warning(
            "freerasp_roothide_residual",
            "freeRASP 上游仍记录 Dopamine 2 RootHide 漏检；此环境必须结合 App Attest/服务端风险策略",
            Some("https://github.com/talsec/Free-RASP-iOS/issues/41"),
        ));
        checks.push(IosCheck::warning(
            "freerasp_spm_resolution",
            "freeRASP 上游存在 SPM 接入反馈；Shellsmith 会在 Archive 前强制解析依赖并在失败时停止",
            Some("https://github.com/talsec/Free-RASP-iOS/issues/55"),
        ));
    }
    checks
}

pub(crate) fn validate_output_location(source_root: &Path, output: &Path) -> Result<()> {
    let source = resolve_existing_ancestor(source_root)?;
    let output = resolve_existing_ancestor(output)?;
    if output == source || output.starts_with(&source) {
        anyhow::bail!("iOS 输出目录不能位于源码目录内，避免递归复制或覆盖原工程");
    }
    if output.exists() && output.read_dir()?.next().is_some() {
        anyhow::bail!("iOS 输出目录必须不存在或为空：{}", output.display());
    }
    Ok(())
}

fn resolve_existing_ancestor(path: &Path) -> Result<PathBuf> {
    let mut existing = normalize_absolute(path)?;
    let mut missing = Vec::new();
    while !existing.exists() {
        let name = existing
            .file_name()
            .context("路径没有可解析的现有父目录")?
            .to_os_string();
        missing.push(name);
        if !existing.pop() {
            anyhow::bail!("路径没有可解析的现有父目录：{}", path.display());
        }
    }
    let mut resolved = existing
        .canonicalize()
        .with_context(|| format!("解析路径失败：{}", existing.display()))?;
    for component in missing.into_iter().rev() {
        resolved.push(component);
    }
    Ok(resolved)
}

fn inspect_xcode() -> XcodeEnvironment {
    if !cfg!(target_os = "macos") {
        return XcodeEnvironment {
            available: false,
            diagnostic: Some("当前系统不是 macOS，只能执行配置和静态检查".to_string()),
            ..XcodeEnvironment::default()
        };
    }
    let selected_developer_dir = Command::new("xcode-select")
        .arg("-p")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string());
    let mut candidates = Vec::new();
    if let Some(path) = std::env::var_os("DEVELOPER_DIR") {
        add_developer_candidate(&mut candidates, PathBuf::from(path));
    }
    if let Some(path) = selected_developer_dir.as_deref() {
        add_developer_candidate(&mut candidates, PathBuf::from(path));
    }
    add_developer_candidate(
        &mut candidates,
        PathBuf::from("/Applications/Xcode.app/Contents/Developer"),
    );
    if let Some(home) = std::env::var_os("HOME") {
        add_developer_candidate(
            &mut candidates,
            PathBuf::from(home).join("Applications/Xcode.app/Contents/Developer"),
        );
    }
    add_installed_xcodes(Path::new("/Applications"), &mut candidates);
    if let Some(home) = std::env::var_os("HOME") {
        add_installed_xcodes(&PathBuf::from(home).join("Applications"), &mut candidates);
    }
    if let Ok(output) = Command::new("mdfind")
        .args(["kMDItemCFBundleIdentifier == 'com.apple.dt.Xcode'"])
        .output()
    {
        for path in String::from_utf8_lossy(&output.stdout).lines() {
            add_developer_candidate(&mut candidates, PathBuf::from(path.trim()));
        }
    }

    let mut diagnostics = Vec::new();
    for developer_dir in candidates {
        let output = Command::new("xcodebuild")
            .env("DEVELOPER_DIR", &developer_dir)
            .arg("-version")
            .output();
        match output {
            Ok(output) if output.status.success() => {
                return XcodeEnvironment {
                    available: true,
                    version: Some(
                        String::from_utf8_lossy(&output.stdout)
                            .trim()
                            .replace('\n', " · "),
                    ),
                    developer_dir: Some(developer_dir.display().to_string()),
                    diagnostic: None,
                };
            }
            Ok(output) => diagnostics.push(clean_command_error(&output.stderr)),
            Err(error) => diagnostics.push(format!("无法启动 xcodebuild：{error}")),
        }
    }
    let selected = selected_developer_dir.as_deref().unwrap_or("未设置");
    XcodeEnvironment {
        available: false,
        version: None,
        developer_dir: Some(selected.to_string()),
        diagnostic: Some(format!(
            "未找到可用的完整 Xcode；当前开发者目录为 {selected}。已自动检查常见 Xcode 安装位置{}",
            diagnostics
                .last()
                .map(|value| format!("：{value}"))
                .unwrap_or_default()
        )),
    }
}

fn add_developer_candidate(candidates: &mut Vec<PathBuf>, path: PathBuf) {
    let path = if path.extension().and_then(|value| value.to_str()) == Some("app") {
        path.join("Contents").join("Developer")
    } else {
        path
    };
    if path.is_dir() && !candidates.iter().any(|item| item == &path) {
        candidates.push(path);
    }
}

fn add_installed_xcodes(root: &Path, candidates: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    let mut apps = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension().and_then(|value| value.to_str()) == Some("app")
                && path
                    .file_stem()
                    .and_then(|value| value.to_str())
                    .is_some_and(|value| value.starts_with("Xcode"))
        })
        .collect::<Vec<_>>();
    apps.sort();
    for app in apps {
        add_developer_candidate(candidates, app);
    }
}

fn inspect_with_xcode(
    project: &Path,
    kind: &str,
    scheme: Option<&str>,
    developer_dir: Option<&Path>,
) -> Result<(Vec<String>, Vec<IosTargetInspection>)> {
    let selector = if kind == "workspace" {
        "-workspace"
    } else {
        "-project"
    };
    let list = xcodebuild_command(developer_dir)
        .arg("-list")
        .arg("-json")
        .arg(selector)
        .arg(project)
        .output()
        .context("启动 xcodebuild -list 失败")?;
    if !list.status.success() {
        anyhow::bail!(crate::xcodebuild::command_diagnostic(
            &list.stdout,
            &list.stderr
        ));
    }
    let list_json: Value =
        serde_json::from_slice(&list.stdout).context("解析 xcodebuild -list JSON 失败")?;
    let root = list_json
        .get(if kind == "workspace" {
            "workspace"
        } else {
            "project"
        })
        .unwrap_or(&list_json);
    let schemes = string_array(root.get("schemes"));
    let Some(scheme) = scheme else {
        return Ok((schemes, Vec::new()));
    };
    let settings = xcodebuild_command(developer_dir)
        .arg(selector)
        .arg(project)
        .arg("-scheme")
        .arg(scheme)
        .arg("-showBuildSettings")
        .arg("-json")
        .output()
        .context("启动 xcodebuild -showBuildSettings 失败")?;
    if !settings.status.success() {
        anyhow::bail!(crate::xcodebuild::command_diagnostic(
            &settings.stdout,
            &settings.stderr
        ));
    }
    let values: Value = serde_json::from_slice(&settings.stdout)
        .context("解析 xcodebuild -showBuildSettings JSON 失败")?;
    let mut targets = Vec::new();
    for item in values.as_array().into_iter().flatten() {
        let build = item.get("buildSettings").and_then(Value::as_object);
        let value = |key: &str| {
            build
                .and_then(|map| map.get(key))
                .and_then(Value::as_str)
                .map(str::to_string)
        };
        let name = item
            .get("target")
            .and_then(Value::as_str)
            .or_else(|| {
                build
                    .and_then(|map| map.get("TARGET_NAME"))
                    .and_then(Value::as_str)
            })
            .unwrap_or(scheme)
            .to_string();
        targets.push(IosTargetInspection {
            name,
            product_type: value("PRODUCT_TYPE").unwrap_or_else(|| "unknown".to_string()),
            bundle_id: value("PRODUCT_BUNDLE_IDENTIFIER"),
            team_id: value("DEVELOPMENT_TEAM"),
            deployment_target: value("IPHONEOS_DEPLOYMENT_TARGET"),
            project_file: value("PROJECT_FILE_PATH").map(PathBuf::from),
            build_library_for_distribution: value("BUILD_LIBRARY_FOR_DISTRIBUTION")
                .is_some_and(|value| value == "YES"),
        });
    }
    Ok((schemes, targets))
}

fn xcodebuild_command(developer_dir: Option<&Path>) -> Command {
    let mut command = Command::new("xcodebuild");
    if let Some(developer_dir) = developer_dir {
        command.env("DEVELOPER_DIR", developer_dir);
    }
    command
}

fn inspect_statically(
    project: &Path,
    kind: &str,
    scheme: Option<&str>,
) -> (Vec<String>, Vec<IosTargetInspection>) {
    let mut pbx_files = Vec::new();
    if kind == "project" {
        pbx_files.push(project.join("project.pbxproj"));
    } else if let Some(root) = project.parent() {
        collect_xcode_projects(root, 0, &mut pbx_files);
    }
    let mut schemes = BTreeSet::new();
    let mut bundle_ids = BTreeSet::new();
    let mut team_ids = BTreeSet::new();
    let mut deployment_targets = BTreeSet::new();
    for pbx in pbx_files {
        let Some(project_dir) = pbx.parent() else {
            continue;
        };
        collect_shared_schemes(project_dir, &mut schemes);
        let Ok(content) = fs::read_to_string(&pbx) else {
            continue;
        };
        collect_assignment_values(&content, "PRODUCT_BUNDLE_IDENTIFIER", &mut bundle_ids);
        collect_assignment_values(&content, "DEVELOPMENT_TEAM", &mut team_ids);
        collect_assignment_values(
            &content,
            "IPHONEOS_DEPLOYMENT_TARGET",
            &mut deployment_targets,
        );
    }
    let targets = scheme
        .map(|name| {
            vec![IosTargetInspection {
                name: name.to_string(),
                product_type: "unknown_without_xcode".to_string(),
                bundle_id: bundle_ids.into_iter().next(),
                team_id: team_ids.into_iter().next(),
                deployment_target: deployment_targets.into_iter().next(),
                project_file: None,
                build_library_for_distribution: false,
            }]
        })
        .unwrap_or_default();
    (schemes.into_iter().collect(), targets)
}

fn collect_xcode_projects(root: &Path, depth: usize, output: &mut Vec<PathBuf>) {
    if depth > 2 {
        return;
    }
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) == Some("xcodeproj") {
            output.push(path.join("project.pbxproj"));
        } else if path.is_dir()
            && !matches!(
                entry.file_name().to_str(),
                Some(".git" | "Pods" | ".build" | "DerivedData")
            )
        {
            collect_xcode_projects(&path, depth + 1, output);
        }
    }
}

fn collect_shared_schemes(project_dir: &Path, output: &mut BTreeSet<String>) {
    let directory = project_dir.join("xcshareddata").join("xcschemes");
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) == Some("xcscheme") {
            if let Some(stem) = path.file_stem().and_then(|value| value.to_str()) {
                output.insert(stem.to_string());
            }
        }
    }
}

fn collect_assignment_values(content: &str, key: &str, output: &mut BTreeSet<String>) {
    for line in content.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed
            .strip_prefix(key)
            .and_then(|value| value.trim_start().strip_prefix('='))
        else {
            continue;
        };
        let value = rest.trim().trim_end_matches(';').trim_matches('"');
        if !value.is_empty() && !value.contains("$(") {
            output.insert(value.to_string());
        }
    }
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

fn clean_command_error(stderr: &[u8]) -> String {
    crate::xcodebuild::command_diagnostic(&[], stderr)
}

fn normalize_absolute(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::ParentDir => {
                normalized.pop();
            }
            Component::CurDir => {}
            other => normalized.push(other.as_os_str()),
        }
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 原生工程不需要_cocoapods() {
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path().join("Demo.xcodeproj");
        fs::create_dir(&project).unwrap();
        fs::write(project.join("project.pbxproj"), "PRODUCT_NAME = Demo;").unwrap();
        assert!(cocoapods_checks(&project).is_empty());
    }

    #[test]
    fn pods_工程必须使用顶层工作区并校验锁文件() {
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path().join("Demo.xcodeproj");
        let workspace = temp.path().join("Demo.xcworkspace");
        fs::create_dir(&project).unwrap();
        fs::create_dir(&workspace).unwrap();
        fs::write(temp.path().join("podfile"), "platform :ios, '13.0'").unwrap();
        let missing = cocoapods_checks(&project);
        assert!(missing
            .iter()
            .any(|check| check.code == "cocoapods_workspace"
                && check.severity == IosCheckSeverity::Blocked));
        assert!(missing
            .iter()
            .any(|check| check.code == "cocoapods_dependencies"
                && check.message.contains("pod install")));

        fs::create_dir_all(temp.path().join("Pods/Pods.xcodeproj")).unwrap();
        fs::write(
            temp.path().join("Pods/Pods.xcodeproj/project.pbxproj"),
            "Pods",
        )
        .unwrap();
        fs::write(temp.path().join("Podfile.lock"), "PODS: []\n").unwrap();
        fs::write(temp.path().join("Pods/Manifest.lock"), "PODS: []\n").unwrap();
        assert!(cocoapods_checks(&workspace)
            .iter()
            .all(|check| check.severity == IosCheckSeverity::Ready));
        assert!(cocoapods_checks(&project.join("project.xcworkspace"))
            .iter()
            .any(|check| check.code == "cocoapods_workspace"));

        fs::write(temp.path().join("Pods/Manifest.lock"), "PODS: [不同版本]\n").unwrap();
        assert!(cocoapods_checks(&workspace)
            .iter()
            .any(|check| check.message.contains("不一致")
                && check.severity == IosCheckSeverity::Blocked));
    }

    #[test]
    fn 缺失_podfile_时仍识别工程中的_pods_接入() {
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path().join("Demo.xcodeproj");
        fs::create_dir(&project).unwrap();
        fs::write(
            project.join("project.pbxproj"),
            "shellScript = \"${PODS_ROOT}/检查脚本\";",
        )
        .unwrap();
        assert!(cocoapods_checks(&project)
            .iter()
            .any(|check| check.code == "cocoapods_workspace"));
        assert!(cocoapods_checks(&project.join("project.xcworkspace"))
            .iter()
            .any(|check| check.code == "cocoapods_workspace"));
    }

    #[test]
    fn static_inspection_finds_shared_scheme_and_settings() {
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path().join("Demo.xcodeproj");
        fs::create_dir_all(project.join("xcshareddata/xcschemes")).unwrap();
        fs::write(
            project.join("xcshareddata/xcschemes/Demo.xcscheme"),
            "<Scheme/>",
        )
        .unwrap();
        fs::write(
            project.join("project.pbxproj"),
            "PRODUCT_BUNDLE_IDENTIFIER = com.example.demo;\nDEVELOPMENT_TEAM = ABCDE12345;\nIPHONEOS_DEPLOYMENT_TARGET = 13.0;",
        )
        .unwrap();

        let report = inspect_ios_project(&project, Some("Demo")).unwrap();
        assert_eq!(report.schemes, vec!["Demo"]);
        assert_eq!(
            report.targets[0].bundle_id.as_deref(),
            Some("com.example.demo")
        );
    }

    #[test]
    fn output_cannot_be_nested_in_source() {
        let temp = tempfile::tempdir().unwrap();
        assert!(validate_output_location(temp.path(), &temp.path().join("out")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn output_symlink_cannot_escape_back_into_source() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let external = temp.path().join("external");
        fs::create_dir_all(source.join("nested")).unwrap();
        fs::create_dir_all(&external).unwrap();
        std::os::unix::fs::symlink(source.join("nested"), external.join("linked")).unwrap();

        assert!(validate_output_location(&source, &external.join("linked/output")).is_err());
    }

    #[test]
    fn known_issues_are_kept_in_report() {
        let report = IosProjectInspection {
            project_path: PathBuf::from("Demo.xcodeproj"),
            source_root: PathBuf::from("."),
            kind: "project".into(),
            requested_scheme: Some("Demo".into()),
            schemes: vec!["Demo".into()],
            targets: vec![IosTargetInspection {
                name: "Demo".into(),
                product_type: "com.apple.product-type.application".into(),
                bundle_id: Some("com.example.demo".into()),
                team_id: None,
                deployment_target: Some("13.0".into()),
                project_file: None,
                build_library_for_distribution: false,
            }],
            xcode: XcodeEnvironment::default(),
            checks: vec![],
        };
        let checks = known_issue_checks(&report, IosProtectionProfile::Balanced, true);
        assert!(checks
            .iter()
            .any(|check| check.code == "freerasp_roothide_residual"));
        assert!(checks
            .iter()
            .any(|check| check.code == "freerasp_spm_resolution"));
    }

    #[test]
    fn target_identity_must_match_protection_configuration() {
        let report = IosProjectInspection {
            project_path: PathBuf::from("Demo.xcodeproj"),
            source_root: PathBuf::from("."),
            kind: "project".into(),
            requested_scheme: Some("Demo".into()),
            schemes: vec!["Demo".into()],
            targets: vec![IosTargetInspection {
                name: "Demo".into(),
                product_type: "com.apple.product-type.application".into(),
                bundle_id: Some("com.example.real".into()),
                team_id: Some("ABCDE12345".into()),
                deployment_target: Some("13.0".into()),
                project_file: None,
                build_library_for_distribution: false,
            }],
            xcode: XcodeEnvironment {
                available: true,
                ..XcodeEnvironment::default()
            },
            checks: vec![],
        };
        assert!(validate_protection_target(
            &report,
            IosProtectionProfile::Balanced,
            "ABCDE12345",
            &["com.example.other".into()]
        )
        .is_err());
    }
}
