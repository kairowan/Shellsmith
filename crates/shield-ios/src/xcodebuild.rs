use crate::IosProjectConfig;
use anyhow::{Context, Result};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

pub(crate) fn resolve_packages(
    project: &Path,
    scheme: &str,
    developer_dir: Option<&Path>,
    cancel: &Arc<AtomicBool>,
) -> Result<()> {
    let mut args = project_selector(project)?;
    args.extend([
        OsString::from("-scheme"),
        OsString::from(scheme),
        OsString::from("-resolvePackageDependencies"),
    ]);
    run(
        "xcodebuild",
        &args,
        developer_dir,
        cancel,
        "解析 Swift Package 失败",
        Some(&project.with_extension("resolve.log")),
        |_, _| None,
    )
}

pub(crate) fn archive(
    project: &Path,
    config: &IosProjectConfig,
    archive_path: &Path,
    developer_dir: Option<&Path>,
    allow_provisioning_updates: bool,
    cancel: &Arc<AtomicBool>,
) -> Result<()> {
    let mut args = project_selector(project)?;
    args.extend([
        OsString::from("-scheme"),
        OsString::from(&config.scheme),
        OsString::from("-configuration"),
        OsString::from(&config.configuration),
        OsString::from("-destination"),
        OsString::from("generic/platform=iOS"),
        OsString::from("-archivePath"),
        archive_path.as_os_str().to_os_string(),
        OsString::from(format!("DEVELOPMENT_TEAM={}", config.team_id)),
    ]);
    if allow_provisioning_updates {
        args.push(OsString::from("-allowProvisioningUpdates"));
    }
    args.push(OsString::from("archive"));
    run(
        "xcodebuild",
        &args,
        developer_dir,
        cancel,
        "生成 Xcode Archive 失败",
        Some(&archive_path.with_extension("archive.log")),
        |_, _| None,
    )
}

pub(crate) fn export_archive(
    archive_path: &Path,
    export_path: &Path,
    export_options: &Path,
    developer_dir: Option<&Path>,
    allow_provisioning_updates: bool,
    cancel: &Arc<AtomicBool>,
) -> Result<()> {
    let mut args = vec![
        OsString::from("-exportArchive"),
        OsString::from("-archivePath"),
        archive_path.as_os_str().to_os_string(),
        OsString::from("-exportPath"),
        export_path.as_os_str().to_os_string(),
        OsString::from("-exportOptionsPlist"),
        export_options.as_os_str().to_os_string(),
    ];
    if allow_provisioning_updates {
        args.push(OsString::from("-allowProvisioningUpdates"));
    }
    // -exportPath 必须可写；先建目录，避免某些 Xcode 版本直接判定导出路径无效。
    fs::create_dir_all(export_path)
        .with_context(|| format!("创建 IPA 导出目录失败：{}", export_path.display()))?;
    run(
        "xcodebuild",
        &args,
        developer_dir,
        cancel,
        "导出 IPA 失败",
        Some(&export_path.with_extension("export.log")),
        |stdout, stderr| export_failure_hint(stdout, stderr, allow_provisioning_updates),
    )
}

/// 把「No profiles for '...' were found」翻译成可以直接执行的下一步。
///
/// 自动签名导出时 Xcode 必须向 Apple 账号换取 App Store 分发描述文件；
/// 这台机器上通常只有开发描述文件，所以导出失败几乎都落在这一句上。
pub(crate) fn export_failure_hint(
    stdout: &[u8],
    stderr: &[u8],
    allow_provisioning_updates: bool,
) -> Option<String> {
    let bundle_ids = missing_profile_bundle_ids(stdout, stderr);
    if bundle_ids.is_empty() {
        return None;
    }
    let list = bundle_ids.join("、");
    Some(if allow_provisioning_updates {
        format!(
            "Xcode 仍未能为 {list} 取得分发描述文件。请确认 Xcode 已登录该 Team 的 Apple 账号且账号拥有这些 App ID 的管理权限（应用与其扩展各自需要 App Store 分发描述文件），或改用带 provisioningProfiles 映射的 ExportOptions.plist"
        )
    } else {
        format!(
            "本机没有 {list} 的 App Store 分发描述文件，而本次未允许 Xcode 更新描述文件，所以导出被取消。请勾选「允许更新 Provisioning Profile」后重试（Xcode 会联网用已登录的开发者账号获取或创建描述文件），或改用带 provisioningProfiles 映射的 ExportOptions.plist"
        )
    })
}

fn missing_profile_bundle_ids(stdout: &[u8], stderr: &[u8]) -> Vec<String> {
    const MARKER: &str = "No profiles for '";
    let mut bundle_ids: Vec<String> = Vec::new();
    for raw in [stdout, stderr] {
        let text = String::from_utf8_lossy(raw);
        let mut rest = text.as_ref();
        while let Some(index) = rest.find(MARKER) {
            rest = &rest[index + MARKER.len()..];
            let Some(end) = rest.find('\'') else {
                break;
            };
            let bundle_id = rest[..end].trim();
            if !bundle_id.is_empty() && !bundle_ids.iter().any(|item| item == bundle_id) {
                bundle_ids.push(bundle_id.to_string());
            }
            rest = &rest[end..];
        }
    }
    bundle_ids
}

fn project_selector(project: &Path) -> Result<Vec<OsString>> {
    let selector = match project.extension().and_then(|value| value.to_str()) {
        Some("xcworkspace") => "-workspace",
        Some("xcodeproj") => "-project",
        _ => anyhow::bail!("Xcode 输入必须是 .xcodeproj 或 .xcworkspace"),
    };
    Ok(vec![
        OsString::from(selector),
        project.as_os_str().to_os_string(),
    ])
}

pub(crate) fn run<H>(
    program: &str,
    args: &[OsString],
    developer_dir: Option<&Path>,
    cancel: &Arc<AtomicBool>,
    context: &str,
    failure_log: Option<&Path>,
    failure_hint: H,
) -> Result<()>
where
    H: Fn(&[u8], &[u8]) -> Option<String>,
{
    if cancel.load(Ordering::SeqCst) {
        anyhow::bail!("iOS 保护任务已取消");
    }
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(developer_dir) = developer_dir {
        command.env("DEVELOPER_DIR", developer_dir);
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("启动 {program} 失败"))?;
    let stdout = child.stdout.take().context("无法读取 xcodebuild stdout")?;
    let stderr = child.stderr.take().context("无法读取 xcodebuild stderr")?;
    let stdout_thread = thread::spawn(move || read_all(stdout));
    let stderr_thread = thread::spawn(move || read_all(stderr));
    let status = loop {
        if cancel.load(Ordering::SeqCst) {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_thread.join();
            let _ = stderr_thread.join();
            anyhow::bail!("iOS 保护任务已取消");
        }
        if let Some(status) = child.try_wait()? {
            break status;
        }
        thread::sleep(Duration::from_millis(100));
    };
    let stdout = stdout_thread
        .join()
        .map_err(|_| anyhow::anyhow!("读取构建 stdout 的线程异常"))?
        .context("读取构建 stdout 失败")?;
    let stderr = stderr_thread
        .join()
        .map_err(|_| anyhow::anyhow!("读取构建 stderr 的线程异常"))?
        .context("读取构建 stderr 失败")?;
    if !status.success() {
        let diagnostic = command_diagnostic(&stdout, &stderr);
        let hint = failure_hint(&stdout, &stderr)
            .map(|hint| format!("；建议：{hint}"))
            .unwrap_or_default();
        let log_note = failure_log
            .map(|path| match write_command_log(path, &stdout, &stderr) {
                Ok(()) => format!("；完整构建日志（仅保存在本机）：{}", path.display()),
                Err(error) => format!("；保存完整日志失败（{}）：{error}", path.display()),
            })
            .unwrap_or_default();
        anyhow::bail!("{context}：{diagnostic}{hint}{log_note}");
    }
    Ok(())
}

fn read_all(mut reader: impl Read) -> std::io::Result<Vec<u8>> {
    let mut output = Vec::new();
    reader.read_to_end(&mut output)?;
    Ok(output)
}

fn write_command_log(path: &Path, stdout: &[u8], stderr: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(b"=== stdout ===\n")?;
    file.write_all(stdout)?;
    file.write_all(b"\n=== stderr ===\n")?;
    file.write_all(stderr)?;
    Ok(())
}

pub(crate) fn command_diagnostic(stdout: &[u8], stderr: &[u8]) -> String {
    let stderr = String::from_utf8_lossy(stderr);
    let stdout = String::from_utf8_lossy(stdout);
    let lines = stdout
        .lines()
        .chain(stderr.lines())
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    let errors = lines.iter().enumerate().filter(|(_, line)| {
        !line.contains("warning:")
            && !line.starts_with("#warning")
            && (line.contains("error:")
                || line.contains("fatal:")
                || line.starts_with("Undefined symbols for architecture")
                || line.starts_with("ld: "))
    });
    let mut selected = Vec::new();
    for (index, _) in errors {
        // 优先保留真正错误，再补充诊断上下文；不让 stderr 的警告占满摘要。
        for line in &lines[index..(index + 4).min(lines.len())] {
            if !selected.contains(line) && selected.len() < 24 {
                selected.push(*line);
            }
        }
    }
    if !selected.is_empty() {
        return selected.join("；");
    }
    // ponytail: 无标准错误标记时保留末尾输出；完整原文另存日志，避免猜测具体业务错误。
    lines[lines.len().saturating_sub(24)..].join("；")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 摘要优先保留日志中段的预编译头错误() {
        let stdout = format!(
            "{}\nCommon/Headers/Prefix.pch:8:9: fatal error: 'PodSDK/PodSDK.h' file not found\n#import <PodSDK/PodSDK.h>\n        ^~~~~~~~~~~~~~~~~\n{}",
            "PrecompileModule SDK.scan\n".repeat(60),
            "builtin-precompileModule SDK.scan\n".repeat(60)
        );
        let stderr = format!("{}** ARCHIVE FAILED **\nThe following build commands failed:\nScanDependencies Prefix.pch.gch\n(2 failures)",
            "warning: 模块不可用\n#warning(\"模块不可用\")\n".repeat(30));
        let diagnostic = command_diagnostic(stdout.as_bytes(), stderr.as_bytes());
        assert!(diagnostic.starts_with("Common/Headers/Prefix.pch:8:9: fatal error:"));
        assert!(diagnostic.contains("#import <PodSDK/PodSDK.h>"));
        assert!(!diagnostic.contains("warning: 模块不可用"));
        assert!(diagnostic.split('；').count() <= 24);
    }

    #[test]
    fn 依赖解析和链接错误也保留具体原因() {
        let diagnostic = command_diagnostic(b"Resolve Package Graph", b"xcodebuild: error: Could not resolve package dependencies:\nFailed to clone repository\nfatal: unable to access https://example.com: timeout");
        assert!(diagnostic.contains("Could not resolve package dependencies"));
        assert!(diagnostic.contains("fatal: unable to access"));
        let diagnostic = command_diagnostic(b"Undefined symbols for architecture arm64:\n  _MissingSymbol, referenced from:\n      _main in main.o\nld: symbol(s) not found for architecture arm64", b"** ARCHIVE FAILED **");
        assert!(diagnostic.contains("_MissingSymbol"));
    }

    #[test]
    fn 无错误标记时摘要按原顺序保留末尾() {
        assert_eq!(
            command_diagnostic("步骤一\n步骤二".as_bytes(), "失败详情\n".as_bytes()),
            "步骤一；步骤二；失败详情"
        );
    }

    #[test]
    fn 导出缺少描述文件时列出全部_bundle_id_并指向开关() {
        let stdout =
            b"error: exportArchive: No profiles for 'com.mova.rec.Share-Extension' were found\n";
        let stderr = b"error: exportArchive: No profiles for 'com.mova.rec' were found\n** EXPORT FAILED **\n";
        let hint = export_failure_hint(stdout, stderr, false).expect("应识别描述文件缺失");
        assert!(hint.contains("com.mova.rec"));
        assert!(hint.contains("com.mova.rec.Share-Extension"));
        assert!(hint.contains("允许更新 Provisioning Profile"));
        assert!(hint.contains("provisioningProfiles"));
    }

    #[test]
    fn 已允许更新描述文件时提示改为检查账号权限() {
        let stderr = b"error: exportArchive: No profiles for 'com.mova.rec' were found\n";
        let hint = export_failure_hint(b"", stderr, true).expect("应识别描述文件缺失");
        assert!(hint.contains("com.mova.rec"));
        assert!(hint.contains("Apple 账号"));
        assert!(!hint.contains("允许更新 Provisioning Profile"));
    }

    #[test]
    fn 与描述文件无关的导出失败不追加建议() {
        assert_eq!(
            export_failure_hint(b"", b"error: exportArchive: Nothing to compile", false),
            None
        );
    }

    #[test]
    fn 重复的_bundle_id_只提示一次() {
        let log = b"error: exportArchive: No profiles for 'com.a' were found\nerror: exportArchive: No profiles for 'com.a' were found\n";
        let hint = export_failure_hint(log, b"", false).expect("应识别描述文件缺失");
        assert_eq!(hint.matches("com.a").count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn 失败提示会附加在命令错误之后() {
        let temp = tempfile::tempdir().unwrap();
        let log = temp.path().join("export.export.log");
        let cancel = Arc::new(AtomicBool::new(false));
        let args = [
            "-c",
            "printf \"error: exportArchive: No profiles for 'com.demo' were found\\n\"; exit 1",
        ]
        .map(OsString::from);
        let error = run(
            "/bin/sh",
            &args,
            None,
            &cancel,
            "导出 IPA 失败",
            Some(&log),
            |stdout, stderr| export_failure_hint(stdout, stderr, false),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("导出 IPA 失败"));
        assert!(error.contains("com.demo"));
        assert!(error.contains("建议"));
        assert!(error.contains(log.to_str().unwrap()));
    }

    #[cfg(unix)]
    #[test]
    fn 命令失败保留完整双流日志且不覆盖已有文件() {
        let temp = tempfile::tempdir().unwrap();
        let log = temp.path().join("archive.log");
        let cancel = Arc::new(AtomicBool::new(false));
        let args = ["-c", "printf '构建开头\\nfatal error: 缺少头文件\\n构建结尾\\n'; printf 'warning: 次要警告\\n' >&2; exit 1"].map(OsString::from);
        let error = run(
            "/bin/sh",
            &args,
            None,
            &cancel,
            "归档失败",
            Some(&log),
            |_, _| None,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("fatal error: 缺少头文件"));
        assert!(error.contains(log.to_str().unwrap()));
        let content = std::fs::read_to_string(&log).unwrap();
        assert!(content.contains("构建开头\nfatal error: 缺少头文件\n构建结尾"));
        assert!(content.contains("=== stderr ===\nwarning: 次要警告"));
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&log).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let error = run(
            "/bin/sh",
            &args,
            None,
            &cancel,
            "归档失败",
            Some(&log),
            |_, _| None,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("保存完整日志失败"));
        assert_eq!(std::fs::read_to_string(&log).unwrap(), content);
    }
}
