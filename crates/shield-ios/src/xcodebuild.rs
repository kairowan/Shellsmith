use crate::IosProjectConfig;
use anyhow::{Context, Result};
use std::ffi::OsString;
use std::fs::OpenOptions;
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
    run(
        "xcodebuild",
        &args,
        developer_dir,
        cancel,
        "导出 IPA 失败",
        Some(&export_path.with_extension("export.log")),
    )
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

pub(crate) fn run(
    program: &str,
    args: &[OsString],
    developer_dir: Option<&Path>,
    cancel: &Arc<AtomicBool>,
    context: &str,
    failure_log: Option<&Path>,
) -> Result<()> {
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
        let log_note = failure_log
            .map(|path| match write_command_log(path, &stdout, &stderr) {
                Ok(()) => format!("；完整构建日志（仅保存在本机）：{}", path.display()),
                Err(error) => format!("；保存完整日志失败（{}）：{error}", path.display()),
            })
            .unwrap_or_default();
        anyhow::bail!("{context}：{diagnostic}{log_note}");
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

    #[cfg(unix)]
    #[test]
    fn 命令失败保留完整双流日志且不覆盖已有文件() {
        let temp = tempfile::tempdir().unwrap();
        let log = temp.path().join("archive.log");
        let cancel = Arc::new(AtomicBool::new(false));
        let args = ["-c", "printf '构建开头\\nfatal error: 缺少头文件\\n构建结尾\\n'; printf 'warning: 次要警告\\n' >&2; exit 1"].map(OsString::from);
        let error = run("/bin/sh", &args, None, &cancel, "归档失败", Some(&log))
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
        let error = run("/bin/sh", &args, None, &cancel, "归档失败", Some(&log))
            .unwrap_err()
            .to_string();
        assert!(error.contains("保存完整日志失败"));
        assert_eq!(std::fs::read_to_string(&log).unwrap(), content);
    }
}
