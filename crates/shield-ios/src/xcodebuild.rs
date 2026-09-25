use crate::IosProjectConfig;
use anyhow::{Context, Result};
use std::ffi::OsString;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

pub(crate) fn resolve_packages(
    project: &Path,
    scheme: &str,
    cancel: &Arc<AtomicBool>,
) -> Result<()> {
    let mut args = project_selector(project)?;
    args.extend([
        OsString::from("-scheme"),
        OsString::from(scheme),
        OsString::from("-resolvePackageDependencies"),
    ]);
    run("xcodebuild", &args, cancel, "解析 Swift Package 失败")
}

pub(crate) fn archive(
    project: &Path,
    config: &IosProjectConfig,
    archive_path: &Path,
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
        OsString::from("-skipMacroValidation"),
        OsString::from("-skipPackagePluginValidation"),
        OsString::from(format!("DEVELOPMENT_TEAM={}", config.team_id)),
    ]);
    if allow_provisioning_updates {
        args.push(OsString::from("-allowProvisioningUpdates"));
    }
    args.push(OsString::from("archive"));
    run("xcodebuild", &args, cancel, "生成 Xcode Archive 失败")
}

pub(crate) fn export_archive(
    archive_path: &Path,
    export_path: &Path,
    export_options: &Path,
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
    run("xcodebuild", &args, cancel, "导出 IPA 失败")
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

fn run(program: &str, args: &[OsString], cancel: &Arc<AtomicBool>, context: &str) -> Result<()> {
    if cancel.load(Ordering::SeqCst) {
        anyhow::bail!("iOS 保护任务已取消");
    }
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
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
    let stdout = stdout_thread.join().unwrap_or_default();
    let stderr = stderr_thread.join().unwrap_or_default();
    if !status.success() {
        let diagnostic = command_diagnostic(&stdout, &stderr);
        anyhow::bail!("{context}：{diagnostic}");
    }
    Ok(())
}

fn read_all(mut reader: impl Read) -> Vec<u8> {
    let mut output = Vec::new();
    let _ = reader.read_to_end(&mut output);
    output
}

fn command_diagnostic(stdout: &[u8], stderr: &[u8]) -> String {
    let stderr = String::from_utf8_lossy(stderr);
    let stdout = String::from_utf8_lossy(stdout);
    stderr
        .lines()
        .chain(stdout.lines().rev())
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .take(24)
        .collect::<Vec<_>>()
        .join("；")
}
