use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tempfile::{NamedTempFile, TempDir};

use crate::diagnostic::{Diagnostic, FailureCode, ToolName};
use crate::utils::{find_java, no_window_command};
use crate::zipalign::align_apk;

#[derive(Debug, Clone, PartialEq)]
pub enum KeystoreType {
    Jks,
    Pkcs12,
}

impl KeystoreType {
    pub fn as_str(&self) -> &'static str {
        match self {
            KeystoreType::Jks => "JKS",
            KeystoreType::Pkcs12 => "PKCS12",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "PKCS12" | "P12" => KeystoreType::Pkcs12,
            _ => KeystoreType::Jks,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SigningVersions {
    pub v1: bool,
    pub v2: bool,
    pub v3: bool,
    pub v4: bool,
}

impl Default for SigningVersions {
    fn default() -> Self {
        Self {
            v1: true,
            v2: true,
            v3: true,
            v4: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SignOptions {
    pub apk_path: PathBuf,
    pub output_path: Option<PathBuf>,
    pub keystore_path: PathBuf,
    pub key_alias: String,
    pub keystore_password: String,
    pub key_password: String,
    pub apksigner_path: Option<PathBuf>,
    pub keystore_type: KeystoreType,
    pub signing_versions: SigningVersions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningProgressStep {
    Prepare,
    Align,
    Sign,
    Commit,
}

pub fn sign_apk(opts: &SignOptions) -> Result<()> {
    sign_apk_with_progress(opts, |_| Ok(()))
}

pub fn sign_apk_with_progress(
    opts: &SignOptions,
    on_progress: impl FnMut(SigningProgressStep) -> std::result::Result<(), String>,
) -> Result<()> {
    let java = find_java().map_err(|err| Diagnostic::new(FailureCode::ToolNotFound).attach(err))?;
    sign_apk_with_java(opts, on_progress, &java)
}

fn sign_apk_with_java(
    opts: &SignOptions,
    mut on_progress: impl FnMut(SigningProgressStep) -> std::result::Result<(), String>,
    java: &Path,
) -> Result<()> {
    validate_signing_versions(&opts.signing_versions)?;
    on_progress(SigningProgressStep::Prepare).map_err(anyhow::Error::msg)?;

    let final_output = opts
        .output_path
        .clone()
        .unwrap_or_else(|| opts.apk_path.clone());
    anyhow::ensure!(!final_output.as_os_str().is_empty(), "签名输出路径不能为空");
    let output_parent = usable_parent(&final_output);
    ensure_output_parent(&output_parent)?;
    reject_output_symlink(&final_output)?;

    let source_report = crate::protection_report::report_path(&opts.apk_path);
    let mut protection_report = if source_report.exists() {
        let report = crate::protection_report::MethodReport::read(&source_report)?;
        anyhow::ensure!(
            report.output_sha256.as_deref()
                == Some(&crate::protection_report::file_sha256(&opts.apk_path)?),
            "待签名 APK 与保护报告摘要不一致"
        );
        Some(report)
    } else {
        None
    };

    let apksigner = match &opts.apksigner_path {
        Some(p) if p.exists() => p.clone(),
        Some(p) => anyhow::bail!("配置的 apksigner.jar 路径不存在: {}", p.display()),
        None => find_apksigner()
            .map_err(|err| Diagnostic::new(FailureCode::ToolNotFound).attach(err))?,
    };

    // 口令经文件传递：写在命令行上的口令对同机其他进程可见（ps、/proc/<pid>/cmdline）。
    // 临时目录随本轮操作结束清理，口令文件另收紧到 0600。
    let password_dir = TempDir::new().context("创建签名口令临时目录失败")?;
    let ks_pass_arg = format!(
        "file:{}",
        java_path(&write_password_file(
            password_dir.path(),
            "ks.pass",
            &opts.keystore_password
        )?)?
    );
    let key_pass_arg = format!(
        "file:{}",
        java_path(&write_password_file(
            password_dir.path(),
            "key.pass",
            &opts.key_password
        )?)?
    );

    let aligned_input = password_dir.path().join("aligned.apk");
    on_progress(SigningProgressStep::Align).map_err(anyhow::Error::msg)?;
    fs::copy(&opts.apk_path, &aligned_input)
        .with_context(|| format!("复制待签名 APK 到临时目录失败: {}", opts.apk_path.display()))?;
    align_apk(&aligned_input)
        .context("内置 APK 对齐失败")
        .map_err(|err| {
            Diagnostic::from_error(&err)
                .or_code(FailureCode::AlignmentFailed)
                .attach(err)
        })?;

    // 暂存 APK 和 V4 附件由同一个任务目录持有；任何提前返回都会把两者一起清理。
    let (staging_dir, staged_output, staged_idsig) = create_signing_stage(&output_parent)?;
    let staged_path = staged_output.path().to_path_buf();

    let aligned_input_str = java_path(&aligned_input)?;
    let staged_output_str = java_path(&staged_path)?;
    let cmd_args: Vec<String> = vec![
        "-jar".into(),
        java_path(&apksigner)?,
        "sign".into(),
        "--ks-type".into(),
        opts.keystore_type.as_str().into(),
        "--ks".into(),
        java_path(&opts.keystore_path)?,
        "--ks-key-alias".into(),
        opts.key_alias.clone(),
        "--ks-pass".into(),
        ks_pass_arg,
        "--key-pass".into(),
        key_pass_arg,
        "--v1-signing-enabled".into(),
        bool_str(opts.signing_versions.v1).into(),
        "--v2-signing-enabled".into(),
        bool_str(opts.signing_versions.v2).into(),
        "--v3-signing-enabled".into(),
        bool_str(opts.signing_versions.v3).into(),
        "--v4-signing-enabled".into(),
        bool_str(opts.signing_versions.v4).into(),
        "--out".into(),
        staged_output_str,
        aligned_input_str,
    ];

    on_progress(SigningProgressStep::Sign).map_err(anyhow::Error::msg)?;
    let output = no_window_command(java)
        .args(&cmd_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("启动 apksigner 失败，请确认 Java 可用")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let code = output.status.code().unwrap_or(-1);
        return Err(Diagnostic::from_tool_output(
            ToolName::Apksigner,
            output.status.code(),
            if output.stderr.is_empty() {
                &output.stdout
            } else {
                &output.stderr
            },
        )
        .attach(anyhow::anyhow!(
            "签名失败（apksigner 退出码 {code}）：{}",
            classify_apksigner_error(&stderr, &stdout)
        )));
    }

    staged_output
        .as_file()
        .sync_all()
        .context("同步暂存 APK 失败")?;
    ensure_nonempty_file(&staged_path, "apksigner 未生成有效签名 APK")?;

    if opts.signing_versions.v4 {
        ensure_nonempty_file(&staged_idsig, "apksigner 未生成有效的 V4 签名附件")?;
    } else if staged_idsig.exists() {
        // 明确关闭 V4 时不能把签名器意外生成的附件带入最终产物。
        fs::remove_file(&staged_idsig)
            .with_context(|| format!("清理暂存 V4 附件失败: {}", staged_idsig.display()))?;
    }

    let staged_report = if let Some(report) = protection_report.as_mut() {
        report.bind(&staged_path, false)?;
        Some(write_staged_report(report, &output_parent)?)
    } else {
        None
    };

    on_progress(SigningProgressStep::Commit).map_err(anyhow::Error::msg)?;
    let final_report = crate::protection_report::report_path(&final_output);
    let final_idsig = idsig_path(&final_output);
    let staged_idsig = opts.signing_versions.v4.then_some(staged_idsig);
    commit_signed_outputs(
        &output_parent,
        staged_output,
        staged_report,
        staged_idsig.as_deref(),
        &final_output,
        &final_report,
        &final_idsig,
    )?;
    drop(staging_dir);

    Ok(())
}

/// 把口令写入临时文件并收紧权限，供 apksigner 的 `file:`、keytool/jarsigner 的 `:file`
/// 参数使用。文件内容不追加换行；包含 CR/LF 的口令无法由单行文件无损表达，直接拒绝。
pub fn write_password_file(dir: &Path, name: &str, password: &str) -> Result<PathBuf> {
    anyhow::ensure!(
        !password.contains('\n') && !password.contains('\r'),
        "密码包含换行符，无法通过密码文件安全传递"
    );
    let path = dir.join(name);
    fs::write(&path, password.as_bytes())
        .with_context(|| format!("写入口令文件失败: {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("收紧口令文件权限失败: {}", path.display()))?;
    }
    Ok(path)
}

fn validate_signing_versions(versions: &SigningVersions) -> Result<()> {
    anyhow::ensure!(
        !versions.v4 || versions.v2 || versions.v3,
        "V4 签名需要同时启用 V2 或 V3；请调整签名版本组合"
    );
    Ok(())
}

fn usable_parent(path: &Path) -> PathBuf {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .to_path_buf()
}

fn ensure_output_parent(parent: &Path) -> Result<()> {
    let metadata = fs::metadata(parent)
        .with_context(|| format!("输出目录不存在或不可访问: {}", parent.display()))?;
    anyhow::ensure!(
        metadata.is_dir(),
        "输出路径的父级不是目录: {}",
        parent.display()
    );
    Ok(())
}

fn reject_output_symlink(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            anyhow::bail!(
                "输出文件是符号链接，请选择实际输出文件而不是链接: {}",
                path.display()
            )
        }
        Ok(metadata) if metadata.is_dir() => {
            anyhow::bail!("输出路径是目录，不能作为 APK 文件: {}", path.display())
        }
        _ => Ok(()),
    }
}

fn ensure_nonempty_file(path: &Path, message: &str) -> Result<()> {
    let metadata = fs::metadata(path).with_context(|| format!("{message}: {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_file() && metadata.len() > 0,
        "{message}: {}",
        path.display()
    );
    Ok(())
}

fn create_signing_stage(parent: &Path) -> Result<(TempDir, NamedTempFile, PathBuf)> {
    let staging_dir = tempfile::Builder::new()
        .prefix("shield-signed-")
        .tempdir_in(parent)
        .with_context(|| {
            format!(
                "创建签名暂存目录失败，请确认输出目录可写: {}",
                parent.display()
            )
        })?;
    let staged_apk = tempfile::Builder::new()
        .prefix("signed-")
        .suffix(".apk")
        .tempfile_in(staging_dir.path())
        .context("创建签名暂存 APK 失败")?;
    let staged_idsig = idsig_path(staged_apk.path());
    Ok((staging_dir, staged_apk, staged_idsig))
}

fn write_staged_report(
    report: &crate::protection_report::MethodReport,
    parent: &Path,
) -> Result<NamedTempFile> {
    let mut file = tempfile::Builder::new()
        .prefix("shield-report-")
        .suffix(".json")
        .tempfile_in(parent)
        .context("创建保护报告暂存文件失败")?;
    serde_json::to_writer_pretty(&mut file, report).context("写入保护报告暂存文件失败")?;
    file.as_file_mut()
        .sync_all()
        .context("同步保护报告暂存文件失败")?;
    Ok(file)
}

fn java_path(path: &Path) -> Result<String> {
    dunce::simplified(path)
        .to_str()
        .map(str::to_owned)
        .with_context(|| format!("路径包含非法字符: {}", path.display()))
}

fn idsig_path(apk: &Path) -> PathBuf {
    let mut value = apk.as_os_str().to_owned();
    value.push(".idsig");
    PathBuf::from(value)
}

struct AttachmentBackup {
    path: PathBuf,
    backup: PathBuf,
    existed: bool,
}

fn backup_attachment(path: &Path, recovery: &Path, name: &str) -> Result<AttachmentBackup> {
    let existed = path.exists();
    let backup = recovery.join(name);
    if existed {
        fs::copy(path, &backup).with_context(|| format!("备份旧附件失败: {}", path.display()))?;
    }
    Ok(AttachmentBackup {
        path: path.to_path_buf(),
        backup,
        existed,
    })
}

fn restore_attachment(backup: &AttachmentBackup) -> Result<()> {
    if backup.existed {
        fs::copy(&backup.backup, &backup.path)
            .with_context(|| format!("恢复旧附件失败: {}", backup.path.display()))?;
    } else if backup.path.exists() {
        fs::remove_file(&backup.path)
            .with_context(|| format!("删除本次新建附件失败: {}", backup.path.display()))?;
    }
    Ok(())
}

fn restore_attachments(report: &AttachmentBackup, idsig: &AttachmentBackup) -> Result<()> {
    restore_attachment(report)?;
    restore_attachment(idsig)
}

fn recovery_failure(
    recovery: TempDir,
    primary: anyhow::Error,
    restore: anyhow::Error,
) -> anyhow::Error {
    let path = recovery.keep();
    anyhow::anyhow!(
        "提交签名产物失败：{primary}；恢复旧附件也失败：{restore}。恢复副本保留在 {}",
        path.display()
    )
}

fn commit_signed_outputs(
    parent: &Path,
    staged_apk: NamedTempFile,
    staged_report: Option<NamedTempFile>,
    staged_idsig: Option<&Path>,
    final_output: &Path,
    final_report: &Path,
    final_idsig: &Path,
) -> Result<()> {
    let recovery = tempfile::Builder::new()
        .prefix("shield-recovery-")
        .tempdir_in(parent)
        .context("创建签名恢复目录失败")?;
    let report_backup = backup_attachment(final_report, recovery.path(), "report.json")?;
    let idsig_backup = backup_attachment(final_idsig, recovery.path(), "idsig")?;

    if let Err(primary) = commit_attachments(staged_report, staged_idsig, final_report, final_idsig)
    {
        return match restore_attachments(&report_backup, &idsig_backup) {
            Ok(()) => Err(anyhow::anyhow!(
                "提交签名附件失败，旧附件尚未改变：{primary}"
            )),
            Err(restore) => Err(recovery_failure(recovery, primary, restore)),
        };
    }

    match staged_apk.persist(final_output) {
        Ok(_) => Ok(()),
        Err(error) => {
            let primary = anyhow::Error::from(error.error)
                .context(format!("替换最终 APK 失败: {}", final_output.display()));
            match restore_attachments(&report_backup, &idsig_backup) {
                Ok(()) => Err(anyhow::anyhow!(
                    "替换最终 APK 失败，旧 APK 保持不变，旧附件已恢复：{primary}"
                )),
                Err(restore) => Err(recovery_failure(recovery, primary, restore)),
            }
        }
    }
}

fn commit_attachments(
    staged_report: Option<NamedTempFile>,
    staged_idsig: Option<&Path>,
    final_report: &Path,
    final_idsig: &Path,
) -> Result<()> {
    if let Some(staged_report) = staged_report {
        if final_report.exists() {
            fs::remove_file(final_report)
                .with_context(|| format!("删除旧保护报告失败: {}", final_report.display()))?;
        }
        staged_report.persist(final_report).map_err(|error| {
            anyhow::Error::from(error.error)
                .context(format!("提交保护报告失败: {}", final_report.display()))
        })?;
    } else if final_report.exists() {
        fs::remove_file(final_report)
            .with_context(|| format!("删除旧保护报告失败: {}", final_report.display()))?;
    }

    if let Some(staged_idsig) = staged_idsig {
        if final_idsig.exists() {
            fs::remove_file(final_idsig)
                .with_context(|| format!("删除旧 V4 附件失败: {}", final_idsig.display()))?;
        }
        fs::rename(staged_idsig, final_idsig)
            .with_context(|| format!("提交 V4 附件失败: {}", final_idsig.display()))?;
    } else if final_idsig.exists() {
        fs::remove_file(final_idsig)
            .with_context(|| format!("删除旧 V4 附件失败: {}", final_idsig.display()))?;
    }
    Ok(())
}

fn bool_str(b: bool) -> &'static str {
    if b {
        "true"
    } else {
        "false"
    }
}

pub fn find_apksigner() -> Result<PathBuf> {
    crate::utils::find_apksigner()
}

pub fn check_apksigner(custom: Option<&Path>) -> (bool, Option<String>) {
    if let Some(p) = custom {
        if p.exists() {
            return (true, None);
        } else {
            return (
                false,
                Some(format!("配置的 apksigner.jar 路径不存在: {}", p.display())),
            );
        }
    }
    match find_apksigner() {
        Ok(_) => (true, None),
        Err(e) => (false, Some(e.to_string())),
    }
}

fn classify_apksigner_error(stderr: &str, stdout: &str) -> String {
    let raw = sanitize_tool_output(if stderr.trim().is_empty() {
        stdout
    } else {
        stderr
    });
    let lower = raw.to_lowercase();

    let reason = if lower.contains("keystore was tampered with")
        || lower.contains("password was incorrect")
        || lower.contains("password is incorrect")
        || lower.contains("keystore password was incorrect")
        || raw.contains("密码不正确")
        || raw.contains("口令不正确")
        || raw.contains("密码错误")
    {
        "Keystore 密码不正确，请检查证书密码"
    } else if lower.contains("cannot recover key")
        || lower.contains("failed to recover key")
        || lower.contains("key password was incorrect")
        || lower.contains("given final block not properly padded")
        || raw.contains("无法恢复密钥")
    {
        "Key 密码不正确；如果 Key 密码与 Keystore 密码相同，可在证书配置中留空 Key 密码"
    } else if lower.contains("no key with alias")
        || lower.contains("alias") && lower.contains("does not exist")
        || lower.contains("failed to find")
        || raw.contains("别名") && raw.contains("不存在")
    {
        "证书 Alias 不存在，请在证书页重新识别 Alias 或重新导入证书"
    } else if lower.contains("invalid keystore format")
        || lower.contains("unrecognized keystore format")
        || lower.contains("toderinputstream rejects tag type")
        || lower.contains("derinputstream.getlength")
        || raw.contains("无效的密钥库格式")
        || raw.contains("无法识别的密钥库格式")
    {
        "证书格式与选择的 JKS/PKCS12 类型不匹配，或 keystore 文件已损坏"
    } else if lower.contains("no such file")
        || lower.contains("file not found")
        || lower.contains("cannot find")
        || raw.contains("系统找不到")
        || raw.contains("没有那个文件")
    {
        "找不到输入 APK、输出目录或 Keystore 文件，请确认文件仍在原路径"
    } else if lower.contains("permission denied")
        || lower.contains("access is denied")
        || raw.contains("权限")
        || raw.contains("拒绝访问")
    {
        "没有权限读取输入文件或写入输出文件，请检查文件权限与输出目录"
    } else if lower.contains("not a valid apk")
        || lower.contains("invalid apk")
        || lower.contains("malformed apk")
        || lower.contains("zip")
        || lower.contains("failed to parse")
    {
        "输入文件不是有效 APK，或 APK 结构已经损坏"
    } else if lower.contains("min-sdk-version")
        || lower.contains("minimum supported platform version")
        || lower.contains("failed to determine")
    {
        "无法识别 APK 的 minSdkVersion；请确认 AndroidManifest.xml 有效，必要时先用 Android 构建工具重新生成 APK"
    } else if lower.contains("java.lang.unsupportedclassversionerror")
        || lower.contains("unsupported major.minor version")
    {
        "当前 Java 版本过低，请安装并使用完整 JDK 8+"
    } else {
        "apksigner 未返回可识别的错误类型"
    };

    if raw.is_empty() {
        reason.to_string()
    } else {
        format!("{reason}。apksigner 输出：{raw}")
    }
}

fn sanitize_tool_output(raw: &str) -> String {
    raw.split_whitespace()
        .map(|part| {
            if part.starts_with("pass:") {
                "pass:******"
            } else {
                part
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn write_test_apk(path: &Path) {
        use std::io::Write;
        let file = fs::File::create(path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file("classes.dex", zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(b"dex").unwrap();
        zip.finish().unwrap();
    }

    #[cfg(unix)]
    fn fake_java(dir: &Path, fail_after_write: bool) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(if fail_after_write {
            "java-fail"
        } else {
            "java-success"
        });
        let tail = if fail_after_write {
            "exit 2\n"
        } else {
            "exit 0\n"
        };
        let script = format!(
            "#!/bin/sh\n\
             if [ \"$1\" = \"-version\" ]; then\n\
               echo 'openjdk version \"17.0.0\"' >&2\n\
               exit 0\n\
             fi\n\
             out=\"\"\n\
             input=\"\"\n\
             prev=\"\"\n\
             v4=0\n\
             for arg in \"$@\"; do\n\
               if [ \"$prev\" = \"--out\" ]; then out=\"$arg\"; fi\n\
               if [ \"$prev\" = \"--v4-signing-enabled\" ] && [ \"$arg\" = \"true\" ]; then v4=1; fi\n\
               input=\"$arg\"\n\
               prev=\"$arg\"\n\
             done\n\
             cp \"$input\" \"$out\" || exit 3\n\
             if [ \"$v4\" = \"1\" ]; then echo fake > \"$out.idsig\"; fi\n\
             {tail}"
        );
        fs::write(&path, script).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[cfg(unix)]
    fn signing_options(root: &Path, output: PathBuf) -> SignOptions {
        SignOptions {
            apk_path: root.join("input.apk"),
            output_path: Some(output),
            keystore_path: root.join("fake.jks"),
            key_alias: "test".into(),
            keystore_password: "synthetic-pass".into(),
            key_password: "synthetic-pass".into(),
            apksigner_path: Some(root.join("apksigner.jar")),
            keystore_type: KeystoreType::Jks,
            signing_versions: SigningVersions {
                v1: true,
                v2: true,
                v3: true,
                v4: true,
            },
        }
    }

    #[cfg(unix)]
    fn staging_entries(root: &Path) -> usize {
        fs::read_dir(root)
            .unwrap()
            .flatten()
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("shield-signed-")
            })
            .count()
    }

    #[cfg(unix)]
    #[test]
    fn 提交前取消保留旧产物并清理暂存目录() {
        let root = tempfile::tempdir().unwrap();
        write_test_apk(&root.path().join("input.apk"));
        fs::write(root.path().join("fake.jks"), b"fake").unwrap();
        fs::write(root.path().join("apksigner.jar"), b"fake").unwrap();
        let output = root.path().join("release.apk");
        fs::write(&output, b"old-apk").unwrap();
        fs::write(root.path().join("release.apk.idsig"), b"old-idsig").unwrap();
        let java = fake_java(root.path(), false);

        let result = sign_apk_with_java(
            &signing_options(root.path(), output.clone()),
            |step| {
                if step == SigningProgressStep::Commit {
                    Err("cancelled".into())
                } else {
                    Ok(())
                }
            },
            &java,
        );

        assert!(result.is_err());
        assert_eq!(fs::read(&output).unwrap(), b"old-apk");
        assert_eq!(
            fs::read(root.path().join("release.apk.idsig")).unwrap(),
            b"old-idsig"
        );
        assert_eq!(staging_entries(root.path()), 0);
    }

    #[cfg(unix)]
    #[test]
    fn 签名器写出后失败不遗留暂存附件() {
        let root = tempfile::tempdir().unwrap();
        write_test_apk(&root.path().join("input.apk"));
        fs::write(root.path().join("fake.jks"), b"fake").unwrap();
        fs::write(root.path().join("apksigner.jar"), b"fake").unwrap();
        let output = root.path().join("failed.apk");
        fs::write(&output, b"old-apk").unwrap();
        fs::write(root.path().join("failed.apk.idsig"), b"old-idsig").unwrap();
        let java = fake_java(root.path(), true);

        assert!(sign_apk_with_java(
            &signing_options(root.path(), output.clone()),
            |_| Ok(()),
            &java,
        )
        .is_err());
        assert_eq!(fs::read(&output).unwrap(), b"old-apk");
        assert_eq!(
            fs::read(root.path().join("failed.apk.idsig")).unwrap(),
            b"old-idsig"
        );
        assert_eq!(staging_entries(root.path()), 0);
    }

    fn temp_file(dir: &Path, name: &str, content: &[u8]) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn keystore_type_from_str_jks_is_default() {
        assert_eq!(KeystoreType::parse("JKS"), KeystoreType::Jks);
        assert_eq!(KeystoreType::parse("jks"), KeystoreType::Jks);
        assert_eq!(KeystoreType::parse("unknown"), KeystoreType::Jks);
    }

    #[test]
    fn keystore_type_from_str_pkcs12_variants() {
        assert_eq!(KeystoreType::parse("PKCS12"), KeystoreType::Pkcs12);
        assert_eq!(KeystoreType::parse("pkcs12"), KeystoreType::Pkcs12);
        assert_eq!(KeystoreType::parse("P12"), KeystoreType::Pkcs12);
        assert_eq!(KeystoreType::parse("p12"), KeystoreType::Pkcs12);
    }

    #[test]
    fn keystore_type_as_str_values() {
        assert_eq!(KeystoreType::Jks.as_str(), "JKS");
        assert_eq!(KeystoreType::Pkcs12.as_str(), "PKCS12");
    }

    #[test]
    fn signing_versions_default_enables_v1_v2_v3_not_v4() {
        let v = SigningVersions::default();
        assert!(v.v1);
        assert!(v.v2);
        assert!(v.v3);
        assert!(!v.v4);
    }

    #[test]
    fn v4_需要_v2_或_v3() {
        let invalid = SigningVersions {
            v1: true,
            v2: false,
            v3: false,
            v4: true,
        };
        assert!(validate_signing_versions(&invalid).is_err());
        let valid = SigningVersions {
            v1: false,
            v2: true,
            v3: false,
            v4: true,
        };
        assert!(validate_signing_versions(&valid).is_ok());
    }

    #[test]
    fn idsig_路径保留原始文件名大小写和空格() {
        assert_eq!(
            idsig_path(Path::new("/tmp/My App.APK")),
            PathBuf::from("/tmp/My App.APK.idsig")
        );
    }

    #[test]
    fn 口令文件收紧权限并拒绝换行() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_password_file(dir.path(), "test.pass", "  中文 pass  ").unwrap();
        assert_eq!(fs::read(&path).unwrap(), "  中文 pass  ".as_bytes());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(write_password_file(dir.path(), "bad.pass", "line1\nline2").is_err());
        assert!(write_password_file(dir.path(), "bad.pass", "line1\rline2").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn 签名暂存目录会同时清理_apk_和_idsig() {
        let dir = tempfile::tempdir().unwrap();
        let (staging, staged_apk, staged_idsig) = create_signing_stage(dir.path()).unwrap();
        let apk_path = staged_apk.path().to_path_buf();
        fs::write(&apk_path, b"staged-apk").unwrap();
        fs::write(&staged_idsig, b"staged-idsig").unwrap();
        drop(staging);
        assert!(!apk_path.exists());
        assert!(!staged_idsig.exists());
        assert!(fs::read_dir(dir.path()).unwrap().next().is_none());
    }

    #[test]
    fn 输出文件是符号链接时拒绝签名() {
        #[cfg(unix)]
        {
            let dir = tempfile::tempdir().unwrap();
            let target = temp_file(dir.path(), "target.apk", b"old");
            let link = dir.path().join("link.apk");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            assert!(reject_output_symlink(&link).is_err());
            assert!(reject_output_symlink(&target).is_ok());
        }
    }

    #[test]
    fn 提交成功时同时替换_apk_报告和_v4_附件() {
        let dir = tempfile::tempdir().unwrap();
        let final_apk = temp_file(dir.path(), "app.APK", b"old-apk");
        let final_report = temp_file(dir.path(), "app.APK.protection.json", b"old-report");
        let final_idsig = temp_file(dir.path(), "app.APK.idsig", b"old-idsig");
        let mut staged = NamedTempFile::new_in(dir.path()).unwrap();
        std::io::Write::write_all(&mut staged, b"new-apk").unwrap();
        let mut staged_report = NamedTempFile::new_in(dir.path()).unwrap();
        std::io::Write::write_all(&mut staged_report, b"new-report").unwrap();
        let staged_idsig = temp_file(dir.path(), "staged.idsig", b"new-idsig");

        commit_signed_outputs(
            dir.path(),
            staged,
            Some(staged_report),
            Some(&staged_idsig),
            &final_apk,
            &final_report,
            &final_idsig,
        )
        .unwrap();

        assert_eq!(fs::read(&final_apk).unwrap(), b"new-apk");
        assert_eq!(fs::read(&final_report).unwrap(), b"new-report");
        assert_eq!(fs::read(&final_idsig).unwrap(), b"new-idsig");
    }

    #[test]
    fn v4_关闭时提交成功会删除旧附件() {
        let dir = tempfile::tempdir().unwrap();
        let final_apk = temp_file(dir.path(), "app.apk", b"old-apk");
        let final_report = temp_file(dir.path(), "app.apk.protection.json", b"old-report");
        let final_idsig = temp_file(dir.path(), "app.apk.idsig", b"old-idsig");
        let mut staged = NamedTempFile::new_in(dir.path()).unwrap();
        std::io::Write::write_all(&mut staged, b"new-apk").unwrap();

        commit_signed_outputs(
            dir.path(),
            staged,
            None,
            None,
            &final_apk,
            &final_report,
            &final_idsig,
        )
        .unwrap();

        assert_eq!(fs::read(&final_apk).unwrap(), b"new-apk");
        assert!(!final_report.exists());
        assert!(!final_idsig.exists());
    }

    #[test]
    fn apk_替换失败时恢复旧报告和附件() {
        let dir = tempfile::tempdir().unwrap();
        let final_apk = dir.path().join("app.apk");
        fs::create_dir(&final_apk).unwrap();
        let final_report = temp_file(dir.path(), "app.apk.protection.json", b"old-report");
        let final_idsig = temp_file(dir.path(), "app.apk.idsig", b"old-idsig");
        let mut staged = NamedTempFile::new_in(dir.path()).unwrap();
        std::io::Write::write_all(&mut staged, b"new-apk").unwrap();
        let mut staged_report = NamedTempFile::new_in(dir.path()).unwrap();
        std::io::Write::write_all(&mut staged_report, b"new-report").unwrap();
        let staged_idsig = temp_file(dir.path(), "staged.idsig", b"new-idsig");

        let error = commit_signed_outputs(
            dir.path(),
            staged,
            Some(staged_report),
            Some(&staged_idsig),
            &final_apk,
            &final_report,
            &final_idsig,
        )
        .unwrap_err();

        assert!(error.to_string().contains("旧 APK 保持不变"));
        assert_eq!(fs::read(&final_report).unwrap(), b"old-report");
        assert_eq!(fs::read(&final_idsig).unwrap(), b"old-idsig");
        assert!(final_apk.is_dir());
    }

    #[test]
    fn bool_str_returns_correct_literals() {
        assert_eq!(bool_str(true), "true");
        assert_eq!(bool_str(false), "false");
    }

    #[test]
    fn check_apksigner_nonexistent_custom_path_returns_error() {
        let (ok, msg) = check_apksigner(Some(Path::new("/nonexistent/apksigner.jar")));
        assert!(!ok);
        assert!(msg.is_some());
    }

    #[test]
    fn check_apksigner_existing_custom_path_returns_ok() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let (ok, msg) = check_apksigner(Some(tmp.path()));
        assert!(ok);
        assert!(msg.is_none());
    }

    #[test]
    fn apksigner_密码错误提示更明确() {
        let message = classify_apksigner_error(
            "Failed to load signer: Keystore was tampered with, or password was incorrect",
            "",
        );
        assert!(message.starts_with("Keystore 密码不正确"));
    }

    #[test]
    fn apksigner_key_密码错误提示更明确() {
        let message = classify_apksigner_error(
            "java.security.UnrecoverableKeyException: Cannot recover key",
            "",
        );
        assert!(message.starts_with("Key 密码不正确"));
    }

    #[test]
    fn apksigner_alias_不存在提示更明确() {
        let message = classify_apksigner_error("No key with alias release in keystore", "");
        assert!(message.starts_with("证书 Alias 不存在"));
    }

    #[test]
    fn apksigner_非法_apk_提示更明确() {
        let message = classify_apksigner_error("Failed to parse APK: not a valid APK", "");
        assert!(message.starts_with("输入文件不是有效 APK"));
    }

    #[test]
    fn apksigner_输出会脱敏_pass_参数() {
        let message = classify_apksigner_error("failed with --ks-pass pass:secret123", "");
        assert!(message.contains("pass:******"));
        assert!(!message.contains("secret123"));
    }
}
