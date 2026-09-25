use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::{Builder, NamedTempFile};
use zip::ZipArchive;

use crate::protection_policy::ProtectionProfile;
use crate::utils::no_window_command;

const PVM2_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const PVM2_HARD_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Clone, Copy)]
struct ProcessLimits {
    idle: Duration,
    hard: Duration,
}

struct ProcessOutput {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

struct OutputLine {
    stderr: bool,
    text: String,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct TransformReport {
    pub(crate) transformed: usize,
    pub(crate) candidates: usize,
    pub(crate) attempted: usize,
    pub(crate) fallback: usize,
    pub(crate) success_rate: f64,
    pub(crate) isa: u8,
    pub(crate) skip_reasons: BTreeMap<String, usize>,
    pub(crate) unsupported_opcodes: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResourceTransformReport {
    mapping: BTreeMap<String, String>,
    source_entries: BTreeMap<String, (u64, u32)>,
    source_arsc_crc: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResourceIdTransformReport {
    pub(crate) changed: usize,
    pub(crate) pinned: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AssetTransformReport {
    pub(crate) encrypted: usize,
    pub(crate) skipped: usize,
    pub(crate) callsites: usize,
    pub(crate) java_assets: usize,
    pub(crate) native_assets: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NativeSoTransformReport {
    pub(crate) encrypted_files: usize,
    pub(crate) encrypted_basenames: usize,
    pub(crate) skipped: usize,
    pub(crate) skipped_policy: usize,
    pub(crate) skipped_reloc: usize,
    pub(crate) skipped_budget: usize,
    pub(crate) function_regions: usize,
}

pub(crate) fn transform_native_sos(
    java: &Path,
    packer: &Path,
    apk_dir: &Path,
    ikm: &[u8],
    signature: &str,
) -> Result<NativeSoTransformReport> {
    let key = crate::dex_packer::derive_native_so_key(ikm, signature);
    let output = no_window_command(java)
        .arg("-jar")
        .arg(packer)
        .arg("native-so-transform")
        .arg("--apk-dir")
        .arg(apk_dir)
        .env("MOCIKA_NATIVE_SO_KEY_HEX", hex_lower(&key))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("启动 Xop Native SO transform-only 失败")?;
    if !output.status.success() {
        anyhow::bail!(resource_transform_failure_message(
            &String::from_utf8_lossy(&output.stdout),
            &String::from_utf8_lossy(&output.stderr)
        ));
    }
    let report = parse_native_so_report(&String::from_utf8_lossy(&output.stdout))?;
    let table = apk_dir.join("assets/protector/mocika-sokeys.bin");
    if report.encrypted_files == 0 {
        if table.exists() {
            anyhow::bail!("Native SO 未加密但产物包含密钥表");
        }
    } else {
        let data = fs::read(&table).context("Native SO 加密后缺少认证密钥表")?;
        if data.len() < 4 + 12 + 16 + 4 || &data[..4] != b"PSO2" {
            anyhow::bail!("Native SO 认证密钥表格式无效");
        }
        if report.encrypted_basenames == 0 || report.encrypted_basenames > report.encrypted_files {
            anyhow::bail!("Native SO 保护报告中的文件/名称计数无效");
        }
    }
    Ok(report)
}

fn parse_native_so_report(stdout: &str) -> Result<NativeSoTransformReport> {
    let values = parse_key_values(
        stdout
            .lines()
            .find(|line| line.starts_with("NATIVE_SO_TRANSFORM_OK"))
            .context("Xop 未返回 Native SO 保护报告")?,
    );
    Ok(NativeSoTransformReport {
        encrypted_files: required_usize(&values, "encrypted_files")?,
        encrypted_basenames: required_usize(&values, "encrypted_basenames")?,
        skipped: required_usize(&values, "skipped")?,
        skipped_policy: required_usize(&values, "skipped_policy")?,
        skipped_reloc: required_usize(&values, "skipped_reloc")?,
        skipped_budget: required_usize(&values, "skipped_budget")?,
        function_regions: required_usize(&values, "function_regions")?,
    })
}

pub(crate) fn transform_resource_ids(
    java: &Path,
    packer: &Path,
    apk_dir: &Path,
) -> Result<ResourceIdTransformReport> {
    let mapping = NamedTempFile::new().context("创建资源 ID 映射临时文件失败")?;
    let output = no_window_command(java)
        .arg("-jar")
        .arg(packer)
        .arg("resource-id-transform")
        .arg("--apk-dir")
        .arg(apk_dir)
        .arg("--mapping-out")
        .arg(mapping.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("启动 Xop 资源 ID transform-only 失败")?;
    if !output.status.success() {
        anyhow::bail!(resource_transform_failure_message(
            &String::from_utf8_lossy(&output.stdout),
            &String::from_utf8_lossy(&output.stderr)
        ));
    }
    let changed = validate_resource_id_mapping(mapping.path())?;
    let values = parse_key_values(
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .find(|line| line.starts_with("RESOURCE_ID_TRANSFORM_OK"))
            .context("Xop 未返回资源 ID 重排报告")?,
    );
    let reported = required_usize(&values, "ids")?;
    if reported != changed {
        anyhow::bail!("资源 ID 重排报告与映射不一致");
    }
    Ok(ResourceIdTransformReport {
        changed,
        pinned: required_usize(&values, "pinned")?,
    })
}

// ponytail: Keep the one-to-one CLI wrapper flat; introduce an options type only if a second caller appears.
#[allow(clippy::too_many_arguments)]
pub(crate) fn transform_assets(
    java: &Path,
    packer: &Path,
    apk_dir: &Path,
    ikm: &[u8],
    signature: &str,
    bridge_class: &str,
    bridge_method: &str,
    allow_external_reader: bool,
) -> Result<AssetTransformReport> {
    let key = crate::dex_packer::derive_assets_pas2_key(ikm, signature);
    let mut command = no_window_command(java);
    command
        .arg("-jar")
        .arg(packer)
        .arg("assets-transform")
        .arg("--apk-dir")
        .arg(apk_dir)
        .arg("--assets-bridge")
        .arg(format!("L{};", bridge_class.replace('.', "/")))
        .arg("--assets-bridge-method")
        .arg(bridge_method)
        .env("MOCIKA_ASSETS_KEY_HEX", hex_lower(&key));
    if allow_external_reader {
        command.arg("--allow-external-reader");
    }
    let output = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("启动 Xop PAS2 assets transform-only 失败")?;
    if !output.status.success() {
        anyhow::bail!(resource_transform_failure_message(
            &String::from_utf8_lossy(&output.stdout),
            &String::from_utf8_lossy(&output.stderr)
        ));
    }
    let values = parse_key_values(
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .find(|line| line.starts_with("ASSETS_TRANSFORM_OK"))
            .context("Xop 未返回 PAS2 assets 报告")?,
    );
    let report = AssetTransformReport {
        encrypted: required_usize(&values, "encrypted")?,
        skipped: required_usize(&values, "skipped")?,
        callsites: required_usize(&values, "callsites")?,
        java_assets: required_usize(&values, "java_assets")?,
        native_assets: required_usize(&values, "native_assets")?,
    };
    verify_pas2_assets(apk_dir, report.encrypted)?;
    let plaintext_map = apk_dir.join("assets/protector/assets.map");
    if plaintext_map.exists() {
        fs::remove_file(&plaintext_map).context("删除 PAS2 明文路径索引失败")?;
    }
    Ok(report)
}

fn validate_resource_id_mapping(path: &Path) -> Result<usize> {
    let text = fs::read_to_string(path).context("读取资源 ID 重排映射失败")?;
    let mut old = std::collections::BTreeSet::new();
    let mut new = std::collections::BTreeSet::new();
    for (index, line) in text.lines().enumerate() {
        let (left, right) = line
            .split_once('\t')
            .with_context(|| format!("资源 ID 映射第 {} 行格式无效", index + 1))?;
        let parse = |value: &str| {
            u32::from_str_radix(value.strip_prefix("0x").unwrap_or(""), 16)
                .with_context(|| format!("无效资源 ID：{value}"))
        };
        let left = parse(left)?;
        let right = parse(right)?;
        if left == right || left >> 16 != right >> 16 {
            anyhow::bail!("资源 ID 重排越过 package/type 边界");
        }
        if !old.insert(left) || !new.insert(right) {
            anyhow::bail!("资源 ID 重排不是一一映射");
        }
    }
    if old != new {
        anyhow::bail!("资源 ID 重排必须是原 ID 集合内的一一置换");
    }
    Ok(old.len())
}

fn verify_pas2_assets(apk_dir: &Path, expected: usize) -> Result<()> {
    let root = apk_dir.join("assets/protector/aenc");
    let mut actual = 0;
    if root.is_dir() {
        for entry in walkdir::WalkDir::new(&root).follow_links(false) {
            let entry = entry.context("遍历 PAS2 assets 失败")?;
            if !entry.file_type().is_file() {
                continue;
            }
            let mut file = fs::File::open(entry.path())
                .with_context(|| format!("打开 PAS2 asset 失败：{}", entry.path().display()))?;
            let mut header = [0u8; 16];
            file.read_exact(&mut header)
                .with_context(|| format!("读取 PAS2 asset 头失败：{}", entry.path().display()))?;
            if &header[..4] != b"PAS2" {
                anyhow::bail!("PAS2 asset 格式无效：{}", entry.path().display());
            }
            actual += 1;
        }
    }
    if actual != expected {
        anyhow::bail!("PAS2 assets 数量不一致：报告 {expected}，实际 {actual}");
    }
    Ok(())
}

impl ResourceTransformReport {
    pub(crate) fn path_count(&self) -> usize {
        self.mapping.len()
    }
}

pub(crate) fn transform_resources(
    java: &Path,
    packer: &Path,
    apk: &Path,
) -> Result<ResourceTransformReport> {
    if !packer.is_file() {
        anyhow::bail!("Xop Packer JAR 不存在: {}", packer.display());
    }
    let parent = apk
        .parent()
        .with_context(|| format!("无法确定 APK 父目录：{}", apk.display()))?;
    let transformed = Builder::new()
        .prefix(".mocika-res-")
        .suffix(".apk")
        .tempfile_in(parent)
        .context("创建资源混淆临时 APK 失败")?;
    let mapping = NamedTempFile::new().context("创建资源混淆映射临时文件失败")?;
    let output = no_window_command(java)
        .arg("-jar")
        .arg(packer)
        .arg("res-transform")
        .arg("--input")
        .arg(apk)
        .arg("--output")
        .arg(transformed.path())
        .arg("--mapping-out")
        .arg(mapping.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("启动 Xop 资源 transform-only 失败")?;
    if !output.status.success() {
        anyhow::bail!(resource_transform_failure_message(
            &String::from_utf8_lossy(&output.stdout),
            &String::from_utf8_lossy(&output.stderr)
        ));
    }
    let parsed_mapping = parse_resource_mapping(mapping.path())?;
    let (source_entries, source_arsc_crc) = capture_resource_source(apk, &parsed_mapping)?;
    let report = ResourceTransformReport {
        mapping: parsed_mapping,
        source_entries,
        source_arsc_crc,
    };
    verify_resource_transform(apk, transformed.path(), &report)?;
    transformed.persist(apk).map_err(|error| {
        anyhow::anyhow!(
            "替换资源混淆后的 APK 失败：{} -> {}：{}",
            error.file.path().display(),
            apk.display(),
            error.error
        )
    })?;
    Ok(report)
}

pub(crate) fn verify_resource_transform(
    _original_apk: &Path,
    transformed_apk: &Path,
    report: &ResourceTransformReport,
) -> Result<()> {
    let transformed_file = fs::File::open(transformed_apk).context("打开资源混淆 APK 失败")?;
    let mut transformed = ZipArchive::new(transformed_file).context("解析资源混淆 APK 失败")?;
    if transformed
        .by_name("assets/protector/res_mapping.txt")
        .is_ok()
    {
        anyhow::bail!("资源混淆产物包含明文路径映射，拒绝继续签名");
    }
    if report.mapping.is_empty() {
        return Ok(());
    }
    for (old, new) in &report.mapping {
        let (old_size, old_crc) = report
            .source_entries
            .get(old)
            .copied()
            .with_context(|| format!("资源混淆报告缺少源条目：{old}"))?;
        if transformed.by_name(old).is_ok() {
            anyhow::bail!("资源旧路径仍存在：{old}");
        }
        let entry = transformed
            .by_name(new)
            .with_context(|| format!("资源混淆产物缺少新路径：{new}"))?;
        if entry.size() != old_size || entry.crc32() != old_crc {
            anyhow::bail!("资源路径改写改变了文件内容：{old} -> {new}");
        }
    }
    let new_arsc = transformed
        .by_name("resources.arsc")
        .context("资源混淆产物缺少 resources.arsc")?
        .crc32();
    if report.source_arsc_crc == new_arsc {
        anyhow::bail!("resources.arsc 未随资源路径更新");
    }
    Ok(())
}

type ResourceEntryFingerprints = BTreeMap<String, (u64, u32)>;

fn capture_resource_source(
    apk: &Path,
    mapping: &BTreeMap<String, String>,
) -> Result<(ResourceEntryFingerprints, u32)> {
    let file = fs::File::open(apk).context("打开待资源混淆 APK 失败")?;
    let mut archive = ZipArchive::new(file).context("解析待资源混淆 APK 失败")?;
    let mut entries = BTreeMap::new();
    for old in mapping.keys() {
        let entry = archive
            .by_name(old)
            .with_context(|| format!("待资源混淆 APK 缺少条目：{old}"))?;
        entries.insert(old.clone(), (entry.size(), entry.crc32()));
    }
    let arsc = archive
        .by_name("resources.arsc")
        .context("待资源混淆 APK 缺少 resources.arsc")?
        .crc32();
    Ok((entries, arsc))
}

fn parse_resource_mapping(path: &Path) -> Result<BTreeMap<String, String>> {
    let text = fs::read_to_string(path).context("读取资源混淆映射失败")?;
    let mut mapping = BTreeMap::new();
    for (index, line) in text.lines().enumerate() {
        let (old, new) = line
            .split_once('\t')
            .with_context(|| format!("资源混淆映射第 {} 行格式无效", index + 1))?;
        if !is_safe_resource_path(old, "res/") || !is_safe_resource_path(new, "r/") {
            anyhow::bail!("资源混淆映射包含非法路径");
        }
        if mapping.insert(old.to_string(), new.to_string()).is_some() {
            anyhow::bail!("资源混淆映射包含重复旧路径：{old}");
        }
    }
    let mut targets = mapping.values().collect::<Vec<_>>();
    targets.sort();
    targets.dedup();
    if targets.len() != mapping.len() {
        anyhow::bail!("资源混淆映射包含重复新路径");
    }
    Ok(mapping)
}

fn is_safe_resource_path(path: &str, prefix: &str) -> bool {
    path.starts_with(prefix)
        && !path.contains("..")
        && !path.contains('\\')
        && !path.chars().any(char::is_whitespace)
}

// ponytail: the arguments mirror the transform-only CLI contract; a one-use
// options struct would add indirection without reducing the boundary surface.
#[allow(clippy::too_many_arguments)]
pub(crate) fn transform(
    java: &Path,
    packer: &Path,
    apk_dir: &Path,
    ikm: &[u8],
    signature: &str,
    profile: ProtectionProfile,
    prefixes: &[String],
    bridge_class: &str,
    bridge_method: &str,
    cancel: &AtomicBool,
    on_progress: &dyn Fn(String),
) -> Result<TransformReport> {
    if !packer.is_file() {
        anyhow::bail!("Xop Packer JAR 不存在: {}", packer.display());
    }
    if prefixes.is_empty() {
        anyhow::bail!("融合 PVM2 必须至少提供一个 --xop-true-vmp-prefix，避免无边界虚拟化");
    }
    for prefix in prefixes {
        validate_prefix(prefix)?;
    }
    if !crate::dex_packer::route_scanner::any_class_matches_prefixes(apk_dir, prefixes)? {
        anyhow::bail!(
            "Xop PVM2 业务类前缀未匹配 APK 中的任何类。请填写应用内真实存在的自有业务包：例如 Java/Kotlin 包 com.acme.app.business 对应 DEX 前缀 Lcom/acme/app/business/；不要照抄界面示例"
        );
    }
    let package = package_name(&apk_dir.join("AndroidManifest.xml"))?;
    let code_out = apk_dir.join(crate::dex_packer::XOP_PVM2_SIDECAR_NAME);
    let key = crate::dex_packer::derive_xop_pvm2_key(ikm, signature);
    let key_hex = hex_lower(&key);
    let profile = match profile {
        ProtectionProfile::Compat | ProtectionProfile::Balanced => "balanced",
        ProtectionProfile::Strict => "industry",
    };
    let bridge_descriptor = format!("L{};", bridge_class.replace('.', "/"));
    let mut command = no_window_command(java);
    command
        .arg("-jar")
        .arg(packer)
        .arg("pvm2-transform")
        .arg("--dex-dir")
        .arg(apk_dir)
        .arg("--code-out")
        .arg(&code_out)
        .arg("--package-name")
        .arg(package)
        .arg("--vm-bridge")
        .arg(&bridge_descriptor)
        .arg("--vm-bridge-method")
        .arg(bridge_method)
        .arg("--profile")
        .arg(profile)
        .arg("--no-payment-auto-vmp")
        .arg("--no-industry-auto-vmp")
        .env("MOCIKA_XOP_PVM2_KEY_HEX", &key_hex)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for prefix in prefixes {
        command.arg("--true-vmp-prefix").arg(prefix);
    }
    let output = run_pvm2_command(
        &mut command,
        cancel,
        on_progress,
        ProcessLimits {
            idle: PVM2_IDLE_TIMEOUT,
            hard: PVM2_HARD_TIMEOUT,
        },
    )?;
    if !output.status.success() {
        anyhow::bail!(transform_failure_message(&output.stdout, &output.stderr));
    }
    let code = fs::read(&code_out).context("Xop 未生成 PVM2 code.bin")?;
    let transformed = validate_code_bin(&code)?;
    parse_transform_report(&output.stdout, transformed)
}

fn run_pvm2_command(
    command: &mut Command,
    cancel: &AtomicBool,
    on_progress: &dyn Fn(String),
    limits: ProcessLimits,
) -> Result<ProcessOutput> {
    let mut child = command
        .spawn()
        .context("启动 Xop PVM2 transform-only 失败")?;
    let stdout = child.stdout.take().context("无法读取 Xop PVM2 标准输出")?;
    let stderr = child.stderr.take().context("无法读取 Xop PVM2 错误输出")?;
    let (sender, receiver) = mpsc::channel();
    let stdout_reader = spawn_output_reader(stdout, false, sender.clone());
    let stderr_reader = spawn_output_reader(stderr, true, sender);
    let started = Instant::now();
    let mut last_output = started;
    let mut stdout_text = String::new();
    let mut stderr_text = String::new();

    let status = loop {
        if cancel.load(Ordering::Relaxed) {
            terminate_child(&mut child);
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            anyhow::bail!("Xop PVM2 已取消");
        }
        if started.elapsed() >= limits.hard {
            terminate_child(&mut child);
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            anyhow::bail!(
                "Xop PVM2 处理超过 {} 分钟，已终止子进程",
                limits.hard.as_secs() / 60
            );
        }
        if last_output.elapsed() >= limits.idle {
            terminate_child(&mut child);
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            anyhow::bail!(
                "Xop PVM2 连续 {} 分钟没有进度，已终止子进程",
                limits.idle.as_secs() / 60
            );
        }
        if let Some(status) = child.try_wait().context("等待 Xop PVM2 子进程失败")? {
            break status;
        }
        match receiver.recv_timeout(PROCESS_POLL_INTERVAL) {
            Ok(line) => {
                last_output = Instant::now();
                consume_output_line(line, &mut stdout_text, &mut stderr_text, on_progress);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                thread::sleep(PROCESS_POLL_INTERVAL);
            }
        }
    };

    let _ = stdout_reader.join();
    let _ = stderr_reader.join();
    for line in receiver.try_iter() {
        consume_output_line(line, &mut stdout_text, &mut stderr_text, on_progress);
    }
    Ok(ProcessOutput {
        status,
        stdout: stdout_text,
        stderr: stderr_text,
    })
}

fn spawn_output_reader<R: Read + Send + 'static>(
    reader: R,
    stderr: bool,
    sender: mpsc::Sender<OutputLine>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut reader = BufReader::new(reader);
        let mut bytes = Vec::new();
        loop {
            bytes.clear();
            match reader.read_until(b'\n', &mut bytes) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let text = String::from_utf8_lossy(&bytes)
                        .trim_end_matches(['\r', '\n'])
                        .to_string();
                    if sender.send(OutputLine { stderr, text }).is_err() {
                        break;
                    }
                }
            }
        }
    })
}

fn consume_output_line(
    line: OutputLine,
    stdout: &mut String,
    stderr: &mut String,
    on_progress: &dyn Fn(String),
) {
    let destination = if line.stderr { stderr } else { stdout };
    destination.push_str(&line.text);
    destination.push('\n');
    if !line.stderr {
        if let Some(message) = pvm2_progress_message(&line.text) {
            on_progress(message);
        }
    }
}

fn terminate_child(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn pvm2_progress_message(line: &str) -> Option<String> {
    if !line.starts_with("PVM2_PROGRESS ") {
        return None;
    }
    let values = parse_key_values(line);
    let dex = values.get("dex")?.parse::<usize>().ok()?;
    let total = values.get("total")?.parse::<usize>().ok()?;
    let scanned = values.get("scanned")?.parse::<usize>().ok()?;
    let selected = values.get("selected")?.parse::<usize>().ok()?;
    let transformed = values.get("transformed")?.parse::<usize>().ok()?;
    let skipped = values.get("skipped")?.parse::<usize>().ok()?;
    let phase = match values.get("phase").map(String::as_str) {
        Some("rewrite") => "正在重写跳板",
        Some("complete") => "本 DEX 已完成",
        _ => "正在扫描",
    };
    Some(format!(
        "PVM2：DEX {dex}/{total}，{phase}；已扫描 {scanned} 个方法，选中 {selected}，成功 {transformed}，跳过 {skipped}"
    ))
}

fn parse_transform_report(stdout: &str, transformed: usize) -> Result<TransformReport> {
    let admission = stdout
        .lines()
        .find(|line| line.starts_with("PVM2 admission:"))
        .context("Xop Packer 未返回 PVM2 覆盖率，请更新内置 Packer")?;
    let reasons = stdout
        .lines()
        .find(|line| line.starts_with("PVM2 skip reasons:"))
        .context("Xop Packer 未返回 PVM2 回退原因")?;
    let morph = stdout
        .lines()
        .find(|line| line.starts_with("PVM2 morph:"))
        .context("Xop Packer 未返回 PVM2 ISA 信息")?;
    let unsupported = stdout
        .lines()
        .find(|line| line.starts_with("TRUE_VMP unsupported opcodes (count):"))
        .context("Xop Packer 未返回 PVM2 不支持指令统计")?;

    let admission = parse_key_values(admission);
    let candidates = required_usize(&admission, "candidates")?;
    let attempted = required_usize(&admission, "attempted")?;
    let reported_success = required_usize(&admission, "success")?;
    let fallback = required_usize(&admission, "fallback")?;
    if reported_success != transformed || attempted != reported_success + fallback {
        anyhow::bail!(
            "Xop PVM2 报告与 code.bin 不一致: success={reported_success}, payload={transformed}, fallback={fallback}"
        );
    }
    let success_rate = admission
        .get("rate")
        .and_then(|value| value.trim_end_matches('%').parse::<f64>().ok())
        .context("Xop PVM2 覆盖率格式无效")?;
    let isa = parse_key_values(morph)
        .get("isa")
        .and_then(|value| value.parse::<u8>().ok())
        .filter(|value| *value < 3)
        .context("Xop PVM2 ISA 编号无效")?;
    let skip_reasons = parse_key_values(reasons)
        .into_iter()
        .filter_map(|(key, value)| value.parse::<usize>().ok().map(|count| (key, count)))
        .collect();
    let unsupported_opcodes = parse_unsupported_opcodes(unsupported)?;

    Ok(TransformReport {
        transformed,
        candidates,
        attempted,
        fallback,
        success_rate,
        isa,
        skip_reasons,
        unsupported_opcodes,
    })
}

fn parse_unsupported_opcodes(line: &str) -> Result<BTreeMap<String, usize>> {
    let body = line
        .split_once('{')
        .and_then(|(_, value)| value.strip_suffix('}'))
        .context("PVM2 不支持指令统计格式无效")?
        .trim();
    if body.is_empty() {
        return Ok(BTreeMap::new());
    }
    body.split(',')
        .map(|entry| {
            let (opcode, count) = entry
                .trim()
                .split_once('=')
                .context("PVM2 不支持指令条目格式无效")?;
            let raw = opcode
                .strip_prefix("0x")
                .context("PVM2 不支持指令缺少 0x 前缀")?;
            u8::from_str_radix(raw, 16).context("PVM2 不支持指令编号无效")?;
            Ok((
                opcode.to_ascii_lowercase(),
                count.parse::<usize>().context("PVM2 不支持指令数量无效")?,
            ))
        })
        .collect()
}

fn parse_key_values(line: &str) -> BTreeMap<String, String> {
    line.split_whitespace()
        .filter_map(|token| {
            let (key, value) = token.split_once('=')?;
            Some((
                key.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                    .to_string(),
                value.trim_matches(',').to_string(),
            ))
        })
        .collect()
}

fn required_usize(values: &BTreeMap<String, String>, key: &str) -> Result<usize> {
    values
        .get(key)
        .and_then(|value| value.parse().ok())
        .with_context(|| format!("Xop PVM2 报告缺少 {key}"))
}

fn transform_failure_message(stdout: &str, stderr: &str) -> String {
    if stdout.contains("selected zero methods") || stderr.contains("selected zero methods") {
        return "Xop PVM2 已匹配到业务类，但没有可转换的方法。构造器和静态初始化器不会转换；含当前不支持的 invoke-custom/polymorphic 指令、超过寄存器/代码大小上限或异常处理表无法映射的方法会被跳过。请改选包含普通自有业务逻辑的类前缀，或查看 PVM2 覆盖率报告"
            .to_string();
    }

    let raw_detail = stderr
        .lines()
        .chain(stdout.lines())
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with("at "))
        .unwrap_or("Packer 未返回可识别的错误信息");
    let detail = raw_detail
        .strip_prefix("Exception in thread \"main\" ")
        .unwrap_or(raw_detail);
    let detail: String = detail.chars().take(500).collect();
    format!("Xop PVM2 transform-only 失败: {detail}")
}

fn resource_transform_failure_message(stdout: &str, stderr: &str) -> String {
    let raw_detail = stderr
        .lines()
        .chain(stdout.lines())
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with("at "))
        .unwrap_or("Packer 未返回可识别的错误信息");
    let detail = raw_detail
        .strip_prefix("Exception in thread \"main\" ")
        .unwrap_or(raw_detail);
    let detail: String = detail.chars().take(500).collect();
    format!("Xop 资源 transform-only 失败: {detail}")
}

fn validate_prefix(prefix: &str) -> Result<()> {
    if prefix.len() < 6
        || !prefix.starts_with('L')
        || !(prefix.ends_with('/') || prefix.ends_with(';'))
        || prefix.contains("..")
        || prefix.chars().any(char::is_whitespace)
    {
        anyhow::bail!(
            "无效的 Xop TRUE_VMP 类描述符前缀: {prefix}（示例 Lcom/example/pay/ 或 Lcom/example/Foo;）"
        );
    }
    Ok(())
}

fn package_name(manifest: &Path) -> Result<String> {
    let text = fs::read_to_string(manifest).context("读取 AndroidManifest.xml 包名失败")?;
    let manifest_start = text.find("<manifest").context("Manifest 缺少 <manifest>")?;
    let tag_end = text[manifest_start..]
        .find('>')
        .map(|offset| manifest_start + offset)
        .context("Manifest 起始标签未闭合")?;
    let tag = &text[manifest_start..=tag_end];
    for quote in ['"', '\''] {
        let needle = format!("package={quote}");
        if let Some(start) = tag.find(&needle) {
            let value_start = start + needle.len();
            if let Some(end) = tag[value_start..].find(quote) {
                let value = &tag[value_start..value_start + end];
                if !value.is_empty() {
                    return Ok(value.to_string());
                }
            }
        }
    }
    anyhow::bail!("Manifest 缺少 package，无法绑定 PVM2 变换")
}

pub(crate) fn validate_code_bin(data: &[u8]) -> Result<usize> {
    if data.len() < 8 {
        anyhow::bail!("Xop code.bin 过短");
    }
    let version = u16::from_le_bytes([data[0], data[1]]);
    if version != 4 {
        anyhow::bail!("Xop code.bin 版本不受支持: {version}");
    }
    let dex_count = u16::from_le_bytes([data[2], data[3]]) as usize;
    let header_end = 4usize
        .checked_add(dex_count.checked_mul(4).context("Xop dex_count 溢出")?)
        .context("Xop header 溢出")?;
    if dex_count == 0 || header_end > data.len() {
        anyhow::bail!("Xop code.bin 不含 PVM2 方法");
    }
    let mut total = 0usize;
    for slot in 0..dex_count {
        let base = 4 + slot * 4;
        let mut cursor = u32::from_le_bytes(data[base..base + 4].try_into().unwrap()) as usize;
        if !matches!(cursor.checked_add(6), Some(end) if end <= data.len()) {
            anyhow::bail!("Xop code.bin dex[{slot}] 越界");
        }
        cursor += 4; // dex_number
        let methods = u16::from_le_bytes(data[cursor..cursor + 2].try_into().unwrap()) as usize;
        cursor += 2;
        for _ in 0..methods {
            if !matches!(cursor.checked_add(16), Some(end) if end <= data.len()) {
                anyhow::bail!("Xop code.bin 方法头越界");
            }
            let encrypted_len =
                u32::from_le_bytes(data[cursor + 8..cursor + 12].try_into().unwrap()) as usize;
            let flags = u32::from_le_bytes(data[cursor + 12..cursor + 16].try_into().unwrap());
            if flags != 2 {
                anyhow::bail!("融合载荷只能包含 TRUE_VMP(PVM2)，检测到 flags={flags}");
            }
            cursor = cursor
                .checked_add(16)
                .and_then(|value| value.checked_add(encrypted_len))
                .context("Xop code.bin 方法长度溢出")?;
            if cursor > data.len() {
                anyhow::bail!("Xop code.bin 方法载荷越界");
            }
            total += 1;
        }
    }
    if total == 0 {
        anyhow::bail!("Xop code.bin 不含 PVM2 方法");
    }
    Ok(total)
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_true_vmp_only_code_bin() {
        let mut data = Vec::new();
        data.extend_from_slice(&4u16.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&8u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&7u32.to_le_bytes());
        data.extend_from_slice(&4u32.to_le_bytes());
        data.extend_from_slice(&28u32.to_le_bytes());
        data.extend_from_slice(&2u32.to_le_bytes());
        data.extend_from_slice(&[0u8; 28]);
        assert_eq!(validate_code_bin(&data).unwrap(), 1);
        data[26] = 1;
        assert!(validate_code_bin(&data).is_err());
    }

    #[test]
    fn validates_bounded_type_prefixes() {
        assert!(validate_prefix("Lcom/example/pay/").is_ok());
        assert!(validate_prefix("Lcom/example/Foo;").is_ok());
        assert!(validate_prefix("L").is_err());
        assert!(validate_prefix("com/example/").is_err());
        assert!(validate_prefix("Lcom/../").is_err());
    }

    #[test]
    fn zero_method_failure_is_actionable_and_does_not_expose_java_stack() {
        let message = transform_failure_message(
            "PVM2 admission: candidates=3 attempted=3 success=0 fallback=3 rate=0.0%",
            "java.lang.IllegalStateException: pvm2-transform selected zero methods; provide a matching --true-vmp-prefix\n\tat com.example.Packer.main(Packer.java:1)",
        );
        assert!(message.contains("没有可转换的方法"));
        assert!(message.contains("覆盖率报告"));
        assert!(!message.contains("java.lang"));
        assert!(!message.contains("Packer.java"));
    }

    #[test]
    fn parses_coverage_and_morph_report() {
        let report = parse_transform_report(
            "PVM2 admission: candidates=16 attempted=16 success=13 fallback=3 rate=81.3%\n\
             PVM2 skip reasons: unsupported_opcode=1 too_many_regs=2 try_catch=0 branch=0 type=0 other=0\n\
             TRUE_VMP unsupported opcodes (count): {0xfc=1}\n\
             PVM2 morph: isa=2\n",
            13,
        )
        .unwrap();
        assert_eq!(report.transformed, 13);
        assert_eq!(report.candidates, 16);
        assert_eq!(report.fallback, 3);
        assert_eq!(report.isa, 2);
        assert_eq!(report.skip_reasons["too_many_regs"], 2);
        assert_eq!(report.unsupported_opcodes["0xfc"], 1);
        assert!((report.success_rate - 81.3).abs() < f64::EPSILON);
    }

    #[test]
    fn parses_empty_unsupported_opcode_report() {
        assert!(
            parse_unsupported_opcodes("TRUE_VMP unsupported opcodes (count): {}")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn parses_streamed_pvm2_progress_for_gui() {
        let message = pvm2_progress_message(
            "PVM2_PROGRESS phase=rewrite dex=4 total=8 scanned=12345 selected=320 transformed=300 skipped=20",
        )
        .unwrap();
        assert!(message.contains("DEX 4/8"));
        assert!(message.contains("已扫描 12345"));
        assert!(message.contains("成功 300"));
        assert!(message.contains("跳过 20"));
        assert!(pvm2_progress_message("普通日志").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn streamed_pvm2_process_honors_cancellation() {
        let cancel = std::sync::Arc::new(AtomicBool::new(false));
        let trigger = std::sync::Arc::clone(&cancel);
        let setter = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            trigger.store(true, Ordering::Relaxed);
        });
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "exec sleep 10"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let started = Instant::now();
        let error = run_pvm2_command(
            &mut command,
            cancel.as_ref(),
            &|_| {},
            ProcessLimits {
                idle: Duration::from_secs(5),
                hard: Duration::from_secs(5),
            },
        )
        .err()
        .unwrap();
        setter.join().unwrap();
        assert!(error.to_string().contains("已取消"));
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[cfg(unix)]
    #[test]
    fn streamed_pvm2_process_enforces_idle_timeout() {
        let cancel = AtomicBool::new(false);
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "exec sleep 10"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let error = run_pvm2_command(
            &mut command,
            &cancel,
            &|_| {},
            ProcessLimits {
                idle: Duration::from_millis(150),
                hard: Duration::from_secs(5),
            },
        )
        .err()
        .unwrap();
        assert!(error.to_string().contains("没有进度"));
    }

    #[test]
    fn parses_native_so_protection_report() {
        let report = parse_native_so_report(
            "NATIVE_SO_TRANSFORM_OK encrypted_files=4 encrypted_basenames=1 skipped=3 skipped_policy=1 skipped_reloc=1 skipped_budget=1 function_regions=12\n",
        )
        .unwrap();
        assert_eq!(report.encrypted_files, 4);
        assert_eq!(report.encrypted_basenames, 1);
        assert_eq!(report.skipped, 3);
        assert_eq!(report.skipped_policy, 1);
        assert_eq!(report.skipped_reloc, 1);
        assert_eq!(report.skipped_budget, 1);
        assert_eq!(report.function_regions, 12);
        assert!(parse_native_so_report("NATIVE_SO_TRANSFORM_OK encrypted_files=1").is_err());
    }

    #[test]
    fn resource_mapping_rejects_escape_and_duplicate_targets() {
        let valid = NamedTempFile::new().unwrap();
        fs::write(valid.path(), "res/drawable/logo.png\tr/a/a.png\n").unwrap();
        assert_eq!(parse_resource_mapping(valid.path()).unwrap().len(), 1);

        let escaped = NamedTempFile::new().unwrap();
        fs::write(escaped.path(), "res/drawable/logo.png\tr/../logo.png\n").unwrap();
        assert!(parse_resource_mapping(escaped.path()).is_err());

        let duplicate = NamedTempFile::new().unwrap();
        fs::write(
            duplicate.path(),
            "res/drawable/a.png\tr/a/a.png\nres/drawable/b.png\tr/a/a.png\n",
        )
        .unwrap();
        assert!(parse_resource_mapping(duplicate.path()).is_err());
    }

    #[test]
    fn empty_resource_id_mapping_is_a_valid_compatibility_noop() {
        let mapping = NamedTempFile::new().unwrap();
        assert_eq!(validate_resource_id_mapping(mapping.path()).unwrap(), 0);
    }
}
