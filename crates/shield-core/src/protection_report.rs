//! 方法级验收记录。报告只包含标识和摘要，不包含密钥或明文镜像。
use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct MethodRecord {
    module: String,
    descriptor: String,
    required: bool,
    input_instruction_bytes: u64,
    input_dex: String,
    transform_status: String,
    reason: Option<String>,
    artifact_verified: bool,
    plaintext_policy: Option<String>,
    final_dex_index: Option<u32>,
    final_method_index: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct DexRecord {
    pub module: String,
    input_sha256: String,
    output_sha256: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct MethodReport {
    schema_version: u32,
    image_version: u32,
    code_version: u32,
    methods: Vec<MethodRecord>,
    pub dexes: BTreeMap<String, DexRecord>,
    code_sha256: String,
    #[serde(default)]
    pub build: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    pub metrics: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    pub artifact_dexes: BTreeMap<String, String>,
    #[serde(default)]
    pub output_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub native_vmp: Vec<crate::native_vmp::NativeRecord>,
}

/// 仅允许固定分类和数量进入可分享摘要，原始原因只保存在本地逐方法报告。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Pvm2SkipReason {
    NoCode,
    Initializer,
    UiRuntimeGlue,
    DataResourceRuntimeGlue,
    CompilerGeneratedBridge,
    PlaybackCompatibility,
    CompatibilityVirtualContract,
    CompatibilitySynchronization,
    CompatibilityExceptionRegion,
    CompatibilityNonLeafInstruction,
    NullableReceiver,
    UnsupportedOpcode,
    RegisterLimit,
    CodeSizeLimit,
    ExceptionMapping,
    ControlFlow,
    Type,
    NotAttempted,
    Other,
}

impl Pvm2SkipReason {
    fn classify(reason: &str) -> Self {
        if let Some((scope, restriction)) = reason.split_once(':') {
            if matches!(
                scope,
                "ui_runtime_glue"
                    | "data_resource_runtime_glue"
                    | "playback_compatibility"
                    | "compiler_generated_bridge"
            ) {
                return match restriction {
                    "virtual_contract" => Self::CompatibilityVirtualContract,
                    "synchronization" => Self::CompatibilitySynchronization,
                    "exception_region" => Self::CompatibilityExceptionRegion,
                    "non_leaf_instruction" => Self::CompatibilityNonLeafInstruction,
                    _ => Self::Other,
                };
            }
        }
        match reason {
            "no_code" => Self::NoCode,
            "initializer" => Self::Initializer,
            "ui_runtime_glue" => Self::UiRuntimeGlue,
            "data_resource_runtime_glue" => Self::DataResourceRuntimeGlue,
            "compiler_generated_bridge" => Self::CompilerGeneratedBridge,
            "playback_compatibility" => Self::PlaybackCompatibility,
            "not_attempted" => Self::NotAttempted,
            "too large" => Self::CodeSizeLimit,
            r if r.contains("unsupported opcode 0x") => Self::UnsupportedOpcode,
            r if r.contains("too many regs") => Self::RegisterLimit,
            r if r.contains("nullable receiver") || r.contains("receiver register") => {
                Self::NullableReceiver
            }
            r if r.contains("branch") => Self::ControlFlow,
            r if r.contains("try ") || r.contains("tries") || r.contains("handler") => {
                Self::ExceptionMapping
            }
            r if r.contains("unsupported return") || r.contains("argument type") => Self::Type,
            _ => Self::Other,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::NoCode => "无 DEX 方法体（Native/抽象方法）",
            Self::Initializer => "构造器/静态初始化器",
            Self::UiRuntimeGlue => "界面范围兼容规则（未细分）",
            Self::DataResourceRuntimeGlue => "数据/资源框架兼容规则",
            Self::CompilerGeneratedBridge => "编译器生成桥接/合成方法",
            Self::PlaybackCompatibility => "媒体/辅助类兼容规则",
            Self::CompatibilityVirtualContract => "兼容范围：特殊对象方法或虚方法契约未验证",
            Self::CompatibilitySynchronization => "兼容范围：同步方法",
            Self::CompatibilityExceptionRegion => "兼容范围：含异常处理区",
            Self::CompatibilityNonLeafInstruction => "兼容范围：含叶子方法白名单之外的指令",
            Self::NullableReceiver => "接收者非空语义无法证明",
            Self::UnsupportedOpcode => "不支持的指令",
            Self::RegisterLimit => "寄存器超限",
            Self::CodeSizeLimit => "方法大小超限",
            Self::ExceptionMapping => "异常处理映射不支持",
            Self::ControlFlow => "控制流不支持",
            Self::Type => "类型不支持",
            Self::NotAttempted => "未进入转换",
            Self::Other => "其他原因（详见本地报告）",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pvm2FailureSummary {
    /// 逐方法清单涉及的类，不计没有任何方法的空类。
    pub selected_classes: usize,
    pub selected_methods: usize,
    pub reasons: BTreeMap<Pvm2SkipReason, usize>,
}

#[derive(Debug)]
pub struct Pvm2Failure {
    pub summary: Pvm2FailureSummary,
    report: MethodReport,
    report_path: Option<PathBuf>,
    report_save_failed: bool,
}

impl Pvm2Failure {
    pub(crate) fn zero_methods(path: &Path) -> Result<Self> {
        ensure!(
            fs::metadata(path)?.len() <= 64 * 1024 * 1024,
            "方法失败报告超过 64 MiB 限制"
        );
        let report = MethodReport::read(path)?;
        ensure!(
            report.schema_version == 2
                && report.code_version == 4
                && matches!(report.image_version, 7..=9),
            "方法失败报告协议无效"
        );
        let mut classes = BTreeSet::new();
        let mut methods = BTreeSet::new();
        let mut reasons = BTreeMap::new();
        for row in &report.methods {
            ensure!(
                valid_signature(&row.descriptor) && methods.insert((&row.module, &row.descriptor)),
                "方法失败报告包含无效或重复方法"
            );
            ensure!(
                row.transform_status == "skipped"
                    && !row.artifact_verified
                    && row.final_method_index.is_none()
                    && row.final_dex_index.is_none(),
                "零转换失败报告包含成功转换记录"
            );
            ensure!(
                report
                    .dexes
                    .get(&row.input_dex)
                    .is_some_and(|dex| dex.module == row.module),
                "方法失败报告模块映射不一致"
            );
            let reason = row
                .reason
                .as_deref()
                .filter(|r| !r.is_empty())
                .context("方法失败报告缺少跳过原因")?;
            classes.insert((&row.module, row.descriptor.split_once("->").unwrap().0));
            *reasons.entry(Pvm2SkipReason::classify(reason)).or_insert(0) += 1;
        }
        let summary = Pvm2FailureSummary {
            selected_classes: classes.len(),
            selected_methods: methods.len(),
            reasons,
        };
        Ok(Self {
            summary,
            report,
            report_path: None,
            report_save_failed: false,
        })
    }

    /// APK/AAB 外层知道最终输出目录；在临时工作目录销毁前分别保留失败报告。
    pub fn preserve(error: &mut crate::ShieldError, artifact: &Path) {
        let crate::ShieldError::Other(source) = error else {
            return;
        };
        let Some(failure) = source.downcast_mut::<Self>() else {
            return;
        };
        failure.report_path = None;
        match failure.save_report(artifact) {
            Ok(path) => {
                failure.report_path = Some(path);
                failure.report_save_failed = false;
            }
            Err(_) => failure.report_save_failed = true,
        }
    }

    fn save_report(&mut self, artifact: &Path) -> Result<PathBuf> {
        let parent = artifact
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        self.report.build.insert("status".into(), "failed".into());
        self.report
            .build
            .insert("failure_code".into(), "PVM2_ZERO_METHODS".into());
        self.report.build.insert(
            "failure_summary".into(),
            serde_json::to_value(&self.summary)?,
        );
        // 每次失败独立留存，不覆盖之前的成功报告或失败证据；临时文件默认仅本机用户可读。
        let mut file = tempfile::Builder::new()
            .prefix("pvm2-failure-")
            .suffix(".json")
            .tempfile_in(parent)?;
        serde_json::to_writer_pretty(&mut file, &self.report)?;
        let (_, path) = file.keep()?;
        Ok(path)
    }
}

impl std::fmt::Display for Pvm2Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PVM2_ZERO_METHODS：没有可转换的方法。逐方法清单涉及 {} 个类、{} 个方法，成功转换 0。",
            self.summary.selected_classes, self.summary.selected_methods
        )?;
        for (reason, count) in &self.summary.reasons {
            write!(f, "\n{}：{}", reason.label(), count)?;
        }
        if self.summary.selected_methods == 0 {
            write!(
                f,
                "\n所选范围没有方法记录，请核对 APK 中的实际类名及选择范围。"
            )?;
        } else if self
            .summary
            .reasons
            .keys()
            .all(|r| matches!(r, Pvm2SkipReason::NoCode | Pvm2SkipReason::Initializer))
        {
            write!(f, "\n所选范围只有无 DEX 方法体或初始化方法，请选择含普通 DEX 方法体的业务范围；SO 内部函数需另走 Native 保护链路。")?;
        } else {
            if self.summary.reasons.keys().any(|r| {
                matches!(
                    r,
                    Pvm2SkipReason::UiRuntimeGlue
                        | Pvm2SkipReason::DataResourceRuntimeGlue
                        | Pvm2SkipReason::CompilerGeneratedBridge
                        | Pvm2SkipReason::PlaybackCompatibility
                        | Pvm2SkipReason::CompatibilityVirtualContract
                        | Pvm2SkipReason::CompatibilitySynchronization
                        | Pvm2SkipReason::CompatibilityExceptionRegion
                        | Pvm2SkipReason::CompatibilityNonLeafInstruction
                )
            }) {
                write!(f, "\n兼容分类表示当前准入限制，不代表这些方法都是生命周期回调。仅修改类前缀或降低保护级别不能证明这些方法已获 PVM2 保护；请核对逐方法报告中的剩余语义限制，使用配套打包器重新加固并核验覆盖。")?;
            }
            if self.summary.reasons.keys().any(|r| {
                matches!(
                    r,
                    Pvm2SkipReason::NullableReceiver
                        | Pvm2SkipReason::UnsupportedOpcode
                        | Pvm2SkipReason::RegisterLimit
                        | Pvm2SkipReason::CodeSizeLimit
                        | Pvm2SkipReason::ExceptionMapping
                        | Pvm2SkipReason::ControlFlow
                        | Pvm2SkipReason::Type
                        | Pvm2SkipReason::NotAttempted
                        | Pvm2SkipReason::Other
                )
            }) {
                write!(f, "\n存在转换能力或语义检查限制，请携带原因统计反馈，不能仅靠修改类前缀认定已解决。")?;
            }
        }
        if let Some(path) = &self.report_path {
            write!(
                f,
                "\n本地逐方法失败报告（含业务标识，请勿直接公开）：{}",
                path.display()
            )?;
        } else if self.report_save_failed {
            write!(
                f,
                "\n逐方法报告保存失败，请检查输出目录权限或磁盘空间；上述原因统计仍可复制。"
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for Pvm2Failure {}

pub(crate) fn sha256(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

pub(crate) fn file_sha256(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

/// 自动报告位置；保留 APK/AAB 扩展名，避免同名产物互相覆盖。
pub fn report_path(artifact: &Path) -> PathBuf {
    let mut name = artifact.as_os_str().to_owned();
    name.push(".protection.json");
    PathBuf::from(name)
}

pub(crate) fn required_methods(path: Option<&Path>) -> Result<BTreeSet<String>> {
    let Some(path) = path else {
        return Ok(BTreeSet::new());
    };
    let text = fs::read_to_string(path).context("读取关键方法清单失败（需要 UTF-8）")?;
    let mut required = BTreeSet::new();
    for (line, value) in text.lines().enumerate() {
        let value = value.trim();
        if value.is_empty() || value.starts_with('#') {
            continue;
        }
        let (module, signature) = value
            .split_once('\t')
            .with_context(|| format!("关键方法清单第 {} 行缺少制表符", line + 1))?;
        ensure!(
            !module.is_empty()
                && module
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
            "关键方法模块名无效：{module}"
        );
        ensure!(
            valid_signature(signature),
            "关键方法描述符无效：{signature}"
        );
        ensure!(required.insert(value.to_owned()), "关键方法重复：{value}");
    }
    ensure!(!required.is_empty(), "关键方法清单为空");
    Ok(required)
}

fn valid_signature(signature: &str) -> bool {
    fn take_type(s: &str, allow_void: bool) -> Option<&str> {
        let scalar = s.trim_start_matches('[');
        let dimensions = s.len() - scalar.len();
        if dimensions > 255 {
            return None;
        }
        match scalar.as_bytes().first()? {
            b'V' if allow_void && dimensions == 0 => Some(&scalar[1..]),
            b'Z' | b'B' | b'S' | b'C' | b'I' | b'J' | b'F' | b'D' => Some(&scalar[1..]),
            b'L' => {
                let end = scalar.find(';')?;
                let name = &scalar[1..end];
                if name.is_empty()
                    || name.split('/').any(str::is_empty)
                    || name
                        .chars()
                        .any(|c| c.is_whitespace() || ".;[()\t".contains(c))
                {
                    return None;
                }
                Some(&scalar[end + 1..])
            }
            _ => None,
        }
    }
    let Some((owner, method)) = signature.split_once("->") else {
        return false;
    };
    if !owner.starts_with('L') || take_type(owner, false) != Some("") {
        return false;
    }
    let Some((name, mut rest)) = method.split_once('(') else {
        return false;
    };
    if name.is_empty()
        || name
            .chars()
            .any(|c| c.is_whitespace() || ".;/[()]".contains(c))
    {
        return false;
    }
    while !rest.starts_with(')') {
        let Some(tail) = take_type(rest, false) else {
            return false;
        };
        rest = tail;
    }
    take_type(&rest[1..], true) == Some("")
}

impl MethodReport {
    pub(crate) fn native_only() -> Self {
        // 未使用 PVM2 时版本为 0；不借 Native 记录虚构方法转换结果。
        Self {
            schema_version: 2,
            ..Self::default()
        }
    }
    pub(crate) fn read(path: &Path) -> Result<Self> {
        serde_json::from_slice(&fs::read(path).context("打包器未生成方法报告，请重建打包器")?)
            .context("方法报告格式无效")
    }

    pub(crate) fn validate(
        &mut self,
        dex_dir: &Path,
        code: &[u8],
        modules: &BTreeMap<String, String>,
        required: &BTreeSet<String>,
        transformed: usize,
        input_hashes: &BTreeMap<String, String>,
    ) -> Result<()> {
        ensure!(
            self.schema_version == 2
                && self.code_version == 4
                && matches!(self.image_version, 7..=9),
            "方法报告协议版本不受支持"
        );
        ensure!(
            self.code_sha256 == sha256(code),
            "方法报告与 code.bin 不一致"
        );
        let mut seen = BTreeSet::new();
        let mut indices = BTreeSet::new();
        let mut declared = BTreeSet::new();
        let mut verified = 0usize;
        let mut input_bytes = 0u64;
        let mut protected_bytes = 0u64;
        for (name, dex) in &self.dexes {
            ensure!(
                modules.get(name) == Some(&dex.module),
                "方法报告的模块映射不一致：{name}"
            );
            ensure!(
                input_hashes.get(name) == Some(&dex.input_sha256),
                "报告与输入 DEX 摘要不一致：{name}"
            );
            ensure!(
                dex.output_sha256 == file_sha256(&dex_dir.join(name))?,
                "报告的 DEX 摘要不一致：{name}"
            );
        }
        ensure!(self.dexes.len() == modules.len(), "方法报告缺少 DEX");
        for row in &self.methods {
            let id = format!("{}\t{}", row.module, row.descriptor);
            ensure!(
                valid_signature(&row.descriptor) && seen.insert(id.clone()),
                "方法描述符无效或重复：{id}"
            );
            ensure!(
                modules.get(&row.input_dex) == Some(&row.module),
                "方法的模块/DEX 对应关系错误：{id}"
            );
            ensure!(
                row.required == required.contains(&id),
                "报告更改了关键方法标记：{id}"
            );
            if row.required {
                declared.insert(id.clone());
            }
            input_bytes = input_bytes
                .checked_add(row.input_instruction_bytes)
                .context("指令字节数溢出")?;
            match row.transform_status.as_str() {
                "transformed" => {
                    let dex_index = if row.input_dex == "classes.dex" {
                        Some(0)
                    } else {
                        row.input_dex
                            .strip_prefix("classes")
                            .and_then(|s| s.strip_suffix(".dex"))
                            .and_then(|n| n.parse::<u32>().ok())
                            .and_then(|n| n.checked_sub(1))
                    };
                    ensure!(
                        dex_index.is_some()
                            && row.artifact_verified
                            && row.plaintext_policy.as_deref()
                                == Some(if row.required {
                                    "clear_after_use"
                                } else {
                                    "bounded_cache"
                                })
                            && row.reason.is_none()
                            && row.final_dex_index == dex_index
                            && row.final_method_index.is_some(),
                        "方法未通过产物验证：{id}"
                    );
                    ensure!(
                        indices.insert((
                            row.final_dex_index.unwrap(),
                            row.final_method_index.unwrap()
                        )),
                        "产物方法索引重复"
                    );
                    verified += 1;
                    protected_bytes = protected_bytes
                        .checked_add(row.input_instruction_bytes)
                        .context("指令字节数溢出")?;
                }
                "skipped" => ensure!(
                    !row.artifact_verified
                        && row.plaintext_policy.is_none()
                        && !row.required
                        && row.reason.as_ref().is_some_and(|r| !r.is_empty())
                        && row.final_method_index.is_none()
                        && row.final_dex_index.is_none(),
                    "关键方法未转换或跳过记录无效：{id}"
                ),
                _ => bail!("未知方法转换状态：{id}"),
            }
        }
        ensure!(declared == *required, "方法报告遗漏了关键方法");
        ensure!(
            indices == crate::protect::xop_pvm2::code_bin_indices(code)?,
            "方法报告与 code.bin 索引不一致"
        );
        ensure!(verified == transformed, "方法报告与转换数量不一致");
        self.metrics
            .insert("selected_methods".into(), self.methods.len().into());
        self.metrics
            .insert("verified_methods".into(), verified.into());
        self.metrics
            .insert("selected_instruction_bytes".into(), input_bytes.into());
        self.metrics
            .insert("protected_instruction_bytes".into(), protected_bytes.into());
        self.metrics.insert(
            "method_coverage_percent".into(),
            ratio(verified as u64, self.methods.len() as u64),
        );
        self.metrics.insert(
            "instruction_coverage_percent".into(),
            ratio(protected_bytes, input_bytes),
        );
        self.metrics
            .insert("required_methods".into(), required.len().into());
        self.metrics.insert(
            "required_coverage_percent".into(),
            ratio(required.len() as u64, required.len() as u64),
        );
        Ok(())
    }

    pub(crate) fn write(&self, path: &Path) -> Result<()> {
        let mut file = tempfile::NamedTempFile::new_in(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?;
        serde_json::to_writer_pretty(&mut file, self)?;
        file.persist(path).map_err(|e| e.error)?;
        Ok(())
    }

    pub(crate) fn bind(&mut self, artifact: &Path, aab: bool) -> Result<()> {
        crate::native_vmp::verify_packaged(&self.native_vmp, artifact, aab)?;
        let actual = archive_dexes(artifact)?;
        let expected = self
            .artifact_dexes
            .iter()
            .filter_map(|(name, hash)| {
                if aab {
                    Some((name.clone(), hash.clone()))
                } else {
                    name.strip_prefix("base/dex/")
                        .or_else(|| name.strip_prefix("base/"))
                        .map(|name| (name.to_owned(), hash.clone()))
                }
            })
            .collect::<BTreeMap<_, _>>();
        ensure!(
            !expected.is_empty() && actual == expected,
            "最终安装包 DEX 与验证产物不一致（缺失、重复、被修改或多出未验证的 DEX）"
        );
        self.output_sha256 = Some(file_sha256(artifact)?);
        self.build
            .insert("output_kind".into(), if aab { "aab" } else { "apk" }.into());
        Ok(())
    }
}

fn ratio(n: u64, d: u64) -> serde_json::Value {
    if d == 0 {
        serde_json::Value::Null
    } else {
        (100.0 * n as f64 / d as f64).into()
    }
}

fn archive_dexes(path: &Path) -> Result<BTreeMap<String, String>> {
    let mut archive = checked_archive(path)?;
    let mut values = BTreeMap::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        if !entry.name().ends_with(".dex") {
            continue;
        }
        let name = entry.name().to_owned();
        let mut hasher = Sha256::new();
        std::io::copy(&mut entry, &mut hasher)?;
        ensure!(
            values
                .insert(name, format!("{:x}", hasher.finalize()))
                .is_none(),
            "产物包含重复 DEX 条目"
        );
    }
    Ok(values)
}

/// zip 2.x 会按名称覆盖重复中央目录记录，必须在其去重后的视图之外核验条目数。
pub fn checked_archive(path: &Path) -> Result<zip::ZipArchive<File>> {
    let archive = zip::ZipArchive::new(File::open(path)?)?;
    let mut raw = File::open(path)?;
    let length = raw.metadata()?.len();
    raw.seek(SeekFrom::Start(archive.central_directory_start()))?;
    let mut count = 0;
    loop {
        let mut signature = [0u8; 4];
        raw.read_exact(&mut signature)?;
        if signature != *b"PK\x01\x02" {
            break;
        }
        let mut header = [0u8; 42];
        raw.read_exact(&mut header)?;
        let variable: u64 = [24, 26, 28]
            .into_iter()
            .map(|at| u16::from_le_bytes([header[at], header[at + 1]]) as u64)
            .sum();
        let end = raw
            .stream_position()?
            .checked_add(variable)
            .context("ZIP 中央目录溢出")?;
        ensure!(end <= length, "ZIP 中央目录越界");
        raw.seek(SeekFrom::Start(end))?;
        count += 1;
        ensure!(count <= archive.len(), "安装包包含重复 ZIP 条目");
    }
    ensure!(count == archive.len(), "ZIP 中央目录条目数量不一致");
    Ok(archive)
}

/// 签名/模块重组后重新比对 DEX，再绑定最终文件摘要；不能仅替换报告中的摘要。
pub fn rebind_report(
    source_artifact: &Path,
    final_artifact: &Path,
    output_report: &Path,
    aab: bool,
    original_input: Option<&Path>,
) -> Result<()> {
    let source = report_path(source_artifact);
    let mut report = MethodReport::read(&source)?;
    ensure!(
        report.output_sha256.as_deref() == Some(&file_sha256(source_artifact)?),
        "源安装包与方法报告的摘要不一致"
    );
    report.bind(final_artifact, aab)?;
    if let Some(input) = original_input {
        report
            .build
            .insert("bundle_input_sha256".into(), file_sha256(input)?.into());
    }
    report.write(output_report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn archive(path: &Path, entries: &[(&str, &[u8])]) {
        let mut zip = zip::ZipWriter::new(File::create(path).unwrap());
        for (name, value) in entries {
            zip.start_file(*name, zip::write::SimpleFileOptions::default())
                .unwrap();
            zip.write_all(value).unwrap();
        }
        zip.finish().unwrap();
    }

    fn report() -> MethodReport {
        serde_json::from_value(serde_json::json!({
            "schema_version": 2, "image_version": 7, "code_version": 4,
            "methods": [], "dexes": {}, "code_sha256": "",
            "artifact_dexes": {"base/dex/classes.dex": sha256(b"stub"), "feature/dex/classes.dex": sha256(b"feature")}
        })).unwrap()
    }

    #[test]
    fn 零转换报告分类脱敏并在临时目录销毁后保留到实际输出目录() {
        let temporary = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        let path = temporary.path().join("methods.json");
        let mut detail = report();
        detail.dexes.insert(
            "classes.dex".into(),
            DexRecord {
                module: "base".into(),
                input_sha256: "input".into(),
                output_sha256: "output".into(),
            },
        );
        let cases = [
            ("no_code", Pvm2SkipReason::NoCode),
            ("initializer", Pvm2SkipReason::Initializer),
            (
                "ui_runtime_glue:virtual_contract",
                Pvm2SkipReason::CompatibilityVirtualContract,
            ),
            (
                "data_resource_runtime_glue:synchronization",
                Pvm2SkipReason::CompatibilitySynchronization,
            ),
            (
                "playback_compatibility:exception_region",
                Pvm2SkipReason::CompatibilityExceptionRegion,
            ),
            (
                "ui_runtime_glue:non_leaf_instruction",
                Pvm2SkipReason::CompatibilityNonLeafInstruction,
            ),
            ("ui_runtime_glue", Pvm2SkipReason::UiRuntimeGlue),
            (
                "data_resource_runtime_glue",
                Pvm2SkipReason::DataResourceRuntimeGlue,
            ),
            (
                "compiler_generated_bridge",
                Pvm2SkipReason::CompilerGeneratedBridge,
            ),
            (
                "playback_compatibility",
                Pvm2SkipReason::PlaybackCompatibility,
            ),
            (
                "nullable receiver at register 3",
                Pvm2SkipReason::NullableReceiver,
            ),
            ("unsupported opcode 0xfc", Pvm2SkipReason::UnsupportedOpcode),
            ("too many regs", Pvm2SkipReason::RegisterLimit),
            ("too large", Pvm2SkipReason::CodeSizeLimit),
            ("handler cannot map", Pvm2SkipReason::ExceptionMapping),
            ("bad branch target", Pvm2SkipReason::ControlFlow),
            ("unsupported return Lprivate/Secret;", Pvm2SkipReason::Type),
            ("not_attempted", Pvm2SkipReason::NotAttempted),
            (
                "private-customer /Users/private/project password=secret",
                Pvm2SkipReason::Other,
            ),
        ];
        for (i, (reason, _)) in cases.iter().enumerate() {
            detail.methods.push(serde_json::from_value(serde_json::json!({
                "module": "base", "descriptor": format!("Lprivate/Secret;->method{i}()V"), "required": false,
                "input_instruction_bytes": 0, "input_dex": "classes.dex", "transform_status": "skipped",
                "reason": reason, "artifact_verified": false, "plaintext_policy": null
            })).unwrap());
        }
        for image in [7, 8, 9, 10] {
            detail.image_version = image;
            detail.write(&path).unwrap();
            assert_eq!(Pvm2Failure::zero_methods(&path).is_ok(), image <= 9);
        }
        detail.image_version = 9;
        detail.write(&path).unwrap();
        let failure = Pvm2Failure::zero_methods(&path).unwrap();
        assert_eq!(failure.summary.selected_classes, 1);
        assert_eq!(failure.summary.selected_methods, cases.len());
        for (_, reason) in cases {
            assert_eq!(failure.summary.reasons[&reason], 1);
        }
        let safe = serde_json::to_string(&failure.summary).unwrap();
        for secret in ["private", "Secret", "method0", "password", "/Users/"] {
            assert!(!safe.contains(secret));
        }
        assert!(!failure.to_string().contains("private"));
        let mut error = crate::ShieldError::from(anyhow::Error::new(failure));
        Pvm2Failure::preserve(&mut error, &temporary.path().join("intermediate.apk"));
        // AAB 复用 APK 核心时，必须重新保存到最终输出目录，不能留下将被删除的临时路径。
        Pvm2Failure::preserve(&mut error, &output.path().join("final.aab"));
        drop(temporary);
        let crate::ShieldError::Other(source) = &error else {
            panic!()
        };
        let failure = source.downcast_ref::<Pvm2Failure>().unwrap();
        let saved = failure.report_path.clone().unwrap();
        assert!(saved.is_file() && saved.starts_with(output.path()));
        let stored: serde_json::Value = serde_json::from_slice(&fs::read(&saved).unwrap()).unwrap();
        assert_eq!(stored["build"]["status"], "failed");
        assert_eq!(stored["build"]["failure_code"], "PVM2_ZERO_METHODS");
        assert_eq!(stored["methods"].as_array().unwrap().len(), cases.len());
        assert!(!output.path().join("final.aab").exists());
        assert!(!report_path(&output.path().join("final.aab")).exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&saved).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        Pvm2Failure::preserve(&mut error, &output.path().join("final.aab"));
        assert!(saved.is_file());
        Pvm2Failure::preserve(&mut error, &output.path().join("missing/final.aab"));
        assert!(error.to_string().contains("报告保存失败"));
        assert!(error.to_string().contains("成功转换 0"));
    }

    #[test]
    fn 零转换诊断拒绝缺失损坏或夹带成功记录的报告() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("methods.json");
        assert!(Pvm2Failure::zero_methods(&path).is_err());
        fs::write(&path, b"broken").unwrap();
        assert!(Pvm2Failure::zero_methods(&path).is_err());
        let mut detail = report();
        detail.write(&path).unwrap();
        assert!(Pvm2Failure::zero_methods(&path)
            .unwrap()
            .to_string()
            .contains("没有方法记录"));
        detail.methods.push(serde_json::from_value(serde_json::json!({
            "module": "base", "descriptor": "La/A;->value()I", "required": false, "input_instruction_bytes": 6,
            "input_dex": "classes.dex", "transform_status": "transformed", "reason": null,
            "artifact_verified": true, "plaintext_policy": "bounded_cache", "final_dex_index": 0, "final_method_index": 0
        })).unwrap());
        detail.write(&path).unwrap();
        assert!(Pvm2Failure::zero_methods(&path).is_err());
    }

    #[test]
    fn 清单严格区分模块重载并拒绝无效描述符() {
        let dir = tempfile::tempdir().unwrap();
        let list = dir.path().join("methods.tsv");
        fs::write(
            &list,
            "# 示例\nbase\tLa/A;->f(I[Ljava/lang/String;)Z\nfeature\tLa/A;->f()J\n",
        )
        .unwrap();
        assert_eq!(required_methods(Some(&list)).unwrap().len(), 2);
        for text in [
            "",
            "base La/A;->f()V",
            "../base\tLa/A;->f()V",
            "base\tLa/A;->f(V)V",
            "base\tLa/A;->f()[V",
            "base\tLa/A;->f()Vjunk",
            "base\tLa/A;->f()V\nbase\tLa/A;->f()V",
        ] {
            fs::write(&list, text).unwrap();
            assert!(required_methods(Some(&list)).is_err(), "{text}");
        }
        assert!(valid_signature("La/外部$Name;->f([[IJD)Ljava/lang/Object;"));
        assert!(ratio(0, 0).is_null());
    }

    #[test]
    fn 签名重组后重新核验全部_dex并拒绝错模块或备份() {
        let dir = tempfile::tempdir().unwrap();
        let apk = dir.path().join("input.apk");
        let aab = dir.path().join("output.aab");
        archive(
            &apk,
            &[
                ("classes.dex", b"stub"),
                ("META-INF/input.SF", b"signature"),
            ],
        );
        let mut report = report();
        report.bind(&apk, false).unwrap();
        report.write(&report_path(&apk)).unwrap();
        archive(
            &aab,
            &[
                ("base/dex/classes.dex", b"stub"),
                ("feature/dex/classes.dex", b"feature"),
                ("META-INF/output.SF", b"new signature"),
            ],
        );
        rebind_report(&apk, &aab, &report_path(&aab), true, None).unwrap();
        assert_eq!(
            MethodReport::read(&report_path(&aab))
                .unwrap()
                .output_sha256,
            Some(file_sha256(&aab).unwrap())
        );
        for entries in [
            vec![
                ("base/dex/classes.dex", &b"changed"[..]),
                ("feature/dex/classes.dex", &b"feature"[..]),
            ],
            vec![
                ("base/dex/classes.dex", &b"stub"[..]),
                ("wrong/dex/classes.dex", &b"feature"[..]),
            ],
            vec![
                ("base/dex/classes.dex", &b"stub"[..]),
                ("feature/dex/classes.dex", &b"feature"[..]),
                ("backup/classes.dex", &b"original"[..]),
            ],
        ] {
            archive(&aab, &entries);
            assert!(rebind_report(&apk, &aab, &report_path(&aab), true, None).is_err());
        }
        archive(&apk, &[("classes.dex", b"different source")]);
        assert!(rebind_report(&apk, &aab, &report_path(&aab), true, None).is_err());
    }

    #[test]
    fn 方法报告必须对应真实输入输出与_sidecar索引() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("classes.dex"), b"transformed").unwrap();
        let mut code = Vec::new();
        code.extend_from_slice(&[4, 0, 1, 0]);
        for n in [8u32, 0] {
            code.extend_from_slice(&n.to_le_bytes());
        }
        code.extend_from_slice(&1u16.to_le_bytes());
        for n in [7u32, 18, 46, 2] {
            code.extend_from_slice(&n.to_le_bytes());
        }
        code.extend_from_slice(&[0; 46]);
        let data = serde_json::json!({
            "schema_version": 2, "image_version": 7, "code_version": 4, "code_sha256": sha256(&code),
            "dexes": {"classes.dex": {"module": "base", "input_sha256": "input", "output_sha256": sha256(b"transformed")}},
            "methods": [{"module": "base", "descriptor": "La/A;->f()I", "required": false, "input_instruction_bytes": 16, "input_dex": "classes.dex", "transform_status": "transformed", "artifact_verified": true, "plaintext_policy": "bounded_cache", "final_dex_index": 0, "final_method_index": 7, "reason": null}]
        });
        let modules = BTreeMap::from([("classes.dex".into(), "base".into())]);
        let inputs = BTreeMap::from([("classes.dex".into(), "input".into())]);
        let mut report: MethodReport = serde_json::from_value(data.clone()).unwrap();
        report
            .validate(dir.path(), &code, &modules, &BTreeSet::new(), 1, &inputs)
            .unwrap();
        assert!(report.metrics["required_coverage_percent"].is_null());
        assert_eq!(report.metrics["instruction_coverage_percent"], 100.0);
        for mandatory in [false, true] {
            let required = if mandatory {
                BTreeSet::from(["base\tLa/A;->f()I".into()])
            } else {
                BTreeSet::new()
            };
            for policy in [
                None,
                Some("bounded_cache"),
                Some("clear_after_use"),
                Some("unknown"),
            ] {
                let mut candidate: MethodReport = serde_json::from_value(data.clone()).unwrap();
                candidate.methods[0].required = mandatory;
                candidate.methods[0].plaintext_policy = policy.map(str::to_owned);
                let accepted = candidate
                    .validate(dir.path(), &code, &modules, &required, 1, &inputs)
                    .is_ok();
                assert_eq!(
                    accepted,
                    policy
                        == Some(if mandatory {
                            "clear_after_use"
                        } else {
                            "bounded_cache"
                        })
                );
            }
        }
        for image in [7, 8, 9] {
            let mut candidate: MethodReport = serde_json::from_value(data.clone()).unwrap();
            candidate.image_version = image;
            assert!(candidate
                .validate(dir.path(), &code, &modules, &BTreeSet::new(), 1, &inputs)
                .is_ok());
        }
        for (schema, image) in [(1, 7), (2, 6), (2, 10)] {
            let mut candidate: MethodReport = serde_json::from_value(data.clone()).unwrap();
            candidate.schema_version = schema;
            candidate.image_version = image;
            assert!(candidate
                .validate(dir.path(), &code, &modules, &BTreeSet::new(), 1, &inputs)
                .is_err());
        }
        report.methods[0].final_method_index = Some(8);
        assert!(report
            .validate(dir.path(), &code, &modules, &BTreeSet::new(), 1, &inputs)
            .is_err());
        let required = BTreeSet::from(["base\tLa/A;->missing()I".into()]);
        let mut report: MethodReport = serde_json::from_value(data).unwrap();
        assert!(report
            .validate(dir.path(), &code, &modules, &required, 1, &inputs)
            .is_err());
    }
}
