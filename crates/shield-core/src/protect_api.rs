use colored::Colorize;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use crate::apk_inspect::{
    check_apk, extract_apk_cert_fingerprint, normalize_fingerprint, ApkCheckOutcome,
};
use crate::diagnostic::{Diagnostic, FailureCode, ToolName};
use crate::error::ShieldError;
use crate::fusion_contract::FusionPlan;
use crate::protect::{
    abi_filter::{remove_excluded, validate_exclusions},
    dex::process_dex,
    manifest::{
        add_cache_identity, add_memory_payload_metrics, add_xop_pvm2_marker, modify_manifest,
        read_native_lib_packaging_policy, NativeLibPackagingPolicy,
    },
    native_alias::verify_in_apk,
    resource_format::{
        normalize_mislabeled_jpeg_resources, restore_original_resources, verify_original_resources,
    },
    runtime::{inject_runtime, read_runtime_selection},
};
use crate::protection_policy::{AiResistance, ProtectionPolicy, ProtectionProfile};
use crate::utils::is_json_mode;
use crate::utils::{
    create_temp_dir, ensure_java_runtime, find_apksigner, find_apktool, find_runtime_resources,
    human_size, no_window_command, print_step, print_success,
};
use std::process::Stdio;

pub const XOP_PVM2_MIN_JAVA_MAJOR_VERSION: u32 = 17;
/// Strict mode fails closed below this transformed/attempted method ratio.
pub const STRICT_PVM2_MIN_SUCCESS_RATE: f64 = 70.0;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EnvironmentPolicy {
    #[default]
    Compatible,
    Strict,
}

impl EnvironmentPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Compatible => "compatible",
            Self::Strict => "strict",
        }
    }
}
use crate::zipalign::{align_apk_with_native_packaging, NativeLibraryPackaging};

#[derive(Debug, Clone)]
pub struct ProtectOptions {
    /// 用户对本次任务明确确认排除的、不受支持的 Native ABI。
    pub excluded_abis: Vec<String>,
    pub input: PathBuf,
    pub output: PathBuf,
    /// 用户自定义 apktool.jar 路径（优先于自动查找）
    pub apktool_path: Option<PathBuf>,
    /// 用户自定义 resources.zip 路径（优先于自动查找）
    pub resources_path: Option<PathBuf>,
    /// 用户自定义 apksigner.jar 路径（优先于自动查找）
    pub apksigner_path: Option<PathBuf>,
    /// 计划用于加固输出签名的证书指纹；提供时必须与输入 APK 当前证书一致
    pub expected_output_cert_fingerprint: Option<String>,
    /// 设备最终安装 APK 的证书指纹。AAB 经 Play App Signing 重签时必须显式提供；
    /// 普通 APK 留空即绑定输入 APK 当前证书。
    pub runtime_cert_fingerprint: Option<String>,
    /// 运行时环境安全策略；默认兼容模式仅执行原有反调试检查。
    pub environment_policy: EnvironmentPolicy,
    /// 保护级别：compat、balanced 或 strict。
    pub protection_profile: ProtectionProfile,
    /// AI 静态语义恢复抵抗强度。
    pub ai_resistance: AiResistance,
    /// Xop transform-only Packer；提供时把 TRUE_VMP 变换接入 Shellsmith 单 Stub。
    pub xop_pvm2_packer_path: Option<PathBuf>,
    /// 明确允许虚拟化的 DEX 类型描述符前缀。
    pub xop_true_vmp_prefixes: Vec<String>,
    /// AAB dynamic-feature DEX staging root. Files use the same PVM2 key and
    /// global DEX index space, then are written back before base DEX packing.
    pub external_pvm2_dex_dir: Option<PathBuf>,
    /// AAB dynamic-feature / Asset Pack staging root. Referenced assets are
    /// encrypted with the base module PAS2 key and written back to their module.
    pub external_pas2_assets_dir: Option<PathBuf>,
    /// Module names whose assets may legitimately be absent until Play delivers
    /// a conditional/on-demand feature or deferred Asset Pack.
    pub deferred_pas2_asset_modules: Vec<String>,
    /// An external Play Asset Delivery reader owns file-path based access, so a
    /// zero AssetManager callsite count is valid for referenced PAS2 assets.
    pub allow_external_pas2_reader: bool,
    /// AAB dynamic-feature native library staging root. Libraries use the same
    /// PSO2 key table as base and are restored to their original module.
    pub external_native_lib_dir: Option<PathBuf>,
}

#[derive(Debug)]
struct StagedExternalDex {
    staged: PathBuf,
    original: PathBuf,
}

#[derive(Debug)]
struct StagedExternalAsset {
    staged_plain: PathBuf,
    staged_encrypted: PathBuf,
    original_plain: PathBuf,
    module_encrypted: PathBuf,
    deferred: bool,
}

#[derive(Debug)]
struct StagedExternalNativeLibrary {
    staged: PathBuf,
    original: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ProgressEvent {
    pub step: ProgressStep,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgressStep {
    CheckTools,
    Unpack,
    ModifyManifest,
    ProcessDex,
    InjectRuntime,
    Repack,
    AlignApk,
}

pub fn protect_apk(
    opts: &ProtectOptions,
    on_progress: impl Fn(ProgressEvent) + Send + 'static,
    cancel: Arc<AtomicBool>,
) -> std::result::Result<(), ShieldError> {
    if !opts.input.exists() {
        return Err(ShieldError::FileNotFound(opts.input.display().to_string()));
    }

    let apktool = match &opts.apktool_path {
        Some(p) if p.exists() => p.clone(),
        Some(p) => {
            return Err(ShieldError::from(anyhow::anyhow!(
                "配置的 apktool.jar 路径不存在: {}",
                p.display()
            )))
        }
        None => find_apktool().map_err(missing_tool)?,
    };
    let custom_runtime_resources = opts.resources_path.is_some();
    let runtime_resources = match &opts.resources_path {
        Some(p) if p.exists() => p.clone(),
        Some(p) => {
            return Err(ShieldError::from(anyhow::anyhow!(
                "配置的 resources.zip 路径不存在: {}",
                p.display()
            )))
        }
        None => find_runtime_resources().map_err(missing_tool)?,
    };
    let apksigner = match &opts.apksigner_path {
        Some(p) if p.exists() => p.clone(),
        Some(p) => {
            return Err(ShieldError::from(anyhow::anyhow!(
                "配置的 apksigner.jar 路径不存在: {}",
                p.display()
            )))
        }
        None => find_apksigner().map_err(missing_tool)?,
    };
    let runtime_selection = read_runtime_selection(
        &runtime_resources,
        opts.environment_policy,
        custom_runtime_resources,
    )
    .map_err(ShieldError::from)?;
    if opts.xop_pvm2_packer_path.is_some() && !runtime_selection.xop_pvm2 {
        return Err(ShieldError::from(anyhow::anyhow!(
            "所选 Runtime 资源未声明 xop_pvm2=true；拒绝生成无法解释 PVM2 跳板的安装包"
        )));
    }
    if let Some(packer) = opts.xop_pvm2_packer_path.as_deref() {
        // 打包器与壳运行时取自不同 XopProtector 源码时，镜像版本会超出运行时上限，
        // 产物在设备上表现为启动即崩（PVM2 unsupported version N / VMP not ready）。
        crate::protect::pvm2_format::verify_format_compatibility(
            packer,
            runtime_selection.xop_pvm2_format,
        )
        .map_err(ShieldError::from)?;
    }
    if matches!(opts.protection_profile, ProtectionProfile::Strict)
        && !runtime_selection.assets_pas2
    {
        return Err(ShieldError::from(anyhow::anyhow!(
            "严格保护需要声明 assets_pas2=true 的新版 Runtime 资源包"
        )));
    }
    if matches!(opts.protection_profile, ProtectionProfile::Strict)
        && !runtime_selection.native_so_text
    {
        return Err(ShieldError::from(anyhow::anyhow!(
            "严格保护需要声明 native_so_text=true 的新版 Runtime 资源包"
        )));
    }
    if matches!(opts.protection_profile, ProtectionProfile::Strict)
        && !runtime_selection.native_so_functions
    {
        return Err(ShieldError::from(anyhow::anyhow!(
            "严格保护需要声明 native_so_functions=true 的新版 Runtime 资源包"
        )));
    }
    if opts.xop_pvm2_packer_path.is_some() && opts.xop_true_vmp_prefixes.is_empty() {
        return Err(ShieldError::from(anyhow::anyhow!(
            "融合 PVM2 必须至少提供一个 xop_true_vmp_prefixes，避免无边界虚拟化"
        )));
    }
    let policy = ProtectionPolicy::for_profile(opts.protection_profile, opts.ai_resistance);
    let fusion_plan = if opts.xop_pvm2_packer_path.is_some() {
        FusionPlan::for_policy(opts.protection_profile, opts.ai_resistance).with_embedded_pvm2()
    } else {
        FusionPlan::for_policy(opts.protection_profile, opts.ai_resistance)
    };
    if !fusion_plan.satisfies_profile() {
        return Err(ShieldError::from(anyhow::anyhow!(
            "strict 保护级别需要真实嵌入的 Xop PVM2；请配置 Packer JAR 和至少一个业务类前缀，或改用 balanced/compat"
        )));
    }

    if !is_json_mode() {
        println!("{}", "========================================".cyan());
        println!("{}", "Shellsmith · APK Protection".cyan().bold());
        println!("{}", "========================================".cyan());
        println!("输入APK: {:?}", opts.input);
        println!("输出APK: {:?}", opts.output);
        println!(
            "保护策略: profile={} ai_resistance={}",
            policy.profile.as_str(),
            policy.ai_resistance.as_str()
        );
        println!(
            "融合契约: v{} DEXB v{} 状态={}（单壳约束={})",
            fusion_plan.contract_version,
            fusion_plan.dex_protocol_version,
            fusion_plan.status(),
            fusion_plan.single_shell_required
        );
        println!("{}", "========================================".cyan());
    }

    let java_info = ensure_java_runtime().map_err(missing_tool)?;
    if opts.xop_pvm2_packer_path.is_some()
        && java_info.major_version.unwrap_or(0) < XOP_PVM2_MIN_JAVA_MAJOR_VERSION
    {
        return Err(ShieldError::from(anyhow::anyhow!(
            "Xop PVM2 Packer 需要 Java {}+；当前检测到 {}",
            XOP_PVM2_MIN_JAVA_MAJOR_VERSION,
            java_info.version_label()
        )));
    }
    let java = java_info.java_path.expect("已验证 Java 路径");

    emit_progress(&on_progress, &cancel, ProgressStep::CheckTools, "检查工具")?;
    print_step("检查工具");
    print_success("所有工具就绪");

    let apk_check = check_apk(&opts.input, Some(&apksigner)).map_err(ShieldError::from)?;
    validate_apk_eligibility(&apk_check).map_err(preflight)?;
    validate_exclusions(&apk_check.native_abis, &opts.excluded_abis).map_err(preflight)?;
    let input_signature =
        extract_apk_cert_fingerprint(&opts.input, Some(&apksigner)).map_err(ShieldError::from)?;
    let signature =
        resolve_runtime_certificate(&input_signature, opts.runtime_cert_fingerprint.as_deref())
            .map_err(preflight)?;
    validate_output_certificate(&signature, opts.expected_output_cert_fingerprint.as_deref())
        .map_err(preflight)?;
    print_success(&format!(
        "运行时绑定证书 SHA-256: {}...{}",
        &signature[..16],
        if signature == normalize_fingerprint(&input_signature) {
            ""
        } else {
            "（使用最终分发证书覆盖）"
        }
    ));

    let temp_dir = create_temp_dir("shield-").map_err(ShieldError::from)?;
    let apk_dir = temp_dir.path().join("apk");

    emit_progress(&on_progress, &cancel, ProgressStep::Unpack, "解包APK")?;
    print_step("解包APK");
    run_apktool_command(
        &java,
        &[
            "-jar",
            apktool.to_str().unwrap(),
            "d",
            opts.input.to_str().unwrap(),
            "-o",
            apk_dir.to_str().unwrap(),
            "-f",
            "--no-src",
        ],
        FailureCode::ToolProcessFailed,
    )
    .map_err(ShieldError::from)?;
    print_success("解包完成");
    remove_excluded(&apk_dir, &opts.excluded_abis).map_err(ShieldError::from)?;
    if !opts.excluded_abis.is_empty() {
        let message = format!("已从输出排除 ABI：{}", opts.excluded_abis.join("、"));
        emit_progress(&on_progress, &cancel, ProgressStep::Unpack, &message)?;
        print_success(&message);
    }

    let native_lib_policy =
        read_native_lib_packaging_policy(&apk_dir).map_err(ShieldError::from)?;
    let normalized_resources =
        normalize_mislabeled_jpeg_resources(&apk_dir).map_err(ShieldError::from)?;
    if normalized_resources > 0 {
        print_success(&format!(
            "已修正 {normalized_resources} 个 JPEG 内容伪装 PNG 的资源文件"
        ));
    }

    emit_progress(
        &on_progress,
        &cancel,
        ProgressStep::ModifyManifest,
        "修改AndroidManifest.xml",
    )?;
    print_step("修改AndroidManifest.xml");
    modify_manifest(
        &apk_dir,
        &runtime_selection.stub_application,
        runtime_selection.stub_component_factory.as_deref(),
        opts.environment_policy,
    )
    .map_err(ShieldError::from)?;
    print_success("Manifest修改完成");

    emit_progress(
        &on_progress,
        &cancel,
        ProgressStep::ProcessDex,
        "处理DEX文件",
    )?;

    let mut ikm = [0u8; 32];
    rand::rng().fill_bytes(&mut ikm);

    if let Some(packer) = opts.xop_pvm2_packer_path.as_deref() {
        let staged_external_assets = stage_external_pas2_assets(
            &apk_dir,
            opts.external_pas2_assets_dir.as_deref(),
            &opts.deferred_pas2_asset_modules,
        )
        .map_err(ShieldError::from)?;
        let staged_external_native =
            stage_external_native_libraries(&apk_dir, opts.external_native_lib_dir.as_deref())
                .map_err(ShieldError::from)?;
        let staged_external;
        if matches!(opts.protection_profile, ProtectionProfile::Strict) {
            let ids = crate::protect::xop_pvm2::transform_resource_ids(&java, packer, &apk_dir)
                .map_err(ShieldError::from)?;
            if ids.changed == 0 {
                print_success(&format!(
                    "资源 ID 重排跳过：各资源类型不足两个安全可置换条目（{} 个 Native/opaque/packed-switch ID 已固定）",
                    ids.pinned
                ));
            } else {
                print_success(&format!(
                    "资源 ID 重排完成：{} 个 ID 已置换，{} 个 Native/opaque/packed-switch ID 为兼容性固定",
                    ids.changed, ids.pinned
                ));
            }
            // Resource-ID rewriting only owns the decoded base resource table. Stage feature
            // DEX after that transform, but before PAS2 so feature-local asset references and
            // AssetManager callsites participate in the shared single-Stub rewrite.
            staged_external =
                stage_external_pvm2_dexes(&apk_dir, opts.external_pvm2_dex_dir.as_deref())
                    .map_err(ShieldError::from)?;
            let assets = crate::protect::xop_pvm2::transform_assets(
                &java,
                packer,
                &apk_dir,
                &ikm,
                &signature,
                runtime_selection.assets_bridge.as_deref().ok_or_else(|| {
                    ShieldError::from(anyhow::anyhow!("Runtime 缺少 PAS2 assets 桥类元数据"))
                })?,
                runtime_selection
                    .assets_bridge_method
                    .as_deref()
                    .ok_or_else(|| {
                        ShieldError::from(anyhow::anyhow!("Runtime 缺少 PAS2 assets 桥方法元数据"))
                    })?,
                opts.allow_external_pas2_reader,
            )
            .map_err(ShieldError::from)?;
            restore_external_pas2_assets(&staged_external_assets).map_err(ShieldError::from)?;
            print_success(&format!(
                "assets PAS2 分块加密完成：{} 个文件加密（Java {}、Native {}），{} 个兼容性跳过，{} 个 open/openFd 调用已重定向",
                assets.encrypted,
                assets.java_assets,
                assets.native_assets,
                assets.skipped,
                assets.callsites
            ));
            let native = crate::protect::xop_pvm2::transform_native_sos(
                &java, packer, &apk_dir, &ikm, &signature,
            )
            .map_err(ShieldError::from)?;
            restore_external_native_libraries(&staged_external_native)
                .map_err(ShieldError::from)?;
            print_success(&format!(
                "Native SO 函数区域保护：{} 个 ABI 文件（{} 个名称、{} 个函数区域）已加密，{} 个跳过（策略 {}、重定位 {}、预算 {}）",
                native.encrypted_files,
                native.encrypted_basenames,
                native.function_regions,
                native.skipped,
                native.skipped_policy,
                native.skipped_reloc,
                native.skipped_budget,
            ));
        } else if !staged_external_assets.is_empty() || !staged_external_native.is_empty() {
            return Err(ShieldError::from(anyhow::anyhow!(
                "AAB 外部 assets/lib 仅在 strict 模式执行 PAS2/PSO2 全量保护；拒绝生成明文模块"
            )));
        } else {
            staged_external =
                stage_external_pvm2_dexes(&apk_dir, opts.external_pvm2_dex_dir.as_deref())
                    .map_err(ShieldError::from)?;
        }
        let report = crate::protect::xop_pvm2::transform(
            &java,
            packer,
            &apk_dir,
            &ikm,
            &signature,
            opts.protection_profile,
            &opts.xop_true_vmp_prefixes,
            runtime_selection.xop_vm_bridge.as_deref().ok_or_else(|| {
                ShieldError::from(anyhow::anyhow!("Runtime 缺少 Xop VM 桥类元数据"))
            })?,
            runtime_selection
                .xop_vm_bridge_method
                .as_deref()
                .ok_or_else(|| {
                    ShieldError::from(anyhow::anyhow!("Runtime 缺少 Xop VM 桥方法元数据"))
                })?,
            cancel.as_ref(),
            &|message| {
                on_progress(ProgressEvent {
                    step: ProgressStep::ProcessDex,
                    message,
                });
            },
        )
        .map_err(|error| {
            if cancel.load(Ordering::Relaxed) {
                ShieldError::Cancelled
            } else {
                ShieldError::from(error)
            }
        })?;
        restore_external_pvm2_dexes(&staged_external).map_err(ShieldError::from)?;
        print_success(&format!(
            "Xop PVM2 覆盖报告：选中 {}，尝试 {}，成功 {}，跳过 {}，覆盖率 {:.1}%，ISA {}",
            report.candidates,
            report.attempted,
            report.transformed,
            report.fallback,
            report.success_rate,
            report.isa,
        ));
        if report.fallback > 0 {
            let reasons = report
                .skip_reasons
                .iter()
                .filter(|(_, count)| **count > 0)
                .map(|(reason, count)| format!("{reason}={count}"))
                .collect::<Vec<_>>()
                .join(", ");
            print_success(&format!("PVM2 兼容回退统计：{reasons}"));
        }
        if !report.unsupported_opcodes.is_empty() {
            let opcodes = report
                .unsupported_opcodes
                .iter()
                .map(|(opcode, count)| format!("{opcode}={count}"))
                .collect::<Vec<_>>()
                .join(", ");
            print_success(&format!("PVM2 未覆盖指令统计：{opcodes}"));
        }
        enforce_pvm2_coverage(opts.protection_profile, &report).map_err(ShieldError::from)?;
        add_xop_pvm2_marker(&apk_dir).map_err(ShieldError::from)?;
    } else if !opts.xop_true_vmp_prefixes.is_empty() {
        return Err(ShieldError::from(anyhow::anyhow!(
            "已提供 Xop TRUE_VMP 前缀，但缺少 xop_pvm2_packer_path"
        )));
    }

    print_step("处理DEX文件");
    let compression_layers = opts.ai_resistance.compression_layers();
    print_success(&format!(
        "DEXB v6 AI 抵抗 {}：使用 {} 层压缩",
        opts.ai_resistance.as_str(),
        compression_layers
    ));
    let cache_identity =
        process_dex(&apk_dir, &signature, &ikm, compression_layers).map_err(ShieldError::from)?;
    add_cache_identity(&apk_dir, &cache_identity).map_err(ShieldError::from)?;
    if runtime_selection.memory_dex {
        add_memory_payload_metrics(&apk_dir, &cache_identity).map_err(ShieldError::from)?;
    }

    emit_progress(
        &on_progress,
        &cancel,
        ProgressStep::InjectRuntime,
        "注入Runtime库",
    )?;
    print_step("注入Runtime库");
    let injected_runtime = inject_runtime(
        &apk_dir,
        &runtime_resources,
        &opts.input,
        &opts.excluded_abis,
    )
    .map_err(|err| diagnosed(err, FailureCode::RuntimeInjectionFailed))?;
    print_success("Runtime库注入完成");

    emit_progress(&on_progress, &cancel, ProgressStep::Repack, "重打包APK")?;
    print_step("重打包APK");
    run_apktool_command(
        &java,
        &[
            "-jar",
            apktool.to_str().unwrap(),
            "b",
            apk_dir.to_str().unwrap(),
            "-o",
            opts.output.to_str().unwrap(),
            "-f",
        ],
        FailureCode::ApkRepackFailed,
    )
    .map_err(|err| diagnosed(err, FailureCode::ApkRepackFailed))?;

    if !matches!(opts.protection_profile, ProtectionProfile::Strict) {
        let restored_resources = restore_original_resources(&opts.input, &opts.output)
            .map_err(|err| diagnosed(err, FailureCode::ApkRepackFailed))?;
        if restored_resources > 0 {
            print_success(&format!(
                "已原样恢复 {restored_resources} 个混淆资源条目（resources.arsc + res/）"
            ));
        }
    }

    let resource_transform = if matches!(opts.protection_profile, ProtectionProfile::Strict) {
        let packer = opts.xop_pvm2_packer_path.as_deref().ok_or_else(|| {
            ShieldError::from(anyhow::anyhow!(
                "严格资源混淆需要可用的内置/自定义 Xop Packer"
            ))
        })?;
        let report = crate::protect::xop_pvm2::transform_resources(&java, packer, &opts.output)
            .map_err(|err| diagnosed(err, FailureCode::ApkRepackFailed))?;
        if report.path_count() == 0 {
            print_success("新增资源路径混淆跳过：APK 中没有可安全缩短的文件型 res 路径");
        } else {
            print_success(&format!(
                "新增资源路径混淆完成：{} 个文件路径已改写并同步更新 resources.arsc",
                report.path_count()
            ));
        }
        Some(report)
    } else {
        None
    };

    let input_size = fs::metadata(&opts.input)
        .map_err(anyhow::Error::from)
        .map_err(ShieldError::from)?
        .len();
    let output_size = fs::metadata(&opts.output)
        .map_err(anyhow::Error::from)
        .map_err(ShieldError::from)?
        .len();
    let ratio = 100.0 * output_size as f64 / input_size as f64;
    print_success(&format!(
        "APK重打包完成: {} -> {} ({:.1}%)",
        human_size(input_size),
        human_size(output_size),
        ratio
    ));

    emit_progress(&on_progress, &cancel, ProgressStep::AlignApk, "对齐APK数据")?;
    print_step("对齐APK数据");
    align_apk_with_native_packaging(&opts.output, native_library_packaging(native_lib_policy))
        .map_err(|err| diagnosed(err, FailureCode::AlignmentFailed))?;
    if let Some(report) = resource_transform.as_ref() {
        crate::protect::xop_pvm2::verify_resource_transform(&opts.input, &opts.output, report)
            .map_err(|err| diagnosed(err, FailureCode::AlignmentFailed))?;
    } else {
        verify_original_resources(&opts.input, &opts.output)
            .map_err(|err| diagnosed(err, FailureCode::AlignmentFailed))?;
    }
    verify_in_apk(&opts.output, &injected_runtime).map_err(ShieldError::from)?;
    print_success("APK数据对齐完成");

    Ok(())
}

fn stage_external_pvm2_dexes(
    apk_dir: &Path,
    external_root: Option<&Path>,
) -> anyhow::Result<Vec<StagedExternalDex>> {
    let Some(external_root) = external_root else {
        return Ok(Vec::new());
    };
    if !external_root.is_dir() {
        anyhow::bail!("AAB 外部 DEX 暂存目录不存在：{}", external_root.display());
    }
    let mut external = walkdir::WalkDir::new(external_root)
        .follow_links(false)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("dex"))
        .collect::<Vec<_>>();
    external.sort();
    if external.is_empty() {
        return Ok(Vec::new());
    }
    let first = std::fs::read_dir(apk_dir)?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| dex_number(&entry.file_name().to_string_lossy()))
        .max()
        .unwrap_or(0)
        + 1;
    let mut staged = Vec::with_capacity(external.len());
    for (offset, original) in external.into_iter().enumerate() {
        let next = first + offset;
        let destination = apk_dir.join(format!("classes{next}.dex"));
        if destination.exists() {
            anyhow::bail!("AAB 外部 DEX 全局编号冲突：{}", destination.display());
        }
        std::fs::copy(&original, &destination)?;
        staged.push(StagedExternalDex {
            staged: destination,
            original,
        });
    }
    Ok(staged)
}

fn restore_external_pvm2_dexes(staged: &[StagedExternalDex]) -> anyhow::Result<()> {
    for item in staged {
        std::fs::copy(&item.staged, &item.original)?;
        std::fs::remove_file(&item.staged)?;
    }
    Ok(())
}

fn stage_external_pas2_assets(
    apk_dir: &Path,
    external_root: Option<&Path>,
    deferred_modules: &[String],
) -> anyhow::Result<Vec<StagedExternalAsset>> {
    let Some(external_root) = external_root else {
        return Ok(Vec::new());
    };
    if !external_root.is_dir() {
        anyhow::bail!("AAB Asset Pack 暂存目录不存在：{}", external_root.display());
    }
    let mut staged = Vec::new();
    let mut modules = std::fs::read_dir(external_root)?
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    modules.sort();
    for module in modules {
        let module_name = module
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| anyhow::anyhow!("AAB 模块名称不是 UTF-8"))?;
        let deferred = deferred_modules.iter().any(|name| name == module_name);
        let assets = module.join("assets");
        if !assets.is_dir() {
            continue;
        }
        if assets.join("protector").exists() {
            anyhow::bail!(
                "AAB Asset Pack 已包含 protector 保留目录：{}",
                assets.display()
            );
        }
        let mut files = walkdir::WalkDir::new(&assets)
            .follow_links(false)
            .into_iter()
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|entry| entry.file_type().is_file())
            .map(|entry| entry.into_path())
            .collect::<Vec<_>>();
        files.sort();
        for original_plain in files {
            let relative = original_plain
                .strip_prefix(&assets)
                .map_err(|_| anyhow::anyhow!("Asset Pack 文件超出 assets 目录"))?;
            let staged_plain = apk_dir.join("assets").join(relative);
            if staged_plain.exists() {
                anyhow::bail!(
                    "AAB install-time Asset Pack 与 base/其他模块资源路径冲突：{}",
                    relative.display()
                );
            }
            if let Some(parent) = staged_plain.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(&original_plain, &staged_plain)?;
            staged.push(StagedExternalAsset {
                staged_encrypted: apk_dir.join("assets/protector/aenc").join(relative),
                module_encrypted: assets.join("protector/aenc").join(relative),
                staged_plain,
                original_plain,
                deferred,
            });
        }
    }
    if staged.is_empty() {
        anyhow::bail!("AAB 外部模块未包含可保护的 assets 文件");
    }
    let deferred_index = apk_dir.join("assets/protector/deferred-assets.sha256");
    if let Some(parent) = deferred_index.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut hashes = staged
        .iter()
        .filter(|item| item.deferred)
        .map(|item| {
            let relative = item
                .staged_plain
                .strip_prefix(apk_dir.join("assets"))
                .map_err(|_| anyhow::anyhow!("暂存 PAS2 asset 超出 assets 目录"))?;
            let digest = Sha256::digest(relative.to_string_lossy().replace('\\', "/").as_bytes());
            Ok::<_, anyhow::Error>(
                digest
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
            )
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    hashes.sort();
    hashes.dedup();
    if hashes.is_empty() {
        if deferred_index.exists() {
            std::fs::remove_file(deferred_index)?;
        }
    } else {
        std::fs::write(deferred_index, hashes.join("\n") + "\n")?;
    }
    Ok(staged)
}

fn restore_external_pas2_assets(staged: &[StagedExternalAsset]) -> anyhow::Result<()> {
    for item in staged {
        if !item.staged_encrypted.is_file() {
            anyhow::bail!(
                "AAB 外部模块资源未被 PAS2 覆盖：{}；请确保代码中使用精确路径或目录前缀访问该资源",
                item.original_plain.display()
            );
        }
    }
    for item in staged {
        if let Some(parent) = item.module_encrypted.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(&item.staged_encrypted, &item.module_encrypted)?;
        std::fs::remove_file(&item.staged_encrypted)?;
        std::fs::remove_file(&item.original_plain)?;
        if item.staged_plain.exists() {
            std::fs::remove_file(&item.staged_plain)?;
        }
    }
    Ok(())
}

fn stage_external_native_libraries(
    apk_dir: &Path,
    external_root: Option<&Path>,
) -> anyhow::Result<Vec<StagedExternalNativeLibrary>> {
    let Some(external_root) = external_root else {
        return Ok(Vec::new());
    };
    if !external_root.is_dir() {
        anyhow::bail!(
            "AAB dynamic-feature Native 暂存目录不存在：{}",
            external_root.display()
        );
    }
    let mut files = walkdir::WalkDir::new(external_root)
        .follow_links(false)
        .into_iter()
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|entry| entry.file_type().is_file())
        .filter(|entry| {
            entry.path().extension().and_then(|value| value.to_str()) == Some("so")
                && entry
                    .path()
                    .components()
                    .any(|component| component.as_os_str() == "lib")
        })
        .map(|entry| entry.into_path())
        .collect::<Vec<_>>();
    files.sort();

    let mut staged = Vec::new();
    for original in files {
        let components = original.components().collect::<Vec<_>>();
        let lib_index = components
            .iter()
            .rposition(|component| component.as_os_str() == "lib")
            .ok_or_else(|| anyhow::anyhow!("dynamic-feature Native 路径缺少 lib 目录"))?;
        let relative =
            components[lib_index + 1..]
                .iter()
                .fold(PathBuf::new(), |mut path, component| {
                    path.push(component.as_os_str());
                    path
                });
        if relative.components().count() != 2 {
            anyhow::bail!(
                "dynamic-feature Native 路径必须是 lib/<abi>/<name>.so：{}",
                original.display()
            );
        }
        let destination = apk_dir.join("lib").join(&relative);
        if destination.exists() {
            anyhow::bail!(
                "AAB base/dynamic-feature Native 路径冲突：{}",
                relative.display()
            );
        }
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(&original, &destination)?;
        staged.push(StagedExternalNativeLibrary {
            staged: destination,
            original,
        });
    }
    Ok(staged)
}

fn restore_external_native_libraries(staged: &[StagedExternalNativeLibrary]) -> anyhow::Result<()> {
    for item in staged {
        if !item.staged.is_file() {
            anyhow::bail!(
                "dynamic-feature Native 变换后文件丢失：{}",
                item.original.display()
            );
        }
    }
    for item in staged {
        std::fs::copy(&item.staged, &item.original)?;
        std::fs::remove_file(&item.staged)?;
    }
    Ok(())
}

fn dex_number(name: &str) -> Option<usize> {
    if name == "classes.dex" {
        return Some(1);
    }
    name.strip_prefix("classes")?
        .strip_suffix(".dex")?
        .parse::<usize>()
        .ok()
        .filter(|value| *value >= 2)
}

fn enforce_pvm2_coverage(
    profile: ProtectionProfile,
    report: &crate::protect::xop_pvm2::TransformReport,
) -> anyhow::Result<()> {
    if matches!(profile, ProtectionProfile::Strict)
        && report.success_rate < STRICT_PVM2_MIN_SUCCESS_RATE
    {
        anyhow::bail!(
            "strict PVM2 覆盖率 {:.1}% 低于最低门槛 {:.1}%：选中 {}，成功 {}，跳过 {}。请缩小到高价值且兼容的业务前缀，或补齐上述跳过指令后重试",
            report.success_rate,
            STRICT_PVM2_MIN_SUCCESS_RATE,
            report.candidates,
            report.transformed,
            report.fallback
        );
    }
    Ok(())
}

fn run_apktool_command(
    java: &std::path::Path,
    args: &[&str],
    fallback: FailureCode,
) -> anyhow::Result<String> {
    let output = no_window_command(java)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| {
            Diagnostic::from_io(&error).attach(anyhow::anyhow!("执行命令失败: {:?}: {error}", java))
        })?;
    if !output.status.success() {
        return Err(apktool_command_error(
            java,
            fallback,
            output.status.code(),
            &output.stdout,
            &output.stderr,
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn apktool_command_error(
    java: &std::path::Path,
    fallback: FailureCode,
    exit_code: Option<i32>,
    stdout: &[u8],
    stderr: &[u8],
) -> anyhow::Error {
    let evidence = if stderr.is_empty() { stdout } else { stderr };
    let mut diagnostic = Diagnostic::from_tool_output(ToolName::Apktool, exit_code, evidence);
    if diagnostic.code == FailureCode::ToolProcessFailed {
        diagnostic.code = fallback;
    }
    diagnostic.attach(anyhow::anyhow!(
        "命令执行失败: {:?}\n错误: {}",
        java,
        String::from_utf8_lossy(stderr)
    ))
}

fn missing_tool(error: anyhow::Error) -> ShieldError {
    diagnosed(error, FailureCode::ToolNotFound)
}

fn diagnosed(error: anyhow::Error, fallback: FailureCode) -> ShieldError {
    ShieldError::from(
        Diagnostic::from_error(&error)
            .or_code(fallback)
            .attach(error),
    )
}

fn preflight(error: anyhow::Error) -> ShieldError {
    let diagnostic = Diagnostic::from_error(&error);
    ShieldError::from(diagnostic.attach_preflight(error))
}

fn native_library_packaging(policy: NativeLibPackagingPolicy) -> NativeLibraryPackaging {
    match policy {
        NativeLibPackagingPolicy::Disabled => NativeLibraryPackaging::Store,
        NativeLibPackagingPolicy::Enabled | NativeLibPackagingPolicy::Unspecified => {
            NativeLibraryPackaging::Preserve
        }
    }
}

fn validate_apk_eligibility(outcome: &ApkCheckOutcome) -> anyhow::Result<()> {
    if outcome.already_protected {
        anyhow::bail!("该 APK 已经加固，禁止重复加固。请使用原始未加固 APK")
    }
    if !outcome.is_signed {
        anyhow::bail!("该 APK 尚未签名，加固需要有效签名的 APK")
    }
    Ok(())
}

fn validate_output_certificate(
    input_fingerprint: &str,
    expected_output_fingerprint: Option<&str>,
) -> anyhow::Result<()> {
    let Some(expected) = expected_output_fingerprint else {
        return Ok(());
    };
    if normalize_fingerprint(input_fingerprint) != normalize_fingerprint(expected) {
        anyhow::bail!(
            "原 APK 签名证书与所选自动签名证书不一致；加固数据绑定原证书，使用所选证书签名后应用将无法启动。请选择与原 APK 相同的证书"
        )
    }
    Ok(())
}

fn resolve_runtime_certificate(
    input_fingerprint: &str,
    runtime_fingerprint: Option<&str>,
) -> anyhow::Result<String> {
    let fingerprint = normalize_fingerprint(runtime_fingerprint.unwrap_or(input_fingerprint));
    if fingerprint.len() != 64 || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        anyhow::bail!("运行时证书 SHA-256 必须是 64 位十六进制字符串")
    }
    Ok(fingerprint)
}

fn emit_progress<F>(
    on_progress: &F,
    cancel: &Arc<AtomicBool>,
    step: ProgressStep,
    message: &str,
) -> std::result::Result<(), ShieldError>
where
    F: Fn(ProgressEvent) + Send + 'static,
{
    check_cancel(cancel)?;
    on_progress(ProgressEvent {
        step,
        message: message.to_string(),
    });
    Ok(())
}

fn check_cancel(cancel: &Arc<AtomicBool>) -> std::result::Result<(), ShieldError> {
    if cancel.load(Ordering::Relaxed) {
        return Err(ShieldError::Cancelled);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        enforce_pvm2_coverage, native_library_packaging, resolve_runtime_certificate,
        restore_external_native_libraries, restore_external_pas2_assets,
        restore_external_pvm2_dexes, stage_external_native_libraries, stage_external_pas2_assets,
        stage_external_pvm2_dexes, validate_apk_eligibility, validate_output_certificate,
    };
    use crate::diagnostic::{Diagnostic, FailureCode, ToolName};
    use crate::protect::xop_pvm2::TransformReport;
    use crate::protection_policy::ProtectionProfile;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    fn pvm2_report(success_rate: f64) -> TransformReport {
        TransformReport {
            transformed: 6,
            candidates: 10,
            attempted: 10,
            fallback: 4,
            success_rate,
            isa: 1,
            skip_reasons: BTreeMap::new(),
            unsupported_opcodes: BTreeMap::new(),
        }
    }

    #[test]
    fn strict_pvm2_覆盖率门槛失败关闭() {
        assert!(enforce_pvm2_coverage(ProtectionProfile::Strict, &pvm2_report(69.9)).is_err());
        assert!(enforce_pvm2_coverage(ProtectionProfile::Strict, &pvm2_report(70.0)).is_ok());
        assert!(enforce_pvm2_coverage(ProtectionProfile::Balanced, &pvm2_report(10.0)).is_ok());
    }

    #[test]
    fn dynamic_feature_dex_共享全局编号并写回原模块() {
        let temp = tempfile::tempdir().unwrap();
        let apk = temp.path().join("apk");
        let feature = temp.path().join("features/feature/dex");
        std::fs::create_dir_all(&apk).unwrap();
        std::fs::create_dir_all(&feature).unwrap();
        std::fs::write(apk.join("classes.dex"), b"base").unwrap();
        let original = feature.join("classes.dex");
        std::fs::write(&original, b"feature").unwrap();

        let staged =
            stage_external_pvm2_dexes(&apk, Some(temp.path().join("features").as_path())).unwrap();
        assert_eq!(staged.len(), 1);
        assert_eq!(std::fs::read(apk.join("classes2.dex")).unwrap(), b"feature");
        std::fs::write(&staged[0].staged, b"virtualized").unwrap();
        restore_external_pvm2_dexes(&staged).unwrap();
        assert_eq!(std::fs::read(original).unwrap(), b"virtualized");
        assert!(!apk.join("classes2.dex").exists());
    }

    #[test]
    fn install_time_asset_pack_仅在pas2覆盖后删除明文() {
        let temp = tempfile::tempdir().unwrap();
        let apk = temp.path().join("apk");
        let module_assets = temp.path().join("modules/pack/assets");
        std::fs::create_dir_all(apk.join("assets")).unwrap();
        std::fs::create_dir_all(&module_assets).unwrap();
        let original = module_assets.join("voice/sample.bin");
        std::fs::create_dir_all(original.parent().unwrap()).unwrap();
        std::fs::write(&original, b"plain").unwrap();

        let staged =
            stage_external_pas2_assets(&apk, Some(temp.path().join("modules").as_path()), &[])
                .unwrap();
        assert!(!apk.join("assets/protector/deferred-assets.sha256").exists());
        assert_eq!(std::fs::read(&staged[0].staged_plain).unwrap(), b"plain");
        assert!(restore_external_pas2_assets(&staged).is_err());
        assert!(original.is_file(), "失败关闭前不得删除模块明文");

        std::fs::create_dir_all(staged[0].staged_encrypted.parent().unwrap()).unwrap();
        std::fs::write(&staged[0].staged_encrypted, b"PAS2cipher").unwrap();
        restore_external_pas2_assets(&staged).unwrap();
        assert!(!original.exists());
        assert_eq!(
            std::fs::read(module_assets.join("protector/aenc/voice/sample.bin")).unwrap(),
            b"PAS2cipher"
        );
    }

    #[test]
    fn deferred_pas2_index_只允许缺失延迟交付模块() {
        let temp = tempfile::tempdir().unwrap();
        let apk = temp.path().join("apk");
        let install = temp.path().join("modules/install/assets");
        let on_demand = temp.path().join("modules/on_demand/assets");
        std::fs::create_dir_all(apk.join("assets")).unwrap();
        std::fs::create_dir_all(&install).unwrap();
        std::fs::create_dir_all(&on_demand).unwrap();
        std::fs::write(install.join("required.bin"), b"required").unwrap();
        std::fs::write(on_demand.join("late.bin"), b"late").unwrap();

        let staged = stage_external_pas2_assets(
            &apk,
            Some(temp.path().join("modules").as_path()),
            &["on_demand".to_string()],
        )
        .unwrap();
        assert_eq!(staged.iter().filter(|item| item.deferred).count(), 1);
        let index =
            std::fs::read_to_string(apk.join("assets/protector/deferred-assets.sha256")).unwrap();
        assert_eq!(index.lines().count(), 1);
        let expected = Sha256::digest(b"late.bin")
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(index.trim(), expected);
    }

    #[test]
    fn dynamic_feature_native_与base共用变换并写回原模块() {
        let temp = tempfile::tempdir().unwrap();
        let apk = temp.path().join("apk");
        let module_lib = temp.path().join("modules/feature/lib/arm64-v8a");
        std::fs::create_dir_all(apk.join("lib")).unwrap();
        std::fs::create_dir_all(&module_lib).unwrap();
        let original = module_lib.join("libfeature.so");
        std::fs::write(&original, b"plain-elf").unwrap();

        let staged =
            stage_external_native_libraries(&apk, Some(temp.path().join("modules").as_path()))
                .unwrap();
        assert_eq!(staged.len(), 1);
        assert_eq!(std::fs::read(&staged[0].staged).unwrap(), b"plain-elf");
        std::fs::write(&staged[0].staged, b"PSO2-protected-elf").unwrap();
        restore_external_native_libraries(&staged).unwrap();
        assert_eq!(std::fs::read(original).unwrap(), b"PSO2-protected-elf");
        assert!(!staged[0].staged.exists());
    }

    #[test]
    fn apktool_失败在字节转换前保留工具诊断() {
        let unsupported = super::apktool_command_error(
            std::path::Path::new("java"),
            FailureCode::ApkRepackFailed,
            Some(1),
            b"",
            b"java.lang.UnsupportedClassVersionError",
        );
        assert_eq!(
            Diagnostic::from_error(&unsupported).code,
            FailureCode::JavaUnsupported
        );
        assert_eq!(
            Diagnostic::from_error(&unsupported).tool,
            Some(ToolName::Apktool)
        );
        assert_eq!(Diagnostic::from_error(&unsupported).exit_code, Some(1));
        assert!(unsupported
            .to_string()
            .contains("UnsupportedClassVersionError"));

        let invalid = super::apktool_command_error(
            std::path::Path::new("java"),
            FailureCode::ApkRepackFailed,
            Some(1),
            b"",
            b"\xff\xfe",
        );
        assert_eq!(
            Diagnostic::from_error(&invalid).code,
            FailureCode::ToolOutputEncodingInvalid
        );
        assert!(invalid.to_string().contains("命令执行失败"));

        let unpack = super::apktool_command_error(
            std::path::Path::new("java"),
            FailureCode::ToolProcessFailed,
            Some(2),
            b"",
            b"ordinary apktool failure",
        );
        let repack = super::apktool_command_error(
            std::path::Path::new("java"),
            FailureCode::ApkRepackFailed,
            Some(3),
            b"",
            b"ordinary apktool failure",
        );
        assert_eq!(
            Diagnostic::from_error(&unpack).code,
            FailureCode::ToolProcessFailed
        );
        assert_eq!(
            Diagnostic::from_error(&repack).code,
            FailureCode::ApkRepackFailed
        );
    }

    #[test]
    fn runtime_certificate_accepts_play_signing_override() {
        let input = "11".repeat(32);
        let play = "aa:".repeat(31) + "aa";
        assert_eq!(
            resolve_runtime_certificate(&input, Some(&play)).unwrap(),
            "AA".repeat(32)
        );
        assert!(resolve_runtime_certificate(&input, Some("not-sha256")).is_err());
    }
    use crate::apk_inspect::ApkCheckOutcome;
    use crate::protect::manifest::NativeLibPackagingPolicy;
    use crate::zipalign::NativeLibraryPackaging;

    #[test]
    fn extract_native_libs_false_映射为不压缩策略() {
        assert_eq!(
            native_library_packaging(NativeLibPackagingPolicy::Disabled),
            NativeLibraryPackaging::Store
        );
        assert_eq!(
            native_library_packaging(NativeLibPackagingPolicy::Enabled),
            NativeLibraryPackaging::Preserve
        );
        assert_eq!(
            native_library_packaging(NativeLibPackagingPolicy::Unspecified),
            NativeLibraryPackaging::Preserve
        );
    }

    #[test]
    fn 已加固_apk_被核心入口拒绝() {
        let outcome = ApkCheckOutcome {
            already_protected: true,
            is_signed: true,
            native_abis: Vec::new(),
        };
        let error = validate_apk_eligibility(&outcome).unwrap_err();
        assert!(error.to_string().contains("禁止重复加固"));
    }

    #[test]
    fn 未签名_apk_被核心入口拒绝() {
        let outcome = ApkCheckOutcome {
            already_protected: false,
            is_signed: false,
            native_abis: Vec::new(),
        };
        let error = validate_apk_eligibility(&outcome).unwrap_err();
        assert!(error.to_string().contains("尚未签名"));
    }

    #[test]
    fn 自动签名证书不一致时失败关闭() {
        let error = validate_output_certificate("AA:BB", Some("CCDD")).unwrap_err();
        assert!(error.to_string().contains("应用将无法启动"));
    }

    #[test]
    fn 自动签名证书比较会规范化格式() {
        validate_output_certificate("aa:bb cc", Some("AABBCC")).unwrap();
    }

    #[test]
    fn 未配置自动签名时允许生成未签名产物() {
        validate_output_certificate("AABB", None).unwrap();
    }
}
