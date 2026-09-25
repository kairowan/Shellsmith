use anyhow::Result;
use colored::Colorize;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

use shield_core::utils::set_json_mode;
use shield_core::{
    check_apk, extract_apk_cert_fingerprint, extract_keystore_cert_fingerprint, inspect_aab,
    protect_apk, sign_apk_with_progress, validate_aab_for_module_processing, AiResistance,
    EnvironmentPolicy, KeystoreType, ProgressEvent, ProtectOptions, ProtectionProfile, SignOptions,
    SigningProgressStep, SigningVersions,
};

use crate::args::{
    AiResistanceArg, EnvironmentPolicyArg, KeystoreTypeArg, ProtectAabArgs, ProtectIosArgs,
    ProtectXopArgs, ProtectionEngineArg, ProtectionProfileArg, XopProfileArg,
};
use crate::config::{ResolvedProtectArgs, ResolvedSignArgs};

use crate::cli_json::{
    apk_check_json, contract_event_json, done_event_json, keystore_check_json, progress_event_json,
};

pub(crate) fn run_protect(args: ResolvedProtectArgs) -> Result<()> {
    if args.json {
        set_json_mode(true);
    } else {
        let level = if args.verbose {
            log::LevelFilter::Debug
        } else {
            log::LevelFilter::Info
        };
        env_logger::Builder::from_default_env()
            .filter_level(level)
            .init();
    }

    let opts = ProtectOptions {
        excluded_abis: args.excluded_abis,
        input: args.input,
        output: args.output,
        apktool_path: args.apktool,
        resources_path: args.resources,
        apksigner_path: args.apksigner,
        expected_output_cert_fingerprint: None,
        runtime_cert_fingerprint: None,
        environment_policy: match args.environment_policy {
            EnvironmentPolicyArg::Compatible => EnvironmentPolicy::Compatible,
            EnvironmentPolicyArg::Strict => EnvironmentPolicy::Strict,
        },
        protection_profile: match args.profile {
            ProtectionProfileArg::Compat => ProtectionProfile::Compat,
            ProtectionProfileArg::Balanced => ProtectionProfile::Balanced,
            ProtectionProfileArg::Strict => ProtectionProfile::Strict,
        },
        ai_resistance: match args.ai_resistance {
            AiResistanceArg::Off => AiResistance::Off,
            AiResistanceArg::Balanced => AiResistance::Balanced,
            AiResistanceArg::High => AiResistance::High,
        },
        xop_pvm2_packer_path: args.xop_pvm2_packer,
        xop_true_vmp_prefixes: args.xop_true_vmp_prefix,
        external_pvm2_dex_dir: None,
        external_pas2_assets_dir: None,
        deferred_pas2_asset_modules: Vec::new(),
        allow_external_pas2_reader: false,
        external_native_lib_dir: None,
    };

    let fusion_plan = if opts.xop_pvm2_packer_path.is_some() {
        shield_core::FusionPlan::for_policy(opts.protection_profile, opts.ai_resistance)
            .with_embedded_pvm2()
    } else {
        shield_core::FusionPlan::for_policy(opts.protection_profile, opts.ai_resistance)
    };
    if args.json {
        println!(
            "{}",
            contract_event_json(
                fusion_plan.contract_version,
                fusion_plan.dex_protocol_version,
                fusion_plan.profile.as_str(),
                fusion_plan.ai_resistance.as_str(),
                fusion_plan.ai_resistance.compression_layers(),
                fusion_plan.status(),
                fusion_plan.single_shell_required,
            )
        );
    }

    let cancel = Arc::new(AtomicBool::new(false));
    let on_progress: Box<dyn Fn(ProgressEvent) + Send + 'static> = if args.json {
        Box::new(|event: ProgressEvent| {
            let step = format!("{:?}", event.step);
            println!("{}", progress_event_json(&step, &event.message));
            let _ = std::io::stdout().flush();
        })
    } else {
        Box::new(|_| {})
    };

    protect_apk(&opts, on_progress, cancel)?;
    if args.json {
        println!("{}", done_event_json());
    } else {
        println!("{}", "✓ 完成".green().bold());
    }
    Ok(())
}

pub(crate) fn run_check_ios(project: PathBuf, scheme: Option<&str>) -> Result<String> {
    let report = shield_ios::inspect_ios_project(&project, scheme)?;
    serde_json::to_string_pretty(&report).map_err(Into::into)
}

pub(crate) fn run_protect_ios(args: ProtectIosArgs) -> Result<()> {
    let config = shield_ios::ShellsmithIosConfig::load(&args.config)?;
    let cancel = Arc::new(AtomicBool::new(false));
    let json = args.json;
    let report = shield_ios::protect_ios_project(
        &shield_ios::ProtectIosOptions {
            config,
            output_dir: args.output,
            export_options: args.export_options,
            export_method: args.export_method,
            allow_provisioning_updates: args.allow_provisioning_updates,
            dry_run: args.dry_run,
        },
        move |event| {
            if json {
                println!("{}", progress_event_json(&event.step, &event.message));
                let _ = std::io::stdout().flush();
            } else {
                println!("{} {}", "•".cyan(), event.message);
            }
        },
        cancel,
    )?;
    if args.json {
        println!("{}", serde_json::to_string(&report)?);
    } else {
        println!("{}", "✓ iOS 任务完成".green().bold());
        if let Some(ipa) = report.ipa {
            println!("IPA: {}", ipa.display());
        }
    }
    Ok(())
}

/// AAB delivery path. Dynamic features share the base PVM2/PAS2/PSO2 keys,
/// while install-time, fast-follow and on-demand asset packs share PAS2.
pub(crate) fn run_protect_aab(args: ProtectAabArgs) -> Result<()> {
    run_protect_aab_with_control(args, |_, _| {}, Arc::new(AtomicBool::new(false)))
}

pub fn run_protect_aab_with_control(
    args: ProtectAabArgs,
    on_progress: impl Fn(&str, &str) + Send + Sync + 'static,
    cancel: Arc<AtomicBool>,
) -> Result<()> {
    let on_progress = Arc::new(on_progress);
    on_progress("CheckTools", "检查 AAB、签名和构建工具");
    ensure_aab_not_cancelled(&cancel)?;
    if args.json {
        set_json_mode(true);
    }
    if !args.input.is_file() {
        anyhow::bail!("输入 AAB 不存在：{}", args.input.display());
    }
    if args.input == args.output {
        anyhow::bail!("输入和输出 AAB 不能是同一路径");
    }
    for (name, path) in [
        ("bundletool", &args.bundletool),
        ("aapt2", &args.aapt2),
        ("keystore", &args.ks),
    ] {
        if !path.is_file() {
            anyhow::bail!("{name} 不存在：{}", path.display());
        }
    }
    let inspection = inspect_aab(&args.input)?;
    validate_aab_for_module_processing(&inspection)?;
    on_progress(
        "InspectBundle",
        "检查 base、dynamic-feature 和 Asset Pack 模块",
    );
    ensure_aab_not_cancelled(&cancel)?;
    let extra_modules = inspection
        .module_details
        .iter()
        .filter(|module| module.name != "base")
        .collect::<Vec<_>>();
    if !extra_modules.is_empty() {
        if !matches!(args.engine, ProtectionEngineArg::Mocika) {
            anyhow::bail!("AAB 多模块当前只支持 Shellsmith 单 Stub + 嵌入式 PVM2");
        }
        if args.xop_pvm2_packer.is_none() || args.xop_true_vmp_prefix.is_empty() {
            anyhow::bail!(
                "AAB 多模块必须配置嵌入式 Xop PVM2 Packer 和业务类前缀，确保代码/资源模块共用单 Stub 密钥生命周期"
            );
        }
    }
    let mut asset_pack_modules = Vec::new();
    let mut dynamic_feature_modules = Vec::new();
    let mut deferred_asset_pack_count = 0usize;
    let mut deferred_asset_modules = Vec::new();
    let mut on_demand_dynamic_count = 0usize;
    let mut conditional_dynamic_count = 0usize;
    for module in &extra_modules {
        let manifest = run_bundletool_dump_manifest(&args.bundletool, &args.input, &module.name)?;
        if manifest.contains("dist:type=\"asset-pack\"") {
            let delivery =
                validate_asset_pack_manifest(&module.name, &manifest, args.play_delivery_adapter)?;
            if !matches!(delivery, AssetPackDelivery::InstallTimeFused) {
                deferred_asset_pack_count += 1;
                deferred_asset_modules.push(module.name.clone());
            }
            asset_pack_modules.push(module.name.clone());
        } else {
            let delivery = validate_dynamic_feature_manifest(&module.name, &manifest)?;
            match delivery {
                DynamicFeatureDelivery::InstallTime => {}
                DynamicFeatureDelivery::Conditional => {
                    conditional_dynamic_count += 1;
                    deferred_asset_modules.push(module.name.clone());
                }
                DynamicFeatureDelivery::OnDemand => {
                    on_demand_dynamic_count += 1;
                    deferred_asset_modules.push(module.name.clone());
                }
            }
            dynamic_feature_modules.push(module.name.clone());
        }
    }
    let dynamic_module_count = dynamic_feature_modules.len();
    if !asset_pack_modules.is_empty()
        && (!matches!(args.engine, ProtectionEngineArg::Mocika)
            || !matches!(args.profile, ProtectionProfileArg::Strict)
            || args.xop_pvm2_packer.is_none())
    {
        anyhow::bail!(
            "Asset Pack 需要 --engine mocika、--profile strict 和内置/自定义 PVM2 Packer，以便 PAS2 密钥与单 Stub 生命周期绑定"
        );
    }
    if matches!(args.engine, ProtectionEngineArg::Xop) {
        if args.xop_pvm2_packer.is_some() || !args.xop_true_vmp_prefix.is_empty() {
            anyhow::bail!(
                "--xop-pvm2-packer/--xop-true-vmp-prefix 只用于 --engine mocika；--engine xop 使用独立 Xop 单壳"
            );
        }
        let packer = args
            .xop_packer
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--engine xop 必须提供 --xop-packer"))?;
        let shell_dir = args
            .xop_shell_dir
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--engine xop 必须提供 --xop-shell-dir"))?;
        if !packer.is_file() {
            anyhow::bail!("Xop Packer JAR 不存在：{}", packer.display());
        }
        if !shell_dir.is_dir() {
            anyhow::bail!("Xop shell-files 目录不存在：{}", shell_dir.display());
        }
    }
    if args.runtime_cert_sha256.is_none() && !args.allow_upload_cert_binding {
        anyhow::bail!(
            "protect-aab 默认要求最终设备/Play App Signing SHA-256；仅本地实验可显式使用 --allow-upload-cert-binding"
        );
    }
    let play_runtime_binding = args.runtime_cert_sha256.is_some();
    let pass = args.ks_pass.clone();
    let key_pass = args.key_pass.clone().unwrap_or_else(|| pass.clone());
    let runtime_cert_sha256 = match args.runtime_cert_sha256.as_deref() {
        Some(value) => Some(normalize_runtime_certificate(value)?),
        None => Some(extract_keystore_cert_fingerprint(
            &args.ks,
            &args.key_alias,
            &pass,
            Some(match args.ks_type {
                KeystoreTypeArg::Jks => "JKS",
                KeystoreTypeArg::Pkcs12 => "PKCS12",
            }),
        )?),
    };
    if args.install_apks && args.apks_output.is_none() {
        anyhow::bail!("--install-apks 必须与 --apks-output 一起使用");
    }
    if args.device_spec.is_some() && args.apks_output.is_none() {
        anyhow::bail!("--device-spec 必须与 --apks-output 一起使用");
    }
    if args.device_id.is_some() && !args.install_apks {
        anyhow::bail!("--device-id 必须与 --install-apks 一起使用");
    }
    if args.smoke_package.is_some() && !args.install_apks {
        anyhow::bail!("--smoke-package 必须与 --install-apks 一起使用");
    }

    let temp = shield_core::utils::create_temp_dir("mocika-protect-aab-")?;
    let universal_apks = temp.path().join("input.apks");
    let universal_apk = temp.path().join("input-universal.apk");
    let protected_unsigned = temp.path().join("protected-unsigned.apk");
    let protected_apk = temp.path().join("protected.apk");
    let proto_apk = temp.path().join("protected-proto.apk");
    let module_dir = temp.path().join("base-module");
    let module_zip = temp.path().join("base.zip");
    let extra_modules_root = temp.path().join("extra-modules");
    let bundle_config = temp.path().join("BundleConfig.pb.json");
    let unsigned_aab = temp.path().join("protected-unsigned.aab");

    let extra_module_dirs = extract_aab_modules(
        &args.input,
        &extra_modules
            .iter()
            .map(|module| module.name.as_str())
            .collect::<Vec<_>>(),
        &extra_modules_root,
    )?;
    let mut has_external_assets = false;
    let mut has_external_native = false;
    for (name, directory) in &extra_module_dirs {
        if asset_pack_modules.iter().any(|module| module == name) {
            if !directory.join("assets").is_dir() || directory.join("lib").is_dir() {
                anyhow::bail!("Asset Pack {name} 的模块结构不受支持");
            }
            has_external_assets = true;
        } else {
            has_external_assets |= directory.join("assets").is_dir();
            has_external_native |= directory.join("lib").is_dir();
        }
    }
    if (has_external_assets || has_external_native)
        && (!matches!(args.profile, ProtectionProfileArg::Strict) || args.xop_pvm2_packer.is_none())
    {
        anyhow::bail!(
            "dynamic-feature/Asset Pack 的 assets/lib 需要 strict 与内置/自定义 PVM2 Packer，拒绝留下明文模块"
        );
    }
    if deferred_asset_pack_count > 0 && !args.play_delivery_adapter {
        // This is also checked while classifying manifests; keep the trust-boundary
        // guard next to the actual external-reader option.
        anyhow::bail!("fast-follow/on-demand Asset Pack 必须显式启用 --play-delivery-adapter");
    }
    if !asset_pack_modules.is_empty() && !has_external_assets {
        anyhow::bail!("AAB Asset Pack 不包含可保护的 assets");
    }
    for (name, directory) in &extra_module_dirs {
        if !asset_pack_modules.iter().any(|module| module == name)
            && directory.join("root").is_dir()
        {
            anyhow::bail!(
                "dynamic-feature {name} 含 root 文件；当前没有安全的跨 split 文件语义适配器"
            );
        }
    }

    run_bundletool_dump_config(&args.bundletool, &args.input, &bundle_config)?;

    on_progress(
        "BuildUniversalApk",
        "从 AAB 生成受控的 universal APK 工作副本",
    );
    ensure_aab_not_cancelled(&cancel)?;
    run_bundletool_build_apks(
        &args.bundletool,
        &args.input,
        &universal_apks,
        "universal",
        None,
        Some(&args.ks),
        Some(&args.key_alias),
        Some(&pass),
        Some(&key_pass),
        (inspection.modules.len() > 1).then_some("base"),
    )?;
    extract_zip_entry(&universal_apks, "universal.apk", &universal_apk)?;

    match args.engine {
        ProtectionEngineArg::Mocika => {
            let protect_opts = ProtectOptions {
                excluded_abis: args.exclude_abis.clone(),
                input: universal_apk,
                output: protected_unsigned.clone(),
                apktool_path: args.apktool.clone(),
                resources_path: args.resources.clone(),
                apksigner_path: args.apksigner.clone(),
                expected_output_cert_fingerprint: None,
                runtime_cert_fingerprint: runtime_cert_sha256.clone(),
                environment_policy: match args.environment_policy {
                    EnvironmentPolicyArg::Compatible => EnvironmentPolicy::Compatible,
                    EnvironmentPolicyArg::Strict => EnvironmentPolicy::Strict,
                },
                protection_profile: match args.profile {
                    ProtectionProfileArg::Compat => ProtectionProfile::Compat,
                    ProtectionProfileArg::Balanced => ProtectionProfile::Balanced,
                    ProtectionProfileArg::Strict => ProtectionProfile::Strict,
                },
                ai_resistance: match args.ai_resistance {
                    AiResistanceArg::Off => AiResistance::Off,
                    AiResistanceArg::Balanced => AiResistance::Balanced,
                    AiResistanceArg::High => AiResistance::High,
                },
                xop_pvm2_packer_path: args.xop_pvm2_packer.clone(),
                xop_true_vmp_prefixes: args.xop_true_vmp_prefix.clone(),
                external_pvm2_dex_dir: (!extra_module_dirs.is_empty())
                    .then_some(extra_modules_root.clone()),
                external_pas2_assets_dir: has_external_assets.then_some(extra_modules_root.clone()),
                deferred_pas2_asset_modules: deferred_asset_modules.clone(),
                allow_external_pas2_reader: deferred_asset_pack_count > 0
                    && args.play_delivery_adapter,
                external_native_lib_dir: has_external_native.then_some(extra_modules_root.clone()),
            };
            let progress = Arc::clone(&on_progress);
            protect_apk(
                &protect_opts,
                move |event| {
                    let step = format!("{:?}", event.step);
                    progress(&step, &event.message);
                },
                Arc::clone(&cancel),
            )?;
        }
        ProtectionEngineArg::Xop => {
            let packer = args
                .xop_packer
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("--engine xop 必须提供 --xop-packer"))?;
            let shell_dir = args
                .xop_shell_dir
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("--engine xop 必须提供 --xop-shell-dir"))?;
            run_xop_packer(
                &universal_apk,
                &protected_unsigned,
                packer,
                shell_dir,
                args.xop_profile,
                args.ai_resistance,
                runtime_cert_sha256.as_deref(),
                &[],
                &[],
                &[],
                args.xop_no_protect_so,
                args.xop_encrypt_assets,
                args.xop_enable_res_protect,
                args.xop_detect_proxy,
                args.xop_rasp_action,
                args.json,
            )?;
        }
    }

    ensure_aab_not_cancelled(&cancel)?;
    let signing_progress = Arc::clone(&on_progress);
    sign_apk_with_progress(
        &SignOptions {
            apk_path: protected_unsigned,
            output_path: Some(protected_apk.clone()),
            keystore_path: args.ks.clone(),
            key_alias: args.key_alias.clone(),
            keystore_password: pass.clone(),
            key_password: key_pass.clone(),
            apksigner_path: args.apksigner,
            keystore_type: match args.ks_type {
                KeystoreTypeArg::Jks => KeystoreType::Jks,
                KeystoreTypeArg::Pkcs12 => KeystoreType::Pkcs12,
            },
            signing_versions: SigningVersions {
                v1: true,
                v2: true,
                v3: true,
                v4: false,
            },
        },
        move |step| {
            signing_progress("SignApk", signing_step_message(step));
            Ok(())
        },
    )?;

    on_progress("RebuildBundle", "重建 protobuf 模块并合并 AAB");
    ensure_aab_not_cancelled(&cancel)?;
    run_aapt2_proto_convert(&args.aapt2, &protected_apk, &proto_apk)?;
    extract_proto_apk_module(&proto_apk, &module_dir)?;
    zip_bundle_module(&module_dir, &module_zip)?;
    let mut module_zips = vec![module_zip];
    for (name, directory) in &extra_module_dirs {
        let output = temp.path().join(format!("{name}.zip"));
        zip_bundle_module(directory, &output)?;
        module_zips.push(output);
    }
    run_bundletool_build_bundle(
        &args.bundletool,
        &module_zips,
        Some(&bundle_config),
        &unsigned_aab,
    )?;
    on_progress("SignAab", "使用所选上传证书签署 AAB");
    ensure_aab_not_cancelled(&cancel)?;
    sign_aab_with_jarsigner(
        &unsigned_aab,
        &args.output,
        &args.ks,
        &args.key_alias,
        &pass,
        &key_pass,
        args.ks_type,
    )?;
    on_progress("ValidateBundle", "使用 bundletool 校验最终 AAB");
    ensure_aab_not_cancelled(&cancel)?;
    run_bundletool_validate(&args.bundletool, &args.output)?;
    let mut device_install = "not-requested";
    let mut smoke_test = "not-requested";
    if let Some(apks_output) = args.apks_output.as_ref() {
        on_progress("BuildApks", "生成本地 split APKS 验证包");
        ensure_aab_not_cancelled(&cancel)?;
        if args.install_apks {
            let upload_cert = extract_keystore_cert_fingerprint(
                &args.ks,
                &args.key_alias,
                &pass,
                Some(match args.ks_type {
                    KeystoreTypeArg::Jks => "JKS",
                    KeystoreTypeArg::Pkcs12 => "PKCS12",
                }),
            )?;
            if runtime_cert_sha256.as_deref() != Some(upload_cert.as_str()) {
                anyhow::bail!(
                    "不能安装本地 APKS：运行时绑定证书不是 upload key；Play App Signing 证书只能在 Play 分发后验证"
                );
            }
        }
        run_bundletool_build_apks(
            &args.bundletool,
            &args.output,
            apks_output,
            "default",
            args.device_spec.as_deref(),
            Some(&args.ks),
            Some(&args.key_alias),
            Some(&pass),
            Some(&key_pass),
            None,
        )?;
        if args.install_apks {
            run_install_apks(
                apks_output.clone(),
                args.bundletool.clone(),
                args.device_id.as_deref(),
            )?;
            device_install = "completed";
            if let Some(package) = args.smoke_package.as_deref() {
                run_device_smoke(package, args.device_id.as_deref())?;
                smoke_test = "completed";
            }
        }
    }
    if args.json {
        let pvm2_in_mocika_stub =
            matches!(args.engine, ProtectionEngineArg::Mocika) && args.xop_pvm2_packer.is_some();
        println!(
            "{}",
            serde_json::json!({
                "path": args.output,
                "module_processing": if extra_module_dirs.is_empty() {
                    "single-base-transformed"
                } else if !asset_pack_modules.is_empty() {
                    "base-dynamic-and-play-delivery-transformed"
                } else {
                    "base-and-dynamic-feature-transformed"
                },
                "engine": match args.engine {
                    ProtectionEngineArg::Mocika => "mocika",
                    ProtectionEngineArg::Xop => "xop-single-shell",
                },
                "protection_status": match args.engine {
                    ProtectionEngineArg::Mocika => "mocika-protected",
                    ProtectionEngineArg::Xop => "xop-protected",
                },
                "play_uploadable": play_runtime_binding,
                "play_uploadable_reason": if play_runtime_binding {
                    "runtime_certificate_bound"
                } else {
                    "upload_key_only_binding"
                },
                "play_validation": "local-bundletool-only",
                "runtime_binding_ready": true,
                "runtime_certificate": if play_runtime_binding {
                    "play-app-signing-provided"
                } else {
                    "upload-key-local-only"
                },
                "fusion_status": if matches!(args.engine, ProtectionEngineArg::Xop) {
                    "not-applicable-xop-single-shell"
                } else if pvm2_in_mocika_stub {
                    "xop-pvm2-embedded"
                } else {
                    "xop-contract-only"
                },
                "pvm2_in_mocika_stub": pvm2_in_mocika_stub,
                "apks_output": args.apks_output,
                "device_spec": args.device_spec,
                "device_install": device_install,
                "smoke_test": smoke_test,
                "dynamic_modules": dynamic_module_count > 0,
                "dynamic_module_count": dynamic_module_count,
                "on_demand_dynamic_module_count": on_demand_dynamic_count,
                "conditional_dynamic_module_count": conditional_dynamic_count,
                "asset_pack_modules": asset_pack_modules.len(),
                "asset_pack_delivery": if asset_pack_modules.is_empty() {
                    "none"
                } else if deferred_asset_pack_count > 0 {
                    "install-time-fast-follow-on-demand-with-adapter"
                } else {
                    "install-time-fused"
                },
                "play_delivery_adapter": args.play_delivery_adapter,
                "external_feature_assets": has_external_assets,
                "external_feature_native": has_external_native,
                "deferred_asset_module_count": deferred_asset_modules.len()
            })
        );
    } else {
        println!(
            "✓ 已生成通过本地 bundletool 校验的受保护 AAB（模块 {}，引擎={}，仍需 Play 内测）：{}",
            inspection.modules.len(),
            match args.engine {
                ProtectionEngineArg::Mocika => "mocika",
                ProtectionEngineArg::Xop => "xop-single-shell",
            },
            args.output.display()
        );
    }
    Ok(())
}

fn ensure_aab_not_cancelled(cancel: &AtomicBool) -> Result<()> {
    if cancel.load(Ordering::Relaxed) {
        anyhow::bail!("已取消")
    }
    Ok(())
}

// ponytail: this mirrors the external Packer CLI exactly; a second options
// object would only duplicate the existing clap/config structures.
#[allow(clippy::too_many_arguments)]
fn run_xop_packer(
    input: &Path,
    output: &Path,
    packer: &Path,
    shell_dir: &Path,
    profile: XopProfileArg,
    ai_resistance: AiResistanceArg,
    runtime_cert_sha256: Option<&str>,
    hollow_prefix: &[String],
    vmp_prefix: &[String],
    true_vmp_prefix: &[String],
    no_protect_so: bool,
    encrypt_assets: bool,
    enable_res_protect: bool,
    detect_proxy: bool,
    rasp_action: u8,
    json: bool,
) -> Result<()> {
    if !input.is_file() {
        anyhow::bail!("输入 APK 不存在：{}", input.display());
    }
    if input == output {
        anyhow::bail!("输入和输出 APK 不能是同一路径");
    }
    if !packer.is_file() {
        anyhow::bail!("Xop Packer JAR 不存在：{}", packer.display());
    }
    if !shell_dir.is_dir() {
        anyhow::bail!("Xop shell-files 目录不存在：{}", shell_dir.display());
    }
    let input_check = check_apk(input, None)?;
    if input_check.already_protected {
        anyhow::bail!("输入 APK 已包含 Shellsmith/Xop 保护载荷，禁止重复加固");
    }
    if !input_check.is_signed {
        anyhow::bail!("Xop Packer 需要已签名输入 APK");
    }

    let java = shield_core::utils::find_java()?;
    let mut command_args = vec![
        "-jar".to_string(),
        packer.to_string_lossy().into_owned(),
        input.to_string_lossy().into_owned(),
        "-o".to_string(),
        output.to_string_lossy().into_owned(),
        "--shell-dir".to_string(),
        shell_dir.to_string_lossy().into_owned(),
        "--profile".to_string(),
        profile.as_str().to_string(),
        "--rasp-action".to_string(),
        rasp_action.to_string(),
    ];
    for prefix in hollow_prefix {
        command_args.extend(["--hollow-prefix".to_string(), prefix.clone()]);
    }
    for prefix in vmp_prefix {
        command_args.extend(["--vmp-prefix".to_string(), prefix.clone()]);
    }
    for prefix in true_vmp_prefix {
        command_args.extend(["--true-vmp-prefix".to_string(), prefix.clone()]);
    }
    match ai_resistance {
        AiResistanceArg::Off => command_args.extend([
            "--no-payment-auto-vmp".to_string(),
            "--no-industry-auto-vmp".to_string(),
        ]),
        AiResistanceArg::Balanced => {}
        AiResistanceArg::High => {
            command_args.extend(["--auto-true-vmp".to_string(), "both".to_string()])
        }
    }
    if no_protect_so {
        command_args.push("--no-protect-so".to_string());
    }
    if encrypt_assets {
        command_args.push("--encrypt-assets".to_string());
    }
    if enable_res_protect {
        command_args.push("--enable-res-protect".to_string());
    }
    if detect_proxy {
        command_args.push("--detect-proxy".to_string());
    }
    if json {
        command_args.push("--json-progress".to_string());
    }
    if let Some(cert) = runtime_cert_sha256 {
        command_args.extend(["--cert-sha256".to_string(), cert.to_string()]);
    }

    let result = shield_core::utils::no_window_command(&java)
        .args(command_args.iter().map(String::as_str))
        .output()?;
    if !result.status.success() {
        let detail = if result.stderr.is_empty() {
            String::from_utf8_lossy(&result.stdout)
        } else {
            String::from_utf8_lossy(&result.stderr)
        };
        anyhow::bail!("Xop Packer 执行失败：{}", detail.trim());
    }
    if !output.is_file() {
        anyhow::bail!("Xop Packer 未生成输出 APK：{}", output.display());
    }
    Ok(())
}

/// Run Xop as the selected APK engine. The output is Xop-owned: Shellsmith is not
/// invoked afterwards, which preserves the single-shell invariant.
pub(crate) fn run_protect_xop(args: ProtectXopArgs) -> Result<()> {
    if args.json {
        set_json_mode(true);
    }
    if !args.input.is_file() {
        anyhow::bail!("输入 APK 不存在：{}", args.input.display());
    }
    if args.input == args.output {
        anyhow::bail!("输入和输出 APK 不能是同一路径");
    }
    if !args.packer.is_file() {
        anyhow::bail!("Xop Packer JAR 不存在：{}", args.packer.display());
    }
    if !args.shell_dir.is_dir() {
        anyhow::bail!("Xop shell-files 目录不存在：{}", args.shell_dir.display());
    }
    let signing = match (&args.ks, &args.key_alias, &args.ks_pass) {
        (Some(ks), Some(alias), Some(pass)) => {
            if !ks.is_file() {
                anyhow::bail!("Xop 输出 keystore 不存在：{}", ks.display());
            }
            let key_pass = args.key_pass.clone().unwrap_or_else(|| pass.clone());
            let cert = extract_keystore_cert_fingerprint(
                ks,
                alias,
                pass,
                Some(match args.ks_type {
                    KeystoreTypeArg::Jks => "JKS",
                    KeystoreTypeArg::Pkcs12 => "PKCS12",
                }),
            )?;
            Some((alias.clone(), pass.clone(), key_pass, cert))
        }
        (None, None, None) if args.allow_unsigned => None,
        _ => anyhow::bail!(
            "protect-xop 默认要求可安装的签名输出；请提供 --ks、--key-alias、--ks-pass，或显式使用 --allow-unsigned"
        ),
    };
    let temp = if signing.is_some() {
        Some(shield_core::utils::create_temp_dir("xop-unsigned-")?)
    } else {
        None
    };
    let packer_output = temp
        .as_ref()
        .map(|dir| dir.path().join("xop-unsigned.apk"))
        .unwrap_or_else(|| args.output.clone());
    run_xop_packer(
        &args.input,
        &packer_output,
        &args.packer,
        &args.shell_dir,
        args.profile,
        args.ai_resistance,
        signing.as_ref().map(|(_, _, _, cert)| cert.as_str()),
        &args.hollow_prefix,
        &args.vmp_prefix,
        &args.true_vmp_prefix,
        args.no_protect_so,
        args.encrypt_assets,
        args.enable_res_protect,
        args.detect_proxy,
        args.rasp_action,
        args.json,
    )?;
    let signed = if let Some((alias, store_pass, key_pass, cert)) = signing {
        sign_apk_with_progress(
            &SignOptions {
                apk_path: packer_output.clone(),
                output_path: Some(args.output.clone()),
                keystore_path: args.ks.clone().expect("validated Xop keystore"),
                key_alias: alias,
                keystore_password: store_pass,
                key_password: key_pass,
                apksigner_path: args.apksigner.clone(),
                keystore_type: match args.ks_type {
                    KeystoreTypeArg::Jks => KeystoreType::Jks,
                    KeystoreTypeArg::Pkcs12 => KeystoreType::Pkcs12,
                },
                signing_versions: SigningVersions {
                    v1: true,
                    v2: true,
                    v3: true,
                    v4: false,
                },
            },
            |_| Ok(()),
        )?;
        let actual = extract_apk_cert_fingerprint(&args.output, args.apksigner.as_deref())?;
        if shield_core::normalize_fingerprint(&actual) != shield_core::normalize_fingerprint(&cert)
        {
            anyhow::bail!("Xop 输出签名证书与运行时绑定证书不一致");
        }
        true
    } else {
        false
    };
    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "path": args.output,
                "engine": "xop",
                "shell_mode": "xop-single-shell",
                "ai_resistance": ai_resistance_name(args.ai_resistance),
                "pvm2": !matches!(args.ai_resistance, AiResistanceArg::Off),
                "native_so": !args.no_protect_so,
                "signed": signed,
                "status": "xop-single-shell-ready",
                "fusion_status": "not-applicable-xop-single-shell",
                "pvm2_in_mocika_stub": false
            })
        );
    } else {
        println!(
            "✓ 已生成 Xop 单壳 APK：{}（签名={}，未与 Shellsmith 壳叠加）",
            args.output.display(),
            if signed { "yes" } else { "no" },
        );
    }
    Ok(())
}

fn ai_resistance_name(value: AiResistanceArg) -> &'static str {
    match value {
        AiResistanceArg::Off => "off",
        AiResistanceArg::Balanced => "balanced",
        AiResistanceArg::High => "high",
    }
}

fn normalize_runtime_certificate(value: &str) -> Result<String> {
    let fingerprint = shield_core::normalize_fingerprint(value);
    if fingerprint.len() != 64 || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        anyhow::bail!("--runtime-cert-sha256 必须是 64 位十六进制 SHA-256")
    }
    Ok(fingerprint)
}

fn extract_zip_entry(archive_path: &Path, entry_name: &str, output: &Path) -> Result<()> {
    let file = std::fs::File::open(archive_path)?;
    let mut archive = zip::ZipArchive::new(file)?;
    let mut entry = archive
        .by_name(entry_name)
        .map_err(|_| anyhow::anyhow!("APKS 中未找到 {entry_name}"))?;
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut out = std::fs::File::create(output)?;
    std::io::copy(&mut entry, &mut out)?;
    Ok(())
}

fn run_aapt2_proto_convert(aapt2: &Path, input: &Path, output: &Path) -> Result<()> {
    let result = shield_core::utils::no_window_command(aapt2)
        .args([
            "convert",
            "--output-format",
            "proto",
            "-o",
            output.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .output()?;
    if !result.status.success() {
        anyhow::bail!(
            "aapt2 proto 转换失败：{}",
            String::from_utf8_lossy(&result.stderr).trim()
        );
    }
    Ok(())
}

fn extract_proto_apk_module(apk: &Path, module: &Path) -> Result<()> {
    std::fs::create_dir_all(module)?;
    let file = std::fs::File::open(apk)?;
    let mut archive = zip::ZipArchive::new(file)?;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let name = entry
            .enclosed_name()
            .ok_or_else(|| anyhow::anyhow!("protobuf APK 包含越界路径"))?
            .to_string_lossy()
            .replace('\\', "/");
        if name.is_empty() || name.ends_with('/') {
            continue;
        }
        let (target_root, relative) = if name == "AndroidManifest.xml" {
            ("manifest", name.as_str())
        } else if name == "resources.pb" {
            ("", name.as_str())
        } else if name.starts_with("classes") && name.ends_with(".dex") {
            ("dex", name.as_str())
        } else if name.starts_with("assets/")
            || name.starts_with("lib/")
            || name.starts_with("res/")
        {
            ("", name.as_str())
        } else if name.starts_with("META-INF/") {
            continue;
        } else {
            ("root", name.as_str())
        };
        let destination = if target_root.is_empty() {
            module.join(relative)
        } else if target_root == "manifest" {
            module.join("manifest/AndroidManifest.xml")
        } else {
            module.join(target_root).join(relative)
        };
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut out = std::fs::File::create(destination)?;
        std::io::copy(&mut entry, &mut out)?;
    }
    if !module.join("manifest/AndroidManifest.xml").is_file()
        || !module.join("resources.pb").is_file()
        || !module.join("dex/classes.dex").is_file()
    {
        anyhow::bail!("protobuf APK 缺少 bundle base module 所需的 manifest/resources.pb/dex");
    }
    Ok(())
}

fn extract_aab_modules(
    input: &Path,
    names: &[&str],
    root: &Path,
) -> Result<Vec<(String, PathBuf)>> {
    let requested = names
        .iter()
        .map(|name| name.to_string())
        .collect::<std::collections::BTreeSet<_>>();
    if requested.is_empty() {
        return Ok(Vec::new());
    }
    for name in &requested {
        if name.is_empty()
            || !name
                .chars()
                .all(|value| value.is_ascii_alphanumeric() || value == '_')
        {
            anyhow::bail!("AAB 模块名非法：{name}");
        }
    }
    std::fs::create_dir_all(root)?;
    let file = std::fs::File::open(input)?;
    let mut archive = zip::ZipArchive::new(file)?;
    let mut seen = std::collections::BTreeSet::new();
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let Some((module, relative)) = entry.name().split_once('/') else {
            continue;
        };
        if !requested.contains(module) || relative.is_empty() {
            continue;
        }
        let relative_path = Path::new(relative);
        if relative_path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            anyhow::bail!("AAB 模块条目路径非法：{}", entry.name());
        }
        if entry
            .unix_mode()
            .is_some_and(|mode| mode & 0o170000 == 0o120000)
        {
            anyhow::bail!("AAB 模块不允许符号链接：{}", entry.name());
        }
        let destination = root.join(module).join(relative_path);
        if entry.is_dir() {
            std::fs::create_dir_all(&destination)?;
            continue;
        }
        if !seen.insert((module.to_string(), relative.to_string())) {
            anyhow::bail!("AAB 模块包含重复条目：{}", entry.name());
        }
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut output = std::fs::File::create(&destination)?;
        std::io::copy(&mut entry, &mut output)?;
    }
    requested
        .into_iter()
        .map(|name| {
            let directory = root.join(&name);
            if !directory.join("manifest/AndroidManifest.xml").is_file() {
                anyhow::bail!("AAB 模块 {name} 缺少 Manifest");
            }
            Ok((name, directory))
        })
        .collect()
}

fn zip_bundle_module(module: &Path, output: &Path) -> Result<()> {
    let mut files = Vec::new();
    collect_module_files(module, &mut files)?;
    files.sort();
    let file = std::fs::File::create(output)?;
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default();
    for path in files {
        let relative = path
            .strip_prefix(module)
            .map_err(|_| anyhow::anyhow!("模块文件路径超出模块目录"))?;
        let name = relative.to_string_lossy().replace('\\', "/");
        zip.start_file(name, options)?;
        let mut input = std::fs::File::open(path)?;
        std::io::copy(&mut input, &mut zip)?;
    }
    zip.finish()?;
    Ok(())
}

fn collect_module_files(current: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_module_files(&path, files)?;
        } else if file_type.is_file() {
            files.push(path);
        } else {
            anyhow::bail!("模块目录包含不支持的文件类型：{}", path.display());
        }
    }
    Ok(())
}

fn run_bundletool_build_bundle(
    bundletool: &Path,
    module_zips: &[PathBuf],
    config: Option<&Path>,
    output: &Path,
) -> Result<()> {
    let java = shield_core::utils::find_java()?;
    if module_zips.is_empty() || module_zips.iter().any(|path| !path.is_file()) {
        anyhow::bail!("bundletool build-bundle 模块 ZIP 缺失");
    }
    let modules = module_zips
        .iter()
        .map(|path| path.to_string_lossy())
        .collect::<Vec<_>>()
        .join(",");
    let mut args = vec![
        "-jar".to_string(),
        bundletool.to_string_lossy().into_owned(),
        "build-bundle".to_string(),
        format!("--modules={modules}"),
        format!("--output={}", output.display()),
    ];
    if let Some(config) = config {
        args.push(format!("--config={}", config.display()));
    }
    let result = shield_core::utils::no_window_command(&java)
        .args(args.iter().map(String::as_str))
        .output()?;
    if !result.status.success() {
        anyhow::bail!(
            "bundletool build-bundle 失败：{}",
            String::from_utf8_lossy(&result.stderr).trim()
        );
    }
    Ok(())
}

fn run_bundletool_dump_config(bundletool: &Path, bundle: &Path, output: &Path) -> Result<()> {
    let java = shield_core::utils::find_java()?;
    let result = shield_core::utils::no_window_command(&java)
        .arg("-jar")
        .arg(bundletool)
        .arg("dump")
        .arg("config")
        .arg(format!("--bundle={}", bundle.display()))
        .output()?;
    if !result.status.success() {
        anyhow::bail!(
            "bundletool dump config 失败：{}",
            String::from_utf8_lossy(&result.stderr).trim()
        );
    }
    validate_bundle_config_json(&result.stdout)?;
    std::fs::write(output, result.stdout)?;
    Ok(())
}

fn run_bundletool_dump_manifest(bundletool: &Path, bundle: &Path, module: &str) -> Result<String> {
    let java = shield_core::utils::find_java()?;
    let output = shield_core::utils::no_window_command(&java)
        .arg("-jar")
        .arg(bundletool)
        .arg("dump")
        .arg("manifest")
        .arg(format!("--bundle={}", bundle.display()))
        .arg(format!("--module={module}"))
        .output()?;
    if !output.status.success() {
        anyhow::bail!(
            "bundletool 读取模块 {module} Manifest 失败：{}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    String::from_utf8(output.stdout)
        .map_err(|_| anyhow::anyhow!("bundletool 输出的模块 {module} Manifest 不是 UTF-8"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AssetPackDelivery {
    InstallTimeFused,
    FastFollow,
    OnDemand,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DynamicFeatureDelivery {
    InstallTime,
    Conditional,
    OnDemand,
}

fn validate_asset_pack_manifest(
    module: &str,
    manifest: &str,
    play_delivery_adapter: bool,
) -> Result<AssetPackDelivery> {
    if !manifest.contains("dist:type=\"asset-pack\"") {
        anyhow::bail!("AAB 模块 {module} 不是 Asset Pack");
    }
    let delivery = if manifest.contains("<dist:fast-follow") {
        AssetPackDelivery::FastFollow
    } else if manifest.contains("<dist:on-demand") {
        AssetPackDelivery::OnDemand
    } else if manifest.contains("<dist:install-time") {
        AssetPackDelivery::InstallTimeFused
    } else {
        anyhow::bail!("Asset Pack {module} 缺少可识别的 delivery 类型");
    };
    if matches!(delivery, AssetPackDelivery::InstallTimeFused)
        && !manifest.contains("<dist:fusing dist:include=\"true\"")
    {
        anyhow::bail!("install-time Asset Pack {module} 必须允许 fusing");
    }
    if !matches!(delivery, AssetPackDelivery::InstallTimeFused) && !play_delivery_adapter {
        anyhow::bail!(
            "Asset Pack {module} 使用 fast-follow/on-demand；业务必须接入 MocikaPlayDelivery 并显式传入 --play-delivery-adapter"
        );
    }
    Ok(delivery)
}

fn validate_dynamic_feature_manifest(
    module: &str,
    manifest: &str,
) -> Result<DynamicFeatureDelivery> {
    if !manifest.contains("android:isFeatureSplit=\"true\"")
        || manifest.contains("dist:type=\"asset-pack\"")
    {
        anyhow::bail!("AAB 代码模块 {module} 不是可识别的 dynamic-feature");
    }
    if manifest.contains("<dist:on-demand") {
        return Ok(DynamicFeatureDelivery::OnDemand);
    }
    if !manifest.contains("<dist:install-time") {
        anyhow::bail!("dynamic-feature {module} 缺少 install-time/on-demand delivery");
    }
    if manifest.contains("<dist:conditions") {
        return Ok(DynamicFeatureDelivery::Conditional);
    }
    if !manifest.contains("<dist:fusing dist:include=\"true\"") {
        anyhow::bail!("无条件 install-time dynamic-feature {module} 必须允许 fusing");
    }
    Ok(DynamicFeatureDelivery::InstallTime)
}

fn validate_bundle_config_json(contents: &[u8]) -> Result<()> {
    let value: serde_json::Value = serde_json::from_slice(contents)
        .map_err(|_| anyhow::anyhow!("bundletool 未输出有效的 BundleConfig JSON"))?;
    if !value.is_object() {
        anyhow::bail!("bundletool 输出的 BundleConfig JSON 不是对象");
    }
    Ok(())
}

fn sign_aab_with_jarsigner(
    input: &Path,
    output: &Path,
    keystore: &Path,
    alias: &str,
    store_pass: &str,
    key_pass: &str,
    keystore_type: KeystoreTypeArg,
) -> Result<()> {
    let java_home = shield_core::utils::find_java()?;
    let jarsigner = java_home
        .parent()
        .map(|dir| {
            dir.join(if cfg!(windows) {
                "jarsigner.exe"
            } else {
                "jarsigner"
            })
        })
        .filter(|path| path.is_file())
        .unwrap_or_else(|| PathBuf::from("jarsigner"));
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let args = vec![
        "-keystore",
        keystore.to_str().unwrap(),
        "-storetype",
        match keystore_type {
            KeystoreTypeArg::Jks => "JKS",
            KeystoreTypeArg::Pkcs12 => "PKCS12",
        },
        "-storepass",
        store_pass,
        "-keypass",
        key_pass,
        "-signedjar",
        output.to_str().unwrap(),
        input.to_str().unwrap(),
        alias,
    ];
    let result = shield_core::utils::no_window_command(&jarsigner)
        .args(args)
        .output()?;
    if !result.status.success() {
        anyhow::bail!(
            "jarsigner 签署 AAB 失败：{}",
            String::from_utf8_lossy(&result.stderr).trim()
        );
    }
    Ok(())
}

pub(crate) fn run_sign(args: ResolvedSignArgs) -> Result<()> {
    let options = SignOptions {
        apk_path: args.input,
        output_path: Some(args.output),
        keystore_path: args.keystore,
        key_alias: args.key_alias,
        keystore_password: args.keystore_password,
        key_password: args.key_password,
        apksigner_path: args.apksigner,
        keystore_type: match args.keystore_type {
            KeystoreTypeArg::Jks => KeystoreType::Jks,
            KeystoreTypeArg::Pkcs12 => KeystoreType::Pkcs12,
        },
        signing_versions: SigningVersions {
            v1: args.v1,
            v2: args.v2,
            v3: args.v3,
            v4: args.v4,
        },
    };
    sign_apk_with_progress(&options, |step| {
        if args.json {
            println!(
                "{}",
                progress_event_json(signing_step_name(step), signing_step_message(step))
            );
            let _ = std::io::stdout().flush();
        }
        Ok(())
    })?;
    if args.json {
        println!("{}", done_event_json());
    } else {
        println!("{}", "✓ 签名完成".green().bold());
    }
    Ok(())
}

fn signing_step_name(step: SigningProgressStep) -> &'static str {
    match step {
        SigningProgressStep::Prepare => "prepare",
        SigningProgressStep::Align => "align",
        SigningProgressStep::Sign => "sign",
    }
}

fn signing_step_message(step: SigningProgressStep) -> &'static str {
    match step {
        SigningProgressStep::Prepare => "准备签名环境",
        SigningProgressStep::Align => "对齐 APK",
        SigningProgressStep::Sign => "写入 APK 签名",
    }
}

pub(crate) fn run_check_apk(path: PathBuf) -> Result<String> {
    match check_apk(&path, None) {
        Ok(result) => {
            let cert_fingerprint = if result.is_signed {
                extract_apk_cert_fingerprint(&path, None).ok()
            } else {
                None
            };
            Ok(apk_check_json(
                result.already_protected,
                result.is_signed,
                cert_fingerprint,
            ))
        }
        Err(err) => Err(err),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run_check_aab(
    path: PathBuf,
    bundletool: Option<PathBuf>,
    apks_output: Option<PathBuf>,
    device_spec: Option<PathBuf>,
    apks_mode: String,
    ks: Option<PathBuf>,
    ks_alias: Option<String>,
    ks_pass: Option<String>,
) -> Result<String> {
    let inspection = inspect_aab(&path)?;
    validate_aab_for_module_processing(&inspection)?;
    if apks_output.is_some() && bundletool.is_none() {
        anyhow::bail!("--apks-output 必须与 --bundletool 一起使用");
    }
    let mut application_id = None;
    let bundletool_status = if let Some(bundletool) = bundletool {
        run_bundletool_validate(&bundletool, &path)?;
        application_id = run_bundletool_dump_manifest(&bundletool, &path, "base")
            .ok()
            .and_then(|manifest| manifest_package(&manifest));
        if let Some(output) = apks_output.as_ref() {
            run_bundletool_build_apks(
                &bundletool,
                &path,
                output,
                &apks_mode,
                device_spec.as_deref(),
                ks.as_deref(),
                ks_alias.as_deref(),
                ks_pass.as_deref(),
                None,
                None,
            )?;
            "validated-and-apks-built"
        } else {
            "validated"
        }
    } else {
        "not-run"
    };
    Ok(serde_json::json!({
        "path": inspection.path,
        "has_base": inspection.has_base,
        "has_bundle_config": inspection.has_bundle_config,
        "modules": inspection.modules,
        "dynamic_feature_modules": inspection.dynamic_feature_modules,
        "module_details": inspection.module_details,
        "dex_entries": inspection.dex_entries,
        "manifest_entries": inspection.manifest_entries,
        "module_processing": "preflight-only",
        "protection_status": "not-transformed",
        "bundletool": bundletool_status,
        "application_id": application_id,
        "apks_output": apks_output,
    })
    .to_string())
}

fn manifest_package(manifest: &str) -> Option<String> {
    let manifest_tag = manifest.find("<manifest").and_then(|start| {
        manifest[start..]
            .find('>')
            .map(|end| &manifest[start..=start + end])
    })?;
    for quote in ['"', '\''] {
        let needle = format!("package={quote}");
        if let Some(start) = manifest_tag.find(&needle) {
            let value = &manifest_tag[start + needle.len()..];
            if let Some(end) = value.find(quote) {
                let package = value[..end].trim();
                if !package.is_empty() {
                    return Some(package.to_string());
                }
            }
        }
    }
    None
}

fn run_bundletool_validate(bundletool: &std::path::Path, bundle: &std::path::Path) -> Result<()> {
    if !bundletool.is_file() {
        anyhow::bail!("bundletool JAR 不存在：{}", bundletool.display());
    }
    let java = shield_core::utils::find_java()?;
    let output = shield_core::utils::no_window_command(&java)
        .args([
            "-jar",
            bundletool.to_str().unwrap(),
            "validate",
            "--bundle",
            bundle.to_str().unwrap(),
        ])
        .output()?;
    if !output.status.success() {
        anyhow::bail!(
            "bundletool validate 失败：{}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_bundletool_build_apks(
    bundletool: &std::path::Path,
    bundle: &std::path::Path,
    output: &std::path::Path,
    mode: &str,
    device_spec: Option<&std::path::Path>,
    keystore: Option<&std::path::Path>,
    key_alias: Option<&str>,
    keystore_password: Option<&str>,
    key_password: Option<&str>,
    modules: Option<&str>,
) -> Result<()> {
    if !matches!(mode, "universal" | "default") {
        anyhow::bail!("--apks-mode 仅支持 universal 或 default");
    }
    let (keystore, key_alias, keystore_password) = match (keystore, key_alias, keystore_password) {
        (Some(ks), Some(alias), Some(pass)) => (ks, alias, pass),
        _ => anyhow::bail!("生成 APKS 需要 --ks、--ks-alias 和 --ks-pass（或环境变量）"),
    };
    if !keystore.is_file() {
        anyhow::bail!("APKS 签名 keystore 不存在：{}", keystore.display());
    }
    if let Some(spec) = device_spec {
        if !spec.is_file() {
            anyhow::bail!("设备规格 JSON 不存在：{}", spec.display());
        }
    }
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let pass_dir = shield_core::utils::create_temp_dir("bundletool-pass-")?;
    let pass_file = pass_dir.path().join("keystore.pass");
    std::fs::write(&pass_file, keystore_password.as_bytes())?;
    let key_pass_file = pass_dir.path().join("key.pass");
    if let Some(key_password) = key_password {
        std::fs::write(&key_pass_file, key_password.as_bytes())?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&pass_file, permissions.clone())?;
        if key_password.is_some() {
            std::fs::set_permissions(&key_pass_file, permissions)?;
        }
    }
    let java = shield_core::utils::find_java()?;
    let mut args = vec![
        "-jar".to_string(),
        bundletool.to_string_lossy().into_owned(),
        "build-apks".to_string(),
        format!("--bundle={}", bundle.display()),
        format!("--output={}", output.display()),
        format!("--mode={mode}"),
        "--overwrite".to_string(),
        format!("--ks={}", keystore.display()),
        format!("--ks-key-alias={key_alias}"),
        format!("--ks-pass=file:{}", pass_file.display()),
    ];
    if key_password.is_some() {
        args.push(format!("--key-pass=file:{}", key_pass_file.display()));
    }
    if let Some(spec) = device_spec {
        args.push(format!("--device-spec={}", spec.display()));
    }
    if let Some(modules) = modules {
        if modules.is_empty()
            || !modules.split(',').all(|module| {
                module
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
            })
        {
            anyhow::bail!("bundletool --modules 包含非法模块名");
        }
        args.push(format!("--modules={modules}"));
    }
    let output_result = shield_core::utils::no_window_command(&java)
        .args(args.iter().map(String::as_str))
        .output()?;
    if !output_result.status.success() {
        anyhow::bail!(
            "bundletool build-apks 失败：{}",
            String::from_utf8_lossy(&output_result.stderr).trim()
        );
    }
    if !output.is_file() {
        anyhow::bail!("bundletool 未生成 APKS：{}", output.display());
    }
    Ok(())
}

pub(crate) fn run_install_apks(
    apks: PathBuf,
    bundletool: PathBuf,
    device_id: Option<&str>,
) -> Result<()> {
    if !apks.is_file() {
        anyhow::bail!("APKS 文件不存在：{}", apks.display());
    }
    if !bundletool.is_file() {
        anyhow::bail!("bundletool JAR 不存在：{}", bundletool.display());
    }
    let java = shield_core::utils::find_java()?;
    let mut args = vec![
        "-jar".to_string(),
        bundletool.to_string_lossy().into_owned(),
        "install-apks".to_string(),
        format!("--apks={}", apks.display()),
    ];
    if let Some(device) = device_id {
        if device.trim().is_empty() {
            anyhow::bail!("--device-id 不能为空");
        }
        args.push(format!("--device-id={device}"));
    }
    let output = shield_core::utils::no_window_command(&java)
        .args(args.iter().map(String::as_str))
        .output()?;
    if !output.status.success() {
        anyhow::bail!(
            "bundletool install-apks 失败：{}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    println!("APKS 已提交到测试设备");
    Ok(())
}

fn run_device_smoke(package: &str, device_id: Option<&str>) -> Result<()> {
    if package.trim().is_empty() || package.split('.').any(|part| part.is_empty()) {
        anyhow::bail!("--smoke-package 必须是非空 Android 包名");
    }
    let adb = std::env::var_os("ANDROID_HOME")
        .map(PathBuf::from)
        .map(|sdk| {
            sdk.join("platform-tools")
                .join(if cfg!(windows) { "adb.exe" } else { "adb" })
        })
        .filter(|path| path.is_file())
        .unwrap_or_else(|| PathBuf::from("adb"));
    let mut base = Vec::new();
    if let Some(device) = device_id {
        if device.trim().is_empty() {
            anyhow::bail!("--device-id 不能为空");
        }
        base.extend(["-s".to_string(), device.to_string()]);
    }
    let mut monkey = base.clone();
    monkey.extend([
        "shell".to_string(),
        "monkey".to_string(),
        "-p".to_string(),
        package.to_string(),
        "1".to_string(),
    ]);
    let launched = shield_core::utils::no_window_command(&adb)
        .args(monkey.iter().map(String::as_str))
        .output()?;
    if !launched.status.success() {
        anyhow::bail!(
            "设备 smoke 启动失败：{}",
            String::from_utf8_lossy(&launched.stderr).trim()
        );
    }
    std::thread::sleep(Duration::from_millis(500));
    let mut pidof = base;
    pidof.extend([
        "shell".to_string(),
        "pidof".to_string(),
        package.to_string(),
    ]);
    let running = shield_core::utils::no_window_command(&adb)
        .args(pidof.iter().map(String::as_str))
        .output()?;
    if !running.status.success() || String::from_utf8_lossy(&running.stdout).trim().is_empty() {
        anyhow::bail!("设备 smoke 进程未保持运行：{package}");
    }
    Ok(())
}

pub(crate) fn run_check_keystore(ks: PathBuf, alias: String, ks_pass: String) -> Result<String> {
    match extract_keystore_cert_fingerprint(&ks, &alias, &ks_pass, None) {
        Ok(fp) => Ok(keystore_check_json(fp)),
        Err(err) => Err(err),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        extract_aab_modules, extract_proto_apk_module, manifest_package,
        normalize_runtime_certificate, run_bundletool_build_apks, run_install_apks,
        run_protect_aab, run_protect_xop, validate_asset_pack_manifest,
        validate_bundle_config_json, validate_dynamic_feature_manifest, AssetPackDelivery,
        DynamicFeatureDelivery,
    };
    use std::io::Write;

    #[test]
    fn manifest_package_accepts_bundletool_xml_quotes() {
        assert_eq!(
            manifest_package(
                r#"<manifest package="com.palmzen.NebulaVox" android:versionCode="1">"#
            )
            .as_deref(),
            Some("com.palmzen.NebulaVox")
        );
        assert_eq!(
            manifest_package("<manifest package='dev.example.app'>").as_deref(),
            Some("dev.example.app")
        );
    }

    #[test]
    fn bundletool_mode_invalid_is_rejected_before_tool_execution() {
        let result = run_bundletool_build_apks(
            std::path::Path::new("missing.jar"),
            std::path::Path::new("input.aab"),
            std::path::Path::new("out.apks"),
            "bad-mode",
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("universal 或 default"));
    }

    #[test]
    fn bundletool_requires_explicit_signing_inputs() {
        let result = run_bundletool_build_apks(
            std::path::Path::new("missing.jar"),
            std::path::Path::new("input.aab"),
            std::path::Path::new("out.apks"),
            "universal",
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("--ks、--ks-alias 和 --ks-pass"));
    }

    #[test]
    fn install_apks_requires_existing_inputs() {
        let result = run_install_apks(
            std::path::PathBuf::from("missing.apks"),
            std::path::PathBuf::from("missing-bundletool.jar"),
            None,
        );
        assert!(result.unwrap_err().to_string().contains("APKS 文件不存在"));
    }

    #[test]
    fn runtime_certificate_requires_sha256_and_normalizes_separators() {
        let formatted = ("AA:".repeat(31) + "AA").to_lowercase();
        assert_eq!(
            normalize_runtime_certificate(&formatted).unwrap(),
            "AA".repeat(32)
        );
        assert!(normalize_runtime_certificate("not-a-certificate").is_err());
    }

    #[test]
    fn xop_requires_packer_and_shell_before_execution() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("input.apk");
        std::fs::write(&input, b"not-an-apk").unwrap();
        let args = crate::args::ProtectXopArgs {
            input,
            output: temp.path().join("out.apk"),
            packer: temp.path().join("missing-packer.jar"),
            shell_dir: temp.path().join("missing-shell"),
            ..Default::default()
        };

        let error = run_protect_xop(args).unwrap_err().to_string();
        assert!(error.contains("Xop Packer JAR 不存在"), "{error}");
    }

    #[test]
    fn proto_apk_is_mapped_to_bundle_base_layout() {
        let temp = tempfile::tempdir().unwrap();
        let apk = temp.path().join("proto.apk");
        let module = temp.path().join("base");
        let file = std::fs::File::create(&apk).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        for (name, contents) in [
            ("AndroidManifest.xml", b"manifest".as_slice()),
            ("resources.pb", b"resources".as_slice()),
            ("classes.dex", b"dex".as_slice()),
            ("assets/config.json", b"{}".as_slice()),
            ("lib/arm64-v8a/libdemo.so", b"so".as_slice()),
            ("res/values.pb", b"res".as_slice()),
            ("META-INF/MANIFEST.MF", b"signature".as_slice()),
            ("NOTICE", b"notice".as_slice()),
        ] {
            zip.start_file(name, options).unwrap();
            zip.write_all(contents).unwrap();
        }
        zip.finish().unwrap();

        extract_proto_apk_module(&apk, &module).unwrap();

        for path in [
            "manifest/AndroidManifest.xml",
            "resources.pb",
            "dex/classes.dex",
            "assets/config.json",
            "lib/arm64-v8a/libdemo.so",
            "res/values.pb",
            "root/NOTICE",
        ] {
            assert!(module.join(path).is_file(), "missing {path}");
        }
        assert!(!module.join("META-INF/MANIFEST.MF").exists());

        let module_zip = temp.path().join("base.zip");
        super::zip_bundle_module(&module, &module_zip).unwrap();
        let file = std::fs::File::open(module_zip).unwrap();
        let archive = zip::ZipArchive::new(file).unwrap();
        let names: Vec<_> = archive.file_names().map(str::to_string).collect();
        assert!(names.contains(&"manifest/AndroidManifest.xml".to_string()));
        assert!(names.contains(&"dex/classes.dex".to_string()));
        assert!(names.contains(&"resources.pb".to_string()));
        assert!(!names.iter().any(|name| name.starts_with("META-INF/")));
    }

    #[test]
    fn aab_dynamic_module_is_extracted_without_top_level_prefix() {
        let temp = tempfile::tempdir().unwrap();
        let bundle = temp.path().join("input.aab");
        let file = std::fs::File::create(&bundle).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("feature/manifest/AndroidManifest.xml", options)
            .unwrap();
        zip.write_all(b"manifest").unwrap();
        zip.start_file("feature/dex/classes.dex", options).unwrap();
        zip.write_all(b"dex").unwrap();
        zip.start_file("base/dex/classes.dex", options).unwrap();
        zip.write_all(b"base").unwrap();
        zip.finish().unwrap();

        let root = temp.path().join("modules");
        let modules = extract_aab_modules(&bundle, &["feature"], &root).unwrap();
        assert_eq!(modules.len(), 1);
        assert_eq!(
            std::fs::read(root.join("feature/dex/classes.dex")).unwrap(),
            b"dex"
        );
        assert!(!root.join("base").exists());
    }

    #[test]
    fn bundle_config_for_build_bundle_must_be_json_not_binary_proto() {
        assert!(validate_bundle_config_json(br#"{"optimizations":{}}"#).is_ok());
        assert!(validate_bundle_config_json(&[0x0a, 0x08, 0x12, 0x06]).is_err());
        assert!(validate_bundle_config_json(b"[]").is_err());
    }

    #[test]
    fn asset_pack_deferred_delivery_requires_explicit_adapter() {
        let install_time = r#"<dist:module dist:type="asset-pack"><dist:fusing dist:include="true"/><dist:delivery><dist:install-time/></dist:delivery></dist:module>"#;
        assert_eq!(
            validate_asset_pack_manifest("pack", install_time, false).unwrap(),
            AssetPackDelivery::InstallTimeFused
        );

        let on_demand = r#"<dist:module dist:type="asset-pack"><dist:fusing dist:include="true"/><dist:delivery><dist:on-demand/></dist:delivery></dist:module>"#;
        let error = validate_asset_pack_manifest("pack", on_demand, false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("MocikaPlayDelivery"), "{error}");
        assert_eq!(
            validate_asset_pack_manifest("pack", on_demand, true).unwrap(),
            AssetPackDelivery::OnDemand
        );
        let fast_follow = on_demand.replace("on-demand", "fast-follow");
        assert_eq!(
            validate_asset_pack_manifest("pack", &fast_follow, true).unwrap(),
            AssetPackDelivery::FastFollow
        );
    }

    #[test]
    fn dynamic_feature_accepts_install_conditional_and_on_demand_delivery() {
        let install_time = r#"<manifest android:isFeatureSplit="true"><dist:module><dist:delivery><dist:install-time/></dist:delivery><dist:fusing dist:include="true"/></dist:module></manifest>"#;
        assert_eq!(
            validate_dynamic_feature_manifest("feature", install_time).unwrap(),
            DynamicFeatureDelivery::InstallTime
        );

        let on_demand = r#"<manifest android:isFeatureSplit="true"><dist:module><dist:delivery><dist:on-demand/></dist:delivery><dist:fusing dist:include="false"/></dist:module></manifest>"#;
        assert_eq!(
            validate_dynamic_feature_manifest("feature", on_demand).unwrap(),
            DynamicFeatureDelivery::OnDemand
        );
        let conditional = r#"<manifest android:isFeatureSplit="true"><dist:module><dist:delivery><dist:install-time><dist:conditions/></dist:install-time></dist:delivery><dist:fusing dist:include="false"/></dist:module></manifest>"#;
        assert_eq!(
            validate_dynamic_feature_manifest("feature", conditional).unwrap(),
            DynamicFeatureDelivery::Conditional
        );
    }

    #[test]
    fn protect_aab_dynamic_modules_require_embedded_pvm2_before_transform() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("dynamic.aab");
        let file = std::fs::File::create(&input).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        for name in [
            "BundleConfig.pb",
            "base/manifest/AndroidManifest.xml",
            "base/dex/classes.dex",
            "feature/manifest/AndroidManifest.xml",
            "feature/dex/classes.dex",
        ] {
            zip.start_file(name, options).unwrap();
            zip.write_all(b"x").unwrap();
        }
        zip.finish().unwrap();

        let tool = temp.path().join("tool");
        std::fs::write(&tool, b"placeholder").unwrap();
        let args = crate::args::ProtectAabArgs {
            input,
            output: temp.path().join("out.aab"),
            bundletool: tool.clone(),
            aapt2: tool.clone(),
            ks: tool,
            key_alias: "test".to_string(),
            ks_pass: "test".to_string(),
            ..Default::default()
        };

        let error = run_protect_aab(args).unwrap_err().to_string();
        assert!(
            error.contains("AAB 多模块必须配置嵌入式 Xop PVM2"),
            "{error}"
        );
    }

    #[test]
    fn protect_aab_xop_requires_external_engine_inputs() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("base.aab");
        let file = std::fs::File::create(&input).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        for name in [
            "BundleConfig.pb",
            "base/manifest/AndroidManifest.xml",
            "base/dex/classes.dex",
        ] {
            zip.start_file(name, options).unwrap();
            zip.write_all(b"x").unwrap();
        }
        zip.finish().unwrap();

        let tool = temp.path().join("tool");
        std::fs::write(&tool, b"placeholder").unwrap();
        let mut args = crate::args::ProtectAabArgs::default();
        args.input = input;
        args.output = temp.path().join("out.aab");
        args.bundletool = tool.clone();
        args.aapt2 = tool.clone();
        args.ks = tool;
        args.key_alias = "test".to_string();
        args.ks_pass = "test".to_string();
        args.engine = crate::args::ProtectionEngineArg::Xop;

        let error = run_protect_aab(args).unwrap_err().to_string();
        assert!(
            error.contains("--engine xop 必须提供 --xop-packer"),
            "{error}"
        );
    }
}
