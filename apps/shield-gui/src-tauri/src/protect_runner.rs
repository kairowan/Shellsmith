use crate::app_paths::{
    find_apksigner_path, find_apktool_path, find_named_resources_path, find_resources_path,
    find_xop_pvm2_packer_path, strip_unc_prefix,
};
use crate::cert_store::CertificateRecord;
use crate::failure_diagnostic::ExecutionFailure;
use crate::signing::execute_sign_apk;
use crate::task_manager::TaskManager;
use shield_core::diagnostic::{Diagnostic, FailureCode};
use shield_core::{
    extract_keystore_cert_fingerprint, protect_apk as shield_protect_apk, AiResistance,
    EnvironmentPolicy, ProgressEvent, ProtectOptions, ProtectionProfile, ShieldError,
};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use tauri::Manager;

pub(crate) struct CancelHandle(pub Arc<AtomicBool>);

#[derive(Clone, Copy, Default, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RuntimeMode {
    #[default]
    Standard,
    AndroidApi19,
}

impl RuntimeMode {
    pub(crate) fn preflight_profile(self) -> shield_core::RuntimeProfile {
        match self {
            Self::Standard => shield_core::RuntimeProfile::Standard,
            Self::AndroidApi19 => shield_core::RuntimeProfile::AndroidApi19,
        }
    }
}

#[derive(Clone, Copy, Default, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EnvironmentPolicyRequest {
    #[default]
    Compatible,
    Strict,
}

#[derive(Clone, Copy, Default, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProtectionProfileRequest {
    Compat,
    #[default]
    Balanced,
    Strict,
}

#[derive(Clone, Copy, Default, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AiResistanceRequest {
    Off,
    #[default]
    Balanced,
    High,
}

fn unsupported_api19_abis(native_abis: &[String]) -> Vec<String> {
    native_abis
        .iter()
        .filter(|abi| abi.as_str() != "armeabi-v7a")
        .cloned()
        .collect()
}

fn resolve_xop_pvm2_packer(
    custom: Option<String>,
    prefixes: &[String],
    required: bool,
    built_in: Option<PathBuf>,
) -> Option<PathBuf> {
    custom
        .filter(|path| !path.trim().is_empty())
        .map(PathBuf::from)
        .map(strip_unc_prefix)
        .or_else(|| {
            (!prefixes.is_empty() || required)
                .then_some(built_in)
                .flatten()
        })
}

pub(crate) struct ProtectExecution {
    pub(crate) byos: Option<crate::byos::SavedProfile>,
    pub(crate) runtime_ui: shield_core::RuntimeUiProtection,
    pub(crate) excluded_abis: Vec<String>,
    pub(crate) task_id: String,
    pub(crate) input: String,
    pub(crate) output: String,
    pub(crate) apktool_path: Option<String>,
    pub(crate) runtime_mode: RuntimeMode,
    pub(crate) environment_policy: EnvironmentPolicyRequest,
    pub(crate) protection_profile: ProtectionProfileRequest,
    pub(crate) ai_resistance: AiResistanceRequest,
    pub(crate) xop_pvm2_packer_path: Option<String>,
    pub(crate) xop_true_vmp_prefixes: Vec<String>,
    pub(crate) pvm2_required_methods: Option<String>,
    pub(crate) native_vmp_evidence: Option<String>,
    pub(crate) protect_route_assets: bool,
    pub(crate) signing_certificate: Option<CertificateRecord>,
    pub(crate) signed_output: Option<String>,
}

pub(crate) async fn execute_protect_apk(
    window: tauri::Window,
    request: ProtectExecution,
    cancel_handle: tauri::State<'_, CancelHandle>,
    task_manager: TaskManager,
) -> Result<(), ExecutionFailure> {
    cancel_handle.inner().0.store(false, Ordering::SeqCst);

    let app = window.app_handle().clone();

    let resolved_apktool = request
        .apktool_path
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| find_apktool_path(&app));

    let resolved_resources = match request.runtime_mode {
        RuntimeMode::Standard => match &request.byos {
            Some(saved) => Some(
                find_named_resources_path(
                    &app,
                    if saved.profile.auth_mode == "device_approval" {
                        "resources-byos.zip"
                    } else {
                        "resources-byos-play.zip"
                    },
                )
                .ok_or_else(|| "缺少对应 BYOS 资源，请使用完整安装包".to_string())?,
            ),
            None => find_resources_path(&app),
        },
        RuntimeMode::AndroidApi19 => {
            let checked = shield_core::check_apk(
                std::path::Path::new(&request.input),
                find_apksigner_path(&app).as_deref(),
            )
            .map_err(|err| format!("检查 Android 4.4 兼容条件失败：{err}"))?;
            let unsupported = unsupported_api19_abis(&checked.native_abis);
            if !unsupported.is_empty() {
                return Err(ExecutionFailure::preflight(
                    format!(
                        "Android 4.4 兼容模式暂不支持 APK 中的原生架构：{}",
                        unsupported.join("、")
                    ),
                    Diagnostic::new(FailureCode::UnsupportedAbi),
                ));
            }
            find_named_resources_path(&app, "resources-api19.zip")
        }
    };
    let resolved_apksigner = find_apksigner_path(&app);
    let ui_packer = find_xop_pvm2_packer_path(&app);
    let resolved_xop_pvm2_packer = resolve_xop_pvm2_packer(
        request.xop_pvm2_packer_path.clone(),
        &request.xop_true_vmp_prefixes,
        request.pvm2_required_methods.is_some(),
        find_xop_pvm2_packer_path(&app),
    );

    let cancel = Arc::clone(&cancel_handle.inner().0);
    let emit_error = Arc::new(Mutex::new(None::<String>));
    let emit_error_for_task = Arc::clone(&emit_error);
    let progress_window = window.clone();
    let progress_task_id = request.task_id;

    let task_result = tokio::task::spawn_blocking(move || {
        let auto_sign = request.signing_certificate.is_some() && request.signed_output.is_some();
        let final_output = request
            .signed_output
            .clone()
            .unwrap_or_else(|| request.output.clone());
        // 自动签名时，加固核心只写任务私有目录；最终输出和附件由签名核心统一提交。
        let (protect_output, _task_temp) = if auto_sign {
            let task_temp = shield_core::utils::create_temp_dir("shield-protect-")
                .map_err(|err| ExecutionFailure::from(err.to_string()))?;
            (task_temp.path().join("unsigned.apk"), Some(task_temp))
        } else {
            (PathBuf::from(&request.output), None)
        };
        let expected_output_cert_fingerprint = request
            .signing_certificate
            .as_ref()
            .map(|certificate| {
                extract_keystore_cert_fingerprint(
                    std::path::Path::new(&certificate.keystore_path),
                    &certificate.key_alias,
                    &certificate.keystore_password,
                    Some(&certificate.ks_type),
                )
            })
            .transpose()
            .map_err(|err| {
                ExecutionFailure::diagnosed(err.to_string(), Diagnostic::from_error(&err))
            })?;
        let opts = ProtectOptions {
            byos_endpoint: request.byos.as_ref().map(|v| v.profile.endpoint.clone()),
            byos_api_key: request.byos.as_ref().map(|v| v.api_key.clone()),
            byos_auth: request
                .byos
                .as_ref()
                .map(|v| v.profile.auth_mode.parse())
                .transpose()
                .map_err(str::to_owned)?,
            runtime_ui: request.runtime_ui,
            ui_packer_path: ui_packer,
            excluded_abis: request.excluded_abis,
            input: strip_unc_prefix(PathBuf::from(request.input)),
            output: strip_unc_prefix(protect_output.clone()),
            apktool_path: resolved_apktool,
            resources_path: resolved_resources,
            apksigner_path: resolved_apksigner,
            expected_output_cert_fingerprint,
            runtime_cert_fingerprint: request.byos.and_then(|v| v.profile.runtime_cert),
            environment_policy: match request.environment_policy {
                EnvironmentPolicyRequest::Compatible => EnvironmentPolicy::Compatible,
                EnvironmentPolicyRequest::Strict => EnvironmentPolicy::Strict,
            },
            protection_profile: match request.protection_profile {
                ProtectionProfileRequest::Compat => ProtectionProfile::Compat,
                ProtectionProfileRequest::Balanced => ProtectionProfile::Balanced,
                ProtectionProfileRequest::Strict => ProtectionProfile::Strict,
            },
            ai_resistance: match request.ai_resistance {
                AiResistanceRequest::Off => AiResistance::Off,
                AiResistanceRequest::Balanced => AiResistance::Balanced,
                AiResistanceRequest::High => AiResistance::High,
            },
            xop_pvm2_packer_path: resolved_xop_pvm2_packer,
            xop_true_vmp_prefixes: request.xop_true_vmp_prefixes,
            pvm2_required_methods: request
                .pvm2_required_methods
                .map(PathBuf::from)
                .map(strip_unc_prefix),
            native_vmp_evidence: request
                .native_vmp_evidence
                .map(PathBuf::from)
                .map(strip_unc_prefix),
            protect_route_assets: request.protect_route_assets,
            external_pvm2_dex_dir: None,
            external_pas2_assets_dir: None,
            deferred_pas2_asset_modules: Vec::new(),
            allow_external_pas2_reader: false,
            external_native_lib_dir: None,
        };
        let cancel_for_progress = Arc::clone(&cancel);
        let cancel_for_protect = Arc::clone(&cancel);
        let protect_manager = task_manager.clone();
        let protect_window = progress_window.clone();
        let protect_task_id = progress_task_id.clone();

        app.state::<crate::application_sharing::SharingState>()
            .verify_input(&progress_task_id);
        shield_protect_apk(
            &opts,
            move |event: ProgressEvent| {
                if let Err(err) = protect_manager.progress(
                    &protect_window,
                    &protect_task_id,
                    &format!("{:?}", event.step),
                    event.message,
                ) {
                    if let Ok(mut slot) = emit_error_for_task.lock() {
                        if slot.is_none() {
                            *slot = Some(format!("发送进度事件失败: {err}"));
                        }
                    }
                    cancel_for_progress.store(true, Ordering::SeqCst);
                }
            },
            cancel_for_protect,
        )
        .map_err(|mut error| {
            // 中间目录会随任务结束销毁；先把 PVM2 逐方法报告保留到最终输出目录。
            shield_core::protection_report::Pvm2Failure::preserve(
                &mut error,
                std::path::Path::new(&final_output),
            );
            ExecutionFailure::from_shield(error)
        })?;

        let sharing = app.state::<crate::application_sharing::SharingState>();
        sharing.protected(&progress_task_id);
        sharing.verify_input(&progress_task_id);

        task_manager.protected(&progress_task_id, auto_sign)?;

        if auto_sign {
            if cancel.load(Ordering::Relaxed) {
                return Err(ExecutionFailure::from_shield(ShieldError::Cancelled));
            }
            let certificate = request.signing_certificate.ok_or_else(|| {
                ExecutionFailure::preflight(
                    "自动签名证书缺失".to_string(),
                    Diagnostic::new(FailureCode::Unknown),
                )
            })?;
            let unsigned_output = opts.output.to_string_lossy().to_string();
            execute_sign_apk(
                &app,
                unsigned_output,
                Some(final_output.clone()),
                None,
                certificate,
                |step, message| {
                    task_manager.progress(&progress_window, &progress_task_id, step, message)
                },
            )?;
            // 末尾进度事件失败不能把已经提交成功的产物误报为失败。
            let _ = task_manager.progress(
                &progress_window,
                &progress_task_id,
                "Cleanup",
                "已清理任务中间文件",
            );
        }
        Ok(())
    })
    .await
    .map_err(|err| format!("后台任务执行失败: {err}"))?;

    let progress_emit_error = emit_error
        .lock()
        .map_err(|_| "发送进度事件失败：状态锁已损坏".to_string())?
        .clone();

    if let Some(msg) = progress_emit_error {
        return Err(msg.into());
    }

    task_result
}

#[cfg(test)]
mod pvm2_tests {
    use super::resolve_xop_pvm2_packer;
    use std::path::PathBuf;

    #[test]
    fn built_in_packer_is_used_only_when_pvm2_prefixes_are_selected() {
        let built_in = PathBuf::from("built-in.jar");
        assert_eq!(
            resolve_xop_pvm2_packer(
                None,
                &["Lcom/example/".into()],
                false,
                Some(built_in.clone())
            ),
            Some(built_in)
        );
        assert_eq!(
            resolve_xop_pvm2_packer(None, &[], false, Some(PathBuf::from("built-in.jar"))),
            None
        );
    }

    #[test]
    fn custom_packer_overrides_built_in() {
        assert_eq!(
            resolve_xop_pvm2_packer(
                Some("custom.jar".into()),
                &["Lcom/example/".into()],
                false,
                Some(PathBuf::from("built-in.jar")),
            ),
            Some(PathBuf::from("custom.jar"))
        );
    }
}

#[cfg(test)]
mod tests {
    use super::unsupported_api19_abis;

    #[test]
    fn api19_允许无原生库或仅有_armv7() {
        assert!(unsupported_api19_abis(&[]).is_empty());
        assert!(unsupported_api19_abis(&["armeabi-v7a".to_string()]).is_empty());
    }

    #[test]
    fn api19_拒绝尚未验证的原生架构() {
        assert_eq!(
            unsupported_api19_abis(&[
                "armeabi-v7a".to_string(),
                "arm64-v8a".to_string(),
                "x86".to_string(),
            ]),
            ["arm64-v8a", "x86"]
        );
    }
}
