use crate::app_paths::{
    find_aapt2_path, find_apksigner_path, find_apktool_path, find_bundletool_path,
    find_resources_path, find_xop_pvm2_packer_path, strip_unc_prefix,
};
use crate::cert_store::CertificateRecord;
use crate::failure_diagnostic::ExecutionFailure;
use crate::protect_runner::{
    AiResistanceRequest, CancelHandle, EnvironmentPolicyRequest, ProtectionProfileRequest,
};
use crate::task_manager::TaskManager;
use shield_cli::{
    AiResistanceArg, EnvironmentPolicyArg, KeystoreTypeArg, ProtectAabArgs, ProtectionEngineArg,
    ProtectionProfileArg, XopProfileArg,
};
use std::path::PathBuf;
use std::sync::{atomic::Ordering, Arc};
use tauri::Manager;

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AabProtectRequest {
    pub(crate) task_id: String,
    pub(crate) input: String,
    pub(crate) output: String,
    pub(crate) apks_output: Option<String>,
    pub(crate) certificate_id: String,
    pub(crate) runtime_cert_sha256: Option<String>,
    pub(crate) allow_upload_cert_binding: bool,
    pub(crate) play_delivery_adapter: bool,
    #[serde(default)]
    pub(crate) environment_policy: EnvironmentPolicyRequest,
    #[serde(default)]
    pub(crate) protection_profile: ProtectionProfileRequest,
    #[serde(default)]
    pub(crate) ai_resistance: AiResistanceRequest,
    #[serde(default)]
    pub(crate) xop_true_vmp_prefixes: Vec<String>,
}

pub(crate) fn check_aab(app: &tauri::AppHandle, path: String) -> Result<serde_json::Value, String> {
    let bundletool = find_bundletool_path(app)
        .ok_or_else(|| "当前安装包缺少 bundletool，无法校验 AAB".to_string())?;
    let output = shield_cli::run_check_aab(
        strip_unc_prefix(PathBuf::from(path)),
        Some(bundletool),
        None,
        None,
        "universal".into(),
        None,
        None,
        None,
    )
    .map_err(|error| format!("{error:#}"))?;
    serde_json::from_str(&output).map_err(|error| format!("解析 AAB 检查结果失败：{error}"))
}

pub(crate) async fn execute_protect_aab(
    window: tauri::Window,
    request: AabProtectRequest,
    certificate: CertificateRecord,
    cancel_handle: tauri::State<'_, CancelHandle>,
    task_manager: TaskManager,
) -> Result<(), ExecutionFailure> {
    cancel_handle.0.store(false, Ordering::SeqCst);
    let app = window.app_handle().clone();
    let bundletool = find_bundletool_path(&app)
        .ok_or_else(|| ExecutionFailure::from("当前安装包缺少 bundletool".to_string()))?;
    let aapt2 = find_aapt2_path(&app)
        .ok_or_else(|| ExecutionFailure::from("当前安装包缺少 aapt2".to_string()))?;
    let apktool = find_apktool_path(&app)
        .ok_or_else(|| ExecutionFailure::from("当前安装包缺少 apktool".to_string()))?;
    let resources = find_resources_path(&app)
        .ok_or_else(|| ExecutionFailure::from("当前安装包缺少 Android 运行时资源".to_string()))?;
    let apksigner = find_apksigner_path(&app)
        .ok_or_else(|| ExecutionFailure::from("当前安装包缺少 apksigner".to_string()))?;
    let pvm2 = if request.xop_true_vmp_prefixes.is_empty() {
        None
    } else {
        Some(find_xop_pvm2_packer_path(&app).ok_or_else(|| {
            ExecutionFailure::from("当前安装包缺少内置 Xop PVM2 Packer".to_string())
        })?)
    };
    let cancel = Arc::clone(&cancel_handle.0);
    let task_id = request.task_id.clone();
    let task_window = window.clone();
    let progress_manager = task_manager.clone();

    let result = tokio::task::spawn_blocking(move || {
        let key_password =
            (!certificate.key_password.is_empty()).then_some(certificate.key_password);
        let args = ProtectAabArgs {
            input: strip_unc_prefix(PathBuf::from(request.input)),
            output: strip_unc_prefix(PathBuf::from(request.output)),
            bundletool,
            aapt2,
            ks: strip_unc_prefix(PathBuf::from(certificate.keystore_path)),
            key_alias: certificate.key_alias,
            ks_pass: certificate.keystore_password,
            key_pass: key_password,
            ks_type: if certificate.ks_type.eq_ignore_ascii_case("PKCS12") {
                KeystoreTypeArg::Pkcs12
            } else {
                KeystoreTypeArg::Jks
            },
            apktool: Some(apktool),
            resources: Some(resources),
            apksigner: Some(apksigner),
            environment_policy: match request.environment_policy {
                EnvironmentPolicyRequest::Compatible => EnvironmentPolicyArg::Compatible,
                EnvironmentPolicyRequest::Strict => EnvironmentPolicyArg::Strict,
            },
            profile: match request.protection_profile {
                ProtectionProfileRequest::Compat => ProtectionProfileArg::Compat,
                ProtectionProfileRequest::Balanced => ProtectionProfileArg::Balanced,
                ProtectionProfileRequest::Strict => ProtectionProfileArg::Strict,
            },
            ai_resistance: match request.ai_resistance {
                AiResistanceRequest::Off => AiResistanceArg::Off,
                AiResistanceRequest::Balanced => AiResistanceArg::Balanced,
                AiResistanceRequest::High => AiResistanceArg::High,
            },
            runtime_cert_sha256: request
                .runtime_cert_sha256
                .filter(|value| !value.trim().is_empty()),
            allow_upload_cert_binding: request.allow_upload_cert_binding,
            play_delivery_adapter: request.play_delivery_adapter,
            engine: ProtectionEngineArg::Mocika,
            xop_packer: None,
            xop_pvm2_packer: pvm2,
            xop_true_vmp_prefix: request.xop_true_vmp_prefixes,
            xop_shell_dir: None,
            xop_profile: XopProfileArg::Industry,
            xop_no_protect_so: false,
            xop_encrypt_assets: false,
            xop_enable_res_protect: false,
            xop_detect_proxy: false,
            xop_rasp_action: 2,
            exclude_abis: Vec::new(),
            apks_output: request.apks_output.map(PathBuf::from).map(strip_unc_prefix),
            install_apks: false,
            device_spec: None,
            device_id: None,
            smoke_package: None,
            json: false,
        };
        let callback_manager = progress_manager.clone();
        let callback_window = task_window.clone();
        let callback_task = task_id.clone();
        shield_cli::run_protect_aab_with_control(
            args,
            move |step, message| {
                let _ = callback_manager.progress(&callback_window, &callback_task, step, message);
            },
            Arc::clone(&cancel),
        )
        .map_err(|error| {
            if cancel.load(Ordering::Relaxed) {
                ExecutionFailure::cancelled()
            } else {
                ExecutionFailure::from(format!("{error:#}"))
            }
        })?;
        task_manager
            .protected(&task_id, true)
            .map_err(ExecutionFailure::from)
    })
    .await
    .unwrap_or_else(|error| Err(ExecutionFailure::from(format!("后台任务执行失败: {error}"))));
    result
}
