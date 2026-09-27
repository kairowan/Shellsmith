use crate::task_manager::{TaskKind, TaskManager, TaskStatus};
use serde::Deserialize;
use shield_ios::{
    IosConfidentialConfig, IosProjectConfig, IosProtectionConfig, IosProtectionProfile,
    IosRaspConfig, ProtectIosOptions, ShellsmithIosConfig,
};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

#[derive(Clone, Default)]
pub(crate) struct IosCancelHandle(pub(crate) Arc<AtomicBool>);

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IosProtectRequest {
    task_id: String,
    project: String,
    scheme: String,
    configuration: String,
    team_id: String,
    #[serde(default)]
    bundle_ids: Vec<String>,
    entrypoint: Option<String>,
    output: String,
    profile: IosProtectionProfile,
    confidential_config: Option<String>,
    watcher_mail: Option<String>,
    #[serde(default = "default_true")]
    is_prod: bool,
    app_attest_endpoint: Option<String>,
    export_options: Option<String>,
    #[serde(default = "default_export_method")]
    export_method: String,
    #[serde(default)]
    allow_provisioning_updates: bool,
    #[serde(default)]
    dry_run: bool,
}

#[tauri::command]
pub(crate) async fn check_ios_project(
    project: String,
    scheme: Option<String>,
) -> Result<shield_ios::IosProjectInspection, String> {
    tokio::task::spawn_blocking(move || {
        shield_ios::inspect_ios_project(PathBuf::from(project).as_path(), scheme.as_deref())
            .map_err(|error| format!("{error:#}"))
    })
    .await
    .map_err(|error| format!("iOS 检查后台任务失败：{error}"))?
}

#[tauri::command]
pub(crate) async fn protect_ios_project(
    window: tauri::Window,
    request: IosProtectRequest,
    cancel_handle: tauri::State<'_, IosCancelHandle>,
    task_manager: tauri::State<'_, TaskManager>,
) -> Result<shield_ios::IosProtectionReport, String> {
    cancel_handle.0.store(false, Ordering::SeqCst);
    task_manager.begin(
        &window,
        request.task_id.clone(),
        TaskKind::IosProtect,
        request.project.clone(),
        request.output.clone(),
        "InspectProject",
    )?;
    let options = request.into_options();
    let cancel = cancel_handle.0.clone();
    let manager = task_manager.inner().clone();
    let progress_window = window.clone();
    let task_id = options.1.clone();
    let result = tokio::task::spawn_blocking(move || {
        shield_ios::protect_ios_project(
            &options.0,
            |event| {
                let _ = manager.progress(&progress_window, &task_id, &event.step, event.message);
            },
            cancel,
        )
        .map_err(|error| format!("{error:#}"))
    })
    .await
    .map_err(|error| format!("iOS 加固后台任务失败：{error}"))?;

    let status = match &result {
        Ok(_) => TaskStatus::Succeeded,
        Err(message) if message.contains("已取消") => TaskStatus::Cancelled,
        Err(_) => TaskStatus::Failed,
    };
    let _ = task_manager.finish(&window, &options.1, status, result.as_ref().err().cloned());
    result
}

#[tauri::command]
pub(crate) fn cancel_ios_protect(cancel: tauri::State<'_, IosCancelHandle>) {
    cancel.0.store(true, Ordering::SeqCst);
}

impl IosProtectRequest {
    fn into_options(self) -> (ProtectIosOptions, String) {
        let task_id = self.task_id;
        let confidential_config = self
            .confidential_config
            .filter(|path| !path.trim().is_empty());
        let uses_confidential = self.profile.uses_confidential() && confidential_config.is_some();
        let uses_rasp = self.profile.uses_rasp();
        let watcher_mail = self
            .watcher_mail
            .map(|mail| mail.trim().to_string())
            .filter(|mail| !mail.is_empty());
        let config = ShellsmithIosConfig {
            project: IosProjectConfig {
                path: PathBuf::from(self.project),
                scheme: self.scheme,
                configuration: self.configuration,
                team_id: self.team_id,
                bundle_ids: self.bundle_ids,
                entrypoint: self.entrypoint.map(PathBuf::from),
            },
            protection: IosProtectionConfig {
                profile: self.profile,
                is_prod: self.is_prod,
                app_attest_endpoint: self.app_attest_endpoint,
            },
            confidential: uses_confidential.then(|| IosConfidentialConfig {
                enabled: true,
                config: PathBuf::from(confidential_config.expect("enabled config")),
            }),
            rasp: uses_rasp.then(|| IosRaspConfig {
                provider: "freerasp".to_string(),
                enabled: true,
                watcher_mail,
                critical: ["signature", "jailbreak", "debugger", "runtimeManipulation"]
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
            }),
        };
        (
            ProtectIosOptions {
                config,
                output_dir: PathBuf::from(self.output),
                export_options: self.export_options.map(PathBuf::from),
                export_method: self.export_method,
                allow_provisioning_updates: self.allow_provisioning_updates,
                dry_run: self.dry_run,
            },
            task_id,
        )
    }
}

fn default_true() -> bool {
    true
}

fn default_export_method() -> String {
    "development".to_string()
}
