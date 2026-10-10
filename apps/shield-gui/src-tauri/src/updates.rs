use crate::task_manager::{TaskKind, TaskManager, TaskStatus};
use serde::{Deserialize, Serialize};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tauri::{ipc::Channel, Manager};
use tauri_plugin_updater::{Update, UpdaterExt};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct UpdateCheckResult {
    pub has_update: bool,
    pub latest_version: Option<String>,
    pub release_url: Option<String>,
    pub update_level: Option<String>,
    pub notes: Option<String>,
    pub can_install: bool,
    /// 无法覆盖安装时的可解释原因；能安装时为 None。
    pub install_blocked_reason: Option<InstallBlockReason>,
    /// 无法覆盖安装时当前平台的直连安装包，避免用户只能在 Release 页面里逐个找。
    pub manual_download_url: Option<String>,
    /// 需要改装到其它位置时，新版 .app 的落地路径；就地覆盖时为 None。
    pub install_relocates_to: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum InstallBlockReason {
    DebugBuild,
    NotAppBundle,
    LinuxPackage,
}

impl InstallBlockReason {
    fn message(self) -> &'static str {
        match self {
            Self::DebugBuild => "开发模式仅检查版本，不执行覆盖安装",
            Self::NotAppBundle => "未能确定当前可执行文件位置，无法执行覆盖安装",
            Self::LinuxPackage => {
                "当前是 deb 系统包安装方式，安装位置由系统包管理器管理，无法在应用内静默替换"
            }
        }
    }

    /// 无法覆盖安装时的修复动作，直接告诉用户怎么才能用上一键更新。
    fn remedy(self) -> &'static str {
        match self {
            Self::DebugBuild => "请使用 Release 页面提供的正式安装包测试更新",
            Self::NotAppBundle => "请从「应用程序」中的 Shellsmith.app 启动后重试",
            Self::LinuxPackage => {
                "下载 deb 后由系统安装器完成安装；若希望之后能一键更新，请改用 AppImage 版本"
            }
        }
    }
}

#[derive(Clone, Serialize)]
pub(crate) struct UpdateProgress {
    phase: &'static str,
    downloaded: u64,
    total: Option<u64>,
}

pub(crate) fn compare_semver(
    current: &str,
    latest: &str,
    release_url: Option<String>,
) -> UpdateCheckResult {
    let (Ok(current), Ok(version)) = (
        semver::Version::parse(current),
        semver::Version::parse(latest),
    ) else {
        return UpdateCheckResult::default();
    };
    if version <= current {
        return UpdateCheckResult::default();
    }
    let level = if version.major > current.major {
        "major"
    } else if version.minor > current.minor {
        "minor"
    } else {
        "patch"
    };
    UpdateCheckResult {
        has_update: true,
        latest_version: Some(latest.to_string()),
        release_url,
        update_level: Some(level.to_string()),
        ..Default::default()
    }
}

/// 一键更新的可行性、不可行时的原因，以及需要改装位置时的目标。
#[derive(Debug)]
pub(crate) struct InstallSupport {
    pub can_install: bool,
    pub blocked_reason: Option<InstallBlockReason>,
    pub relocation: Option<RelocationPlan>,
}

/// 当前运行位置无法写入时，把新版本装到这里的 .app，并改从它启动。
///
/// macOS 上从 DMG 或 Gatekeeper 转位路径运行时，应用包整体只读，插件的原地替换
/// （rename 当前 .app 再放入新版）必然失败；改为安装到「应用程序」后，用户无需手动
/// 拖拽，且下一次更新就能走正常的原地覆盖。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelocationPlan {
    /// 交给更新器的安装目标（.app 内的可执行文件），它据此推导要替换的 .app。
    pub target_executable: PathBuf,
    /// 展示给用户的 .app 落地路径。
    pub target_app: PathBuf,
}

/// macOS 应用的运行形态。
#[cfg(any(target_os = "macos", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MacRunMode {
    /// 正常 .app，磁盘位置可写，可原地覆盖。
    Bundle,
    /// 直接从只读磁盘映像（DMG）运行。
    MountedVolume,
    /// Gatekeeper 的随机只读路径（App Translocation）。
    Translocated,
    /// 不是 .app 形态（裸二进制运行）。
    NotBundle,
}

/// 依据可执行文件路径判定 macOS 运行形态。
///
/// 纯路径判定，便于三平台回归；正式运行时传入 `current_exe()`。
#[cfg(any(target_os = "macos", test))]
pub(crate) fn classify_macos_executable(exe: &Path) -> MacRunMode {
    if exe.starts_with("/Volumes") {
        return MacRunMode::MountedVolume;
    }
    if exe
        .components()
        .any(|part| part.as_os_str() == "AppTranslocation")
    {
        return MacRunMode::Translocated;
    }
    if exe
        .parent()
        .is_some_and(|parent| parent.ends_with("Contents/MacOS"))
    {
        return MacRunMode::Bundle;
    }
    MacRunMode::NotBundle
}

/// 从可执行文件路径取 .app 名称；裸二进制运行时退回产品名。
#[cfg(any(target_os = "macos", test))]
fn bundle_name(exe: &Path) -> OsString {
    exe.components()
        .map(|part| part.as_os_str().to_os_string())
        .find(|name| name.to_string_lossy().ends_with(".app"))
        .unwrap_or_else(|| OsString::from("Shellsmith.app"))
}

/// 把新版本安装到「应用程序」时的目标路径。
#[cfg(any(target_os = "macos", test))]
fn macos_relocation_plan(exe: &Path) -> RelocationPlan {
    let binary = exe
        .file_name()
        .map(OsStr::to_os_string)
        .unwrap_or_else(|| OsString::from("mocika-shield"));
    let target_app = Path::new("/Applications").join(bundle_name(exe));
    let target_executable = target_app.join("Contents").join("MacOS").join(binary);
    RelocationPlan {
        target_executable,
        target_app,
    }
}

/// macOS 的安装能力判定：只读位置或裸二进制一律改装到「应用程序」，不再让用户手动拖拽。
///
/// 纯路径判定，便于三平台回归；正式运行时传入 `std::env::current_exe()`。
#[cfg(any(target_os = "macos", test))]
pub(crate) fn macos_support_for(exe: Option<&Path>) -> InstallSupport {
    match exe {
        Some(exe) => match classify_macos_executable(exe) {
            MacRunMode::Bundle => InstallSupport {
                can_install: true,
                blocked_reason: None,
                relocation: None,
            },
            MacRunMode::MountedVolume | MacRunMode::Translocated | MacRunMode::NotBundle => {
                InstallSupport {
                    can_install: true,
                    blocked_reason: None,
                    relocation: Some(macos_relocation_plan(exe)),
                }
            }
        },
        None => InstallSupport {
            can_install: false,
            blocked_reason: Some(InstallBlockReason::NotAppBundle),
            relocation: None,
        },
    }
}

fn install_support(app: &tauri::AppHandle) -> InstallSupport {
    if cfg!(debug_assertions) {
        return InstallSupport {
            can_install: false,
            blocked_reason: Some(InstallBlockReason::DebugBuild),
            relocation: None,
        };
    }
    #[cfg(target_os = "linux")]
    {
        let _ = app;
        // AppImage 可以整体替换自身；deb 由系统包管理器管理，交给系统安装器完成。
        return if app.env().appimage.is_some() {
            InstallSupport {
                can_install: true,
                blocked_reason: None,
                relocation: None,
            }
        } else {
            InstallSupport {
                can_install: false,
                blocked_reason: Some(InstallBlockReason::LinuxPackage),
                relocation: None,
            }
        };
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = app;
        #[cfg(target_os = "macos")]
        let support = macos_support_for(std::env::current_exe().ok().as_deref());
        // Windows 安装包走 NSIS 静默安装，可原地覆盖，无需改装位置。
        #[cfg(not(target_os = "macos"))]
        let support = InstallSupport {
            can_install: true,
            blocked_reason: None,
            relocation: None,
        };
        support
    }
}

/// 当前平台的直连安装包地址。资产命名与发布脚本、更新清单生成器保持一致：
/// macOS 只发布 universal 包；Linux 只发布 deb，AppImage 走应用内更新而不会走到这里。
fn manual_download_url(version: &str, target_os: &str) -> Option<String> {
    let asset = match target_os {
        "macos" => format!("Shellsmith_{version}_macos_universal.dmg"),
        "windows" => format!("Shellsmith_{version}_windows_x64_setup.exe"),
        "linux" => format!("Shellsmith_{version}_linux_amd64.deb"),
        _ => return None,
    };
    Some(format!(
        "https://github.com/kairowan/Shellsmith/releases/download/v{version}/{asset}"
    ))
}

async fn available_update(
    app: &tauri::AppHandle,
    install_target: Option<&Path>,
) -> Result<Option<Update>, String> {
    let mut builder = app
        .updater_builder()
        .timeout(Duration::from_secs(20))
        .version_comparator(|current, release| {
            release.version.pre.is_empty() && release.version > current
        });
    if let Some(target) = install_target {
        // 指定安装目标后，插件据此推导要替换的 .app，并复用其备份与系统授权逻辑；
        // 否则它会去 rename 当前这份只读的 .app，安装必然失败。
        builder = builder.executable_path(target);
    }
    builder
        .build()
        .map_err(|error| format!("初始化更新器失败：{error}"))?
        .check()
        .await
        .map_err(|error| format!("检查更新失败，请检查网络或前往 Release 页面：{error}"))
}

pub(crate) async fn check_update_impl(app: &tauri::AppHandle) -> Result<UpdateCheckResult, String> {
    // ponytail: 每次检查直接读取稳定版清单，不缓存一天，也不为更新另建业务后台。
    let Some(update) = available_update(app, None).await? else {
        return Ok(UpdateCheckResult::default());
    };
    let mut result = compare_semver(
        &update.current_version,
        &update.version,
        Some(format!(
            "https://github.com/kairowan/Shellsmith/releases/tag/v{}",
            update.version
        )),
    );
    result.notes = update.body;
    let support = install_support(app);
    result.can_install = support.can_install;
    result.install_blocked_reason = support.blocked_reason;
    result.install_relocates_to = support
        .relocation
        .as_ref()
        .map(|plan| plan.target_app.display().to_string());
    result.manual_download_url = if support.can_install {
        None
    } else {
        manual_download_url(&update.version, std::env::consts::OS)
    };
    Ok(result)
}

#[tauri::command]
pub(crate) async fn install_update(
    window: tauri::Window,
    tasks: tauri::State<'_, TaskManager>,
    version: String,
    on_progress: Channel<UpdateProgress>,
) -> Result<(), String> {
    let app = window.app_handle().clone();
    let support = install_support(&app);
    if !support.can_install {
        let reason = support
            .blocked_reason
            .map(|reason| format!("{}。{}。", reason.message(), reason.remedy()))
            .unwrap_or_else(|| "当前运行方式不支持覆盖更新。".to_string());
        return Err(format!(
            "{reason}也可以直接下载安装包手动覆盖安装：{}",
            manual_download_url(&version, std::env::consts::OS).unwrap_or_else(|| {
                "https://github.com/kairowan/Shellsmith/releases/latest".to_string()
            })
        ));
    }
    let task_id = uuid::Uuid::new_v4().to_string();
    tasks.begin(
        &window,
        task_id.clone(),
        TaskKind::Update,
        String::new(),
        String::new(),
        "Update",
    )?;
    let result =
        download_and_install(&app, &version, support.relocation.as_ref(), &on_progress).await;
    match result {
        Ok(None) => {
            // 安装后到退出前仍保持互斥，避免重启间隙接入新的加固任务。
            app.restart();
        }
        Ok(Some(target_app)) => {
            // 新版装在别处，当前运行位置仍是上一版，restart 只会再启动旧版本。
            relaunch_from(&target_app).map_err(|error| {
                format!(
                    "更新已安装到 {}，但自动重启失败：{error}",
                    target_app.display()
                )
            })?;
            app.exit(0);
            Ok(())
        }
        Err(error) => {
            let _ = tasks.finish(&window, &task_id, TaskStatus::Failed, Some(error.clone()));
            Err(error)
        }
    }
}

/// 启动新安装的 .app；失败由调用方转成可读错误。
#[cfg(target_os = "macos")]
fn relaunch_from(target_app: &Path) -> Result<(), std::io::Error> {
    std::process::Command::new("open")
        .arg(target_app)
        .spawn()
        .map(|_| ())
}

/// 非 macOS 平台不会发生改装位置，保留同名桩以便调用点无需条件编译。
#[cfg(not(target_os = "macos"))]
fn relaunch_from(_target_app: &Path) -> Result<(), std::io::Error> {
    Ok(())
}

/// 返回 `Some(路径)` 表示新版装在别处，需要从该路径启动。
async fn download_and_install(
    app: &tauri::AppHandle,
    expected_version: &str,
    relocation: Option<&RelocationPlan>,
    progress: &Channel<UpdateProgress>,
) -> Result<Option<PathBuf>, String> {
    let mut update = available_update(app, relocation.map(|plan| plan.target_executable.as_path()))
        .await?
        .ok_or("没有可安装的新版本，请重新检查更新")?;
    if update.version != expected_version {
        return Err("可用版本已经变化，请重新检查并确认更新".into());
    }
    // 检查清单限时 20 秒；完整安装包允许较慢网络，下载失败不会调用安装。
    update.timeout = Some(Duration::from_secs(1800));
    let mut downloaded = 0;
    let mut last_sent = Instant::now();
    let bytes = update
        .download(
            |chunk, total| {
                downloaded += chunk as u64;
                if last_sent.elapsed() >= Duration::from_millis(150) || total == Some(downloaded) {
                    let _ = progress.send(UpdateProgress {
                        phase: "downloading",
                        downloaded,
                        total,
                    });
                    last_sent = Instant::now();
                }
            },
            || {
                let _ = progress.send(UpdateProgress {
                    phase: "verifying",
                    downloaded: 0,
                    total: None,
                });
            },
        )
        .await
        .map_err(|error| format!("下载或签名校验失败，未执行安装：{error}"))?;
    // download 已完成包签名和签名版本校验，不能跳过或降级为仅校验 SHA-256。
    let _ = progress.send(UpdateProgress {
        phase: "installing",
        downloaded: 0,
        total: None,
    });
    tokio::task::spawn_blocking(move || update.install(bytes))
        .await
        .map_err(|error| format!("更新安装任务失败：{error}"))?
        .map_err(|error| format!("安装更新失败，请从 Release 页面手动安装：{error}"))?;
    Ok(relocation.map(|plan| plan.target_app.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "需要真实 Release 与网络，只下载验签，不安装"]
    fn 已发布三平台更新包通过内置公钥验签() {
        use tauri::test::{mock_builder, mock_context, noop_assets};
        let mut context = mock_context(noop_assets());
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        context
            .config_mut()
            .plugins
            .0
            .insert("updater".into(), config["plugins"]["updater"].clone());
        let app = mock_builder()
            .plugin(tauri_plugin_updater::Builder::new().build())
            .build(context)
            .unwrap();
        tauri::async_runtime::block_on(async {
            for target in [
                "darwin-aarch64",
                "darwin-x86_64",
                "windows-x86_64",
                "linux-x86_64",
            ] {
                let update = app
                    .updater_builder()
                    .target(target)
                    .timeout(Duration::from_secs(600))
                    .build()
                    .unwrap()
                    .check()
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(update.version, env!("CARGO_PKG_VERSION"));
                let bytes = update.download(|_, _| {}, || {}).await.unwrap();
                assert!(!bytes.is_empty());
                println!(
                    "{target} {}：{} 字节，验签通过，未执行安装",
                    update.version,
                    bytes.len()
                );
            }
        });
    }

    #[test]
    fn 官方更新器接受合法签名且拒绝篡改包和伪造版本() {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;
        use tauri::test::{mock_builder, mock_context, noop_assets};

        // 独立测试密钥的公钥及签名；没有提交私钥，也不使用生产签名密钥。
        const PUBLIC_KEY: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDM2ODY0QjRGNEY5ODc2QzIKUldUQ2RwaFBUMHVHTml6eHpDWktJYTJReC9rRFhCdSsvTFZoT3NBRGNsdmdCZWJaVnZpazlURnQK";
        const SIGNATURE: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRhdXJpIHNlY3JldCBrZXkKUlVUQ2RwaFBUMHVHTnFsSEhNNDkyOGVnZkJ0RmQ4Yk1GTDU3WllRWmUxNG01QkttK2hmWll1cjliMXI2SU55NnU4U2NVdy83a1lHZ1VmVXNyY2JPeVp6cExMM0tqRnlFbWdZPQp0cnVzdGVkIGNvbW1lbnQ6IHRpbWVzdGFtcDoxNzkxNDQzNzc1CWZpbGU6cGF5bG9hZAl2ZXJzaW9uOjEuNC41CkxvczFZMkd2REVyUzJEWnpQbHFOa3NwV2N3b1J4Q1p5K3NlWEoyVDVYMzFnL25PanZMWGZrRDZYRzY2bXJmRzJFMm1IVTN6Rjd6Y21JZkNjTktBcUNBPT0K";
        const PAYLOAD: &str = "Shellsmith 更新验签测试\n";
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            for mut stream in listener.incoming().take(6).map(Result::unwrap) {
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut reader = BufReader::new(&mut stream);
                let mut request = String::new();
                reader.read_line(&mut request).unwrap();
                loop {
                    let mut header = String::new();
                    reader.read_line(&mut header).unwrap();
                    if header == "\r\n" || header.is_empty() {
                        break;
                    }
                }
                let route = request.split_whitespace().nth(1).unwrap();
                let body = if route.ends_with("/manifest") {
                    let scenario = route.split('/').nth(1).unwrap();
                    serde_json::json!({
                        "version": if scenario == "spoof" { "9.0.0" } else { "1.4.5" },
                        "platforms": {"test": {
                            "url": format!("http://{address}/{scenario}/payload"),
                            "signature": SIGNATURE
                        }}
                    })
                    .to_string()
                } else if route.contains("tampered") {
                    "被修改的内容".into()
                } else {
                    PAYLOAD.into()
                };
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
        });
        let mut context = mock_context(noop_assets());
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        assert_eq!(config["plugins"]["updater"]["requireSignedVersion"], true);
        let mut updater_config = config["plugins"]["updater"].clone();
        updater_config["pubkey"] = PUBLIC_KEY.into();
        updater_config["dangerousInsecureTransportProtocol"] = true.into();
        context
            .config_mut()
            .plugins
            .0
            .insert("updater".into(), updater_config);
        let app = mock_builder()
            .plugin(tauri_plugin_updater::Builder::new().build())
            .build(context)
            .unwrap();
        tauri::async_runtime::block_on(async {
            for scenario in ["good", "tampered", "spoof"] {
                let update = app
                    .updater_builder()
                    .target("test")
                    .no_proxy()
                    .timeout(Duration::from_secs(5))
                    .endpoints(vec![format!("http://{address}/{scenario}/manifest")
                        .parse()
                        .unwrap()])
                    .unwrap()
                    .build()
                    .unwrap()
                    .check()
                    .await
                    .unwrap()
                    .unwrap();
                let result = update.download(|_, _| {}, || {}).await;
                match scenario {
                    "good" => assert_eq!(result.unwrap(), PAYLOAD.as_bytes()),
                    "spoof" => assert!(matches!(
                        result,
                        Err(tauri_plugin_updater::Error::SignedVersionMismatch { .. })
                    )),
                    _ => assert!(result.is_err()),
                }
            }
        });
        server.join().unwrap();
    }

    #[test]
    fn patch_update_detected() {
        let r = compare_semver("1.0.0", "1.0.1", Some("http://x".into()));
        assert!(r.has_update);
        assert_eq!(r.update_level.as_deref(), Some("patch"));
        assert_eq!(r.latest_version.as_deref(), Some("1.0.1"));
    }

    #[test]
    fn minor_update_detected() {
        let r = compare_semver("1.0.0", "1.1.0", Some("http://x".into()));
        assert!(r.has_update);
        assert_eq!(r.update_level.as_deref(), Some("minor"));
    }

    #[test]
    fn major_update_detected() {
        let r = compare_semver("1.0.0", "2.0.0", Some("http://x".into()));
        assert!(r.has_update);
        assert_eq!(r.update_level.as_deref(), Some("major"));
    }

    #[test]
    fn no_update_when_same_version() {
        let r = compare_semver("1.0.0", "1.0.0", None);
        assert!(!r.has_update);
        assert!(r.update_level.is_none());
    }

    #[test]
    fn no_update_when_current_is_newer() {
        let r = compare_semver("1.2.0", "1.0.5", None);
        assert!(!r.has_update);
    }

    #[test]
    fn no_update_on_invalid_latest() {
        let r = compare_semver("1.0.0", "not-a-version", None);
        assert!(!r.has_update);
    }

    #[test]
    fn no_update_on_empty_latest() {
        let r = compare_semver("1.0.0", "", None);
        assert!(!r.has_update);
    }

    #[test]
    fn v_prefix_stripped_before_compare() {
        let stripped = "v1.0.1".trim_start_matches(['v', 'V']);
        let r = compare_semver("1.0.0", stripped, None);
        assert!(r.has_update);
        assert_eq!(r.update_level.as_deref(), Some("patch"));
    }

    #[test]
    fn major_dominates_minor_patch() {
        let r = compare_semver("1.9.9", "2.0.0", None);
        assert!(r.has_update);
        assert_eq!(r.update_level.as_deref(), Some("major"));
    }

    #[test]
    fn release_url_preserved() {
        let url = "https://github.com/kairowan/Shellsmith/releases/tag/v1.0.1";
        let r = compare_semver("1.0.0", "1.0.1", Some(url.into()));
        assert_eq!(r.release_url.as_deref(), Some(url));
    }

    #[test]
    fn 默认结果不影响一键更新且不预置下载地址() {
        let r = UpdateCheckResult::default();
        assert!(!r.can_install);
        assert!(r.install_blocked_reason.is_none());
        assert!(r.manual_download_url.is_none());
        assert!(r.install_relocates_to.is_none());
    }

    #[test]
    fn 直连安装包地址与发布资产命名一致() {
        assert_eq!(
            manual_download_url("1.5.1", "macos").as_deref(),
            Some("https://github.com/kairowan/Shellsmith/releases/download/v1.5.1/Shellsmith_1.5.1_macos_universal.dmg")
        );
        assert_eq!(
            manual_download_url("1.5.1", "windows").as_deref(),
            Some("https://github.com/kairowan/Shellsmith/releases/download/v1.5.1/Shellsmith_1.5.1_windows_x64_setup.exe")
        );
        // deb 安装走不到应用内更新，给它 deb 包才是有用的产物。
        assert_eq!(
            manual_download_url("1.5.1", "linux").as_deref(),
            Some("https://github.com/kairowan/Shellsmith/releases/download/v1.5.1/Shellsmith_1.5.1_linux_amd64.deb")
        );
        assert_eq!(manual_download_url("1.5.1", "freebsd"), None);
    }

    #[test]
    fn 每种阻止原因都有可读说明和修复动作() {
        for reason in [
            InstallBlockReason::DebugBuild,
            InstallBlockReason::NotAppBundle,
            InstallBlockReason::LinuxPackage,
        ] {
            assert!(!reason.message().is_empty(), "{reason:?}");
            assert!(!reason.remedy().is_empty(), "{reason:?}");
        }
    }

    #[test]
    fn 阻止原因序列化为前端可映射的蛇形命名() {
        assert_eq!(
            serde_json::to_string(&InstallBlockReason::NotAppBundle).unwrap(),
            "\"not_app_bundle\""
        );
        assert_eq!(
            serde_json::to_string(&InstallBlockReason::LinuxPackage).unwrap(),
            "\"linux_package\""
        );
    }

    #[test]
    fn 只读映像与转位路径都识别为需要改装位置() {
        // 从 DMG 直接运行：整卷只读，插件的原地替换必然失败。
        let volume = Path::new("/Volumes/Shellsmith/Shellsmith.app/Contents/MacOS/mocika-shield");
        assert_eq!(classify_macos_executable(volume), MacRunMode::MountedVolume);
        // Gatekeeper 转位路径：随机只读副本。
        let translocated = Path::new(
            "/private/var/folders/xy/abc/T/AppTranslocation/9F3/d/Shellsmith.app/Contents/MacOS/mocika-shield",
        );
        assert_eq!(
            classify_macos_executable(translocated),
            MacRunMode::Translocated
        );
        // 裸二进制运行。
        assert_eq!(
            classify_macos_executable(Path::new("/Users/me/build/target/release/mocika-shield")),
            MacRunMode::NotBundle
        );
    }

    #[test]
    fn 已安装的应用程序包可原地覆盖() {
        let installed = Path::new("/Applications/Shellsmith.app/Contents/MacOS/mocika-shield");
        assert_eq!(classify_macos_executable(installed), MacRunMode::Bundle);
        // 用户目录下的 .app 同样可写，不需要改装位置。
        let home = Path::new("/Users/me/Applications/Shellsmith.app/Contents/MacOS/mocika-shield");
        assert_eq!(classify_macos_executable(home), MacRunMode::Bundle);
    }

    #[test]
    fn 改装目标沿用原应用包名与可执行文件名() {
        let plan = macos_relocation_plan(Path::new(
            "/Volumes/Shellsmith/Shellsmith.app/Contents/MacOS/mocika-shield",
        ));
        assert_eq!(
            plan.target_executable,
            Path::new("/Applications/Shellsmith.app/Contents/MacOS/mocika-shield")
        );
        assert_eq!(plan.target_app, Path::new("/Applications/Shellsmith.app"));

        // 转位路径同样落到「应用程序」，去掉随机只读前缀。
        let from_translocation = macos_relocation_plan(Path::new(
            "/private/var/folders/xy/abc/T/AppTranslocation/9F3/d/Shellsmith.app/Contents/MacOS/mocika-shield",
        ));
        assert_eq!(
            from_translocation.target_app,
            Path::new("/Applications/Shellsmith.app")
        );
    }

    #[test]
    fn 只读位置与裸二进制都改为安装到应用程序而不是拒绝安装() {
        // 这三种位置都无法原地覆盖：DMG 只读、转位副本只读、裸二进制没有 .app。
        for path in [
            "/Volumes/Shellsmith/Shellsmith.app/Contents/MacOS/mocika-shield",
            "/private/var/folders/xy/abc/T/AppTranslocation/9F3/d/Shellsmith.app/Contents/MacOS/mocika-shield",
            "/Users/me/build/target/release/mocika-shield",
        ] {
            let support = macos_support_for(Some(Path::new(path)));
            assert!(support.can_install, "{path} 应仍可一键更新");
            assert!(support.blocked_reason.is_none(), "{path}");
            let plan = support.relocation.expect("应给出改装目标");
            assert_eq!(plan.target_app, Path::new("/Applications/Shellsmith.app"));
        }
    }

    #[test]
    fn 已安装位置不触发改装且无法定位可执行文件时明确拒绝() {
        let installed = macos_support_for(Some(Path::new(
            "/Applications/Shellsmith.app/Contents/MacOS/mocika-shield",
        )));
        assert!(installed.can_install);
        assert!(installed.relocation.is_none());

        let unknown = macos_support_for(None);
        assert!(!unknown.can_install);
        assert_eq!(
            unknown.blocked_reason,
            Some(InstallBlockReason::NotAppBundle)
        );
        assert!(unknown.relocation.is_none());
    }

    #[test]
    fn 裸二进制改装时退回产品名并保留可执行文件名() {
        let plan = macos_relocation_plan(Path::new("/Users/me/build/target/release/mocika-shield"));
        assert_eq!(plan.target_app, Path::new("/Applications/Shellsmith.app"));
        assert_eq!(
            plan.target_executable,
            Path::new("/Applications/Shellsmith.app/Contents/MacOS/mocika-shield")
        );
    }

    #[test]
    fn stable_release_updates_release_candidate() {
        let r = compare_semver("1.2.0-rc.1", "1.2.0", None);
        assert!(r.has_update);
        assert_eq!(r.update_level.as_deref(), Some("patch"));
        assert_eq!(r.latest_version.as_deref(), Some("1.2.0"));
    }

    #[test]
    fn newer_release_candidate_updates_older_release_candidate() {
        let r = compare_semver("1.2.0-rc.1", "1.2.0-rc.2", None);
        assert!(r.has_update);
        assert_eq!(r.update_level.as_deref(), Some("patch"));
    }

    #[test]
    fn release_candidate_does_not_update_stable_release() {
        let r = compare_semver("1.2.0", "1.2.0-rc.2", None);
        assert!(!r.has_update);
    }

    #[test]
    fn minor_level_preserved_for_prerelease_current() {
        let r = compare_semver("1.2.0-rc.1", "1.3.0-rc.1", None);
        assert!(r.has_update);
        assert_eq!(r.update_level.as_deref(), Some("minor"));
    }
}
