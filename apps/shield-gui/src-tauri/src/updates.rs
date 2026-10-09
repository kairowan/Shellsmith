use crate::task_manager::{TaskKind, TaskManager, TaskStatus};
use serde::{Deserialize, Serialize};
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum InstallBlockReason {
    DebugBuild,
    MountedVolume,
    AppTranslocation,
    NotAppBundle,
    LinuxPackage,
}

impl InstallBlockReason {
    fn message(self) -> &'static str {
        match self {
            Self::DebugBuild => "开发模式仅检查版本，不执行覆盖安装",
            Self::MountedVolume => {
                "应用正从磁盘映像（DMG）中直接运行，磁盘映像是只读的，无法覆盖安装"
            }
            Self::AppTranslocation => {
                "应用正从 Gatekeeper 的随机只读路径运行（App Translocation），例如下载后未移入「应用程序」就直接打开"
            }
            Self::NotAppBundle => "当前不是以 .app 应用包形式运行，无法覆盖安装",
            Self::LinuxPackage => "当前是 deb 等系统包安装方式，不支持应用内覆盖更新",
        }
    }

    /// 无法覆盖安装时的修复动作，直接告诉用户怎么才能用上一键更新。
    fn remedy(self) -> &'static str {
        match self {
            Self::DebugBuild => "请使用 Release 页面提供的正式安装包测试更新",
            Self::MountedVolume | Self::AppTranslocation | Self::NotAppBundle => {
                "请把 Shellsmith.app 拖入「应用程序」文件夹后重新打开，之后即可使用一键更新"
            }
            Self::LinuxPackage => "请下载 AppImage 并改用 AppImage 运行，之后即可一键更新",
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

/// 一键更新的可行性，以及不可行时的原因。
pub(crate) struct InstallSupport {
    pub can_install: bool,
    pub blocked_reason: Option<InstallBlockReason>,
}

fn install_support(app: &tauri::AppHandle) -> InstallSupport {
    if cfg!(debug_assertions) {
        return InstallSupport {
            can_install: false,
            blocked_reason: Some(InstallBlockReason::DebugBuild),
        };
    }
    #[cfg(target_os = "linux")]
    {
        let _ = app;
        return if app.env().appimage.is_some() {
            InstallSupport {
                can_install: true,
                blocked_reason: None,
            }
        } else {
            InstallSupport {
                can_install: false,
                blocked_reason: Some(InstallBlockReason::LinuxPackage),
            }
        };
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = app;
        #[cfg(target_os = "macos")]
        {
            let blocked = |reason| InstallSupport {
                can_install: false,
                blocked_reason: Some(reason),
            };
            return match std::env::current_exe() {
                Ok(path) if path.starts_with("/Volumes") => {
                    blocked(InstallBlockReason::MountedVolume)
                }
                Ok(path)
                    if path
                        .components()
                        .any(|part| part.as_os_str() == "AppTranslocation") =>
                {
                    blocked(InstallBlockReason::AppTranslocation)
                }
                Ok(path)
                    if path
                        .parent()
                        .is_some_and(|parent| parent.ends_with("Contents/MacOS")) =>
                {
                    InstallSupport {
                        can_install: true,
                        blocked_reason: None,
                    }
                }
                _ => blocked(InstallBlockReason::NotAppBundle),
            };
        }
        #[cfg(not(target_os = "macos"))]
        InstallSupport {
            can_install: true,
            blocked_reason: None,
        }
    }
}

/// 当前平台的直连安装包地址。资产命名与发布脚本、更新清单生成器保持一致：
/// macOS 只发布 universal 包，非 universal 名称不会被更新清单接受。
fn manual_download_url(version: &str, target_os: &str) -> Option<String> {
    let asset = match target_os {
        "macos" => format!("Shellsmith_{version}_macos_universal.dmg"),
        "windows" => format!("Shellsmith_{version}_windows_x64_setup.exe"),
        "linux" => format!("Shellsmith_{version}_linux_amd64.AppImage"),
        _ => return None,
    };
    Some(format!(
        "https://github.com/kairowan/Shellsmith/releases/download/v{version}/{asset}"
    ))
}

async fn available_update(app: &tauri::AppHandle) -> Result<Option<Update>, String> {
    app.updater_builder()
        .timeout(Duration::from_secs(20))
        .version_comparator(|current, release| {
            release.version.pre.is_empty() && release.version > current
        })
        .build()
        .map_err(|error| format!("初始化更新器失败：{error}"))?
        .check()
        .await
        .map_err(|error| format!("检查更新失败，请检查网络或前往 Release 页面：{error}"))
}

pub(crate) async fn check_update_impl(app: &tauri::AppHandle) -> Result<UpdateCheckResult, String> {
    // ponytail: 每次检查直接读取稳定版清单，不缓存一天，也不为更新另建业务后台。
    let Some(update) = available_update(app).await? else {
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
    let result = download_and_install(&app, &version, &on_progress).await;
    match result {
        Ok(()) => {
            // 安装后到退出前仍保持互斥，避免重启间隙接入新的加固任务。
            app.restart();
        }
        Err(error) => {
            let _ = tasks.finish(&window, &task_id, TaskStatus::Failed, Some(error.clone()));
            Err(error)
        }
    }
}

async fn download_and_install(
    app: &tauri::AppHandle,
    expected_version: &str,
    progress: &Channel<UpdateProgress>,
) -> Result<(), String> {
    let mut update = available_update(app)
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
    Ok(())
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
        assert_eq!(
            manual_download_url("1.5.1", "linux").as_deref(),
            Some("https://github.com/kairowan/Shellsmith/releases/download/v1.5.1/Shellsmith_1.5.1_linux_amd64.AppImage")
        );
        assert_eq!(manual_download_url("1.5.1", "freebsd"), None);
    }

    #[test]
    fn 每种阻止原因都有可读说明和修复动作() {
        for reason in [
            InstallBlockReason::DebugBuild,
            InstallBlockReason::MountedVolume,
            InstallBlockReason::AppTranslocation,
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
            serde_json::to_string(&InstallBlockReason::AppTranslocation).unwrap(),
            "\"app_translocation\""
        );
        assert_eq!(
            serde_json::to_string(&InstallBlockReason::MountedVolume).unwrap(),
            "\"mounted_volume\""
        );
        assert_eq!(
            serde_json::to_string(&InstallBlockReason::LinuxPackage).unwrap(),
            "\"linux_package\""
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
