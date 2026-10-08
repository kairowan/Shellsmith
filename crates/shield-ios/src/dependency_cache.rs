use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use crate::{xcodebuild, FREERASP_IOS_VERSION};

// 只内置官方 v7.1.4 的内容指纹，不随 Shellsmith 分发 SDK 二进制。
const REVISION: &str = "958d7b1933e28fc33f3b7a2725fc174d98c0939f";
const MAX_ARCHIVE_SIZE: u64 = 32 * 1024 * 1024;
pub(crate) const SDK_DIRECTORY: &str = ".shellsmith/Dependencies/Free-RASP-iOS";

#[derive(Deserialize)]
struct SdkFile {
    path: String,
    size: u64,
    sha256: String,
    executable: bool,
}

#[derive(Serialize)]
pub struct IosSdkStatus {
    pub version: &'static str,
    pub path: PathBuf,
    pub ready: bool,
    pub diagnostic: Option<String>,
}

/// GUI 与 CLI 共用当前 macOS 用户的缓存；不放进工程或安装包资源目录。
pub fn default_ios_cache_dir() -> Result<PathBuf> {
    anyhow::ensure!(cfg!(target_os = "macos"), "iOS SDK 自动准备需要 macOS");
    let home = std::env::var_os("HOME").context("无法定位当前用户的 iOS SDK 缓存目录")?;
    Ok(PathBuf::from(home).join("Library/Caches/dev.mocika.shield-gui/ios-dependencies"))
}

fn cache_path(cache_dir: &Path) -> PathBuf {
    cache_dir.join(format!("freerasp-{FREERASP_IOS_VERSION}-{REVISION}.zip"))
}

fn files() -> Vec<SdkFile> {
    serde_json::from_str(include_str!("freerasp-files.json")).expect("内置 freeRASP 文件清单无效")
}

pub fn ios_sdk_status(cache_dir: &Path) -> IosSdkStatus {
    let path = cache_path(cache_dir);
    let result = read_sdk(&path, &files(), None, &AtomicBool::new(false));
    IosSdkStatus {
        version: FREERASP_IOS_VERSION,
        path,
        ready: result.is_ok(),
        diagnostic: result.err().map(|error| format!("{error:#}")),
    }
}

/// 导入优先；否则命中缓存时不联网，缺失时才从固定官方提交下载。
pub fn prepare_ios_sdk(
    cache_dir: &Path,
    import_zip: Option<&Path>,
    cancel: &Arc<AtomicBool>,
) -> Result<PathBuf> {
    check_cancel(cancel)?;
    let cached = cache_path(cache_dir);
    if import_zip.is_none() && cached.try_exists()? {
        read_sdk(&cached, &files(), None, cancel)
            .context("freeRASP 缓存校验失败；请重新导入官方 v7.1.4 ZIP，不能跳过运行时保护")?;
        return Ok(cached);
    }
    fs::create_dir_all(cache_dir).context("创建 iOS SDK 缓存目录失败")?;
    let mut staging = tempfile::NamedTempFile::new_in(cache_dir)?;
    if let Some(source) = import_zip {
        anyhow::ensure!(fs::metadata(source)?.is_file(), "请选择普通 ZIP 文件");
        let file = File::open(source).context("打开 freeRASP ZIP 失败")?;
        anyhow::ensure!(
            file.metadata()?.len() <= MAX_ARCHIVE_SIZE,
            "freeRASP ZIP 超过大小限制"
        );
        let copied = std::io::copy(&mut file.take(MAX_ARCHIVE_SIZE + 1), &mut staging)?;
        anyhow::ensure!(copied <= MAX_ARCHIVE_SIZE, "freeRASP ZIP 超过大小限制");
    } else {
        let url = format!("https://codeload.github.com/talsec/Free-RASP-iOS/zip/{REVISION}");
        let mut args = [
            "--disable",
            "--fail",
            "--location",
            "--silent",
            "--show-error",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--connect-timeout",
            "20",
            "--max-time",
            "180",
            "--max-filesize",
            "33554432",
            "--output",
        ]
        .into_iter()
        .map(std::ffi::OsString::from)
        .collect::<Vec<_>>();
        args.push(staging.path().as_os_str().to_owned());
        args.push(url.into());
        xcodebuild::run("/usr/bin/curl", &args, None, cancel,
            "下载 freeRASP 失败；可在能访问 GitHub 的电脑下载官方 v7.1.4 源码 ZIP，再用“导入官方 ZIP”准备本机缓存")?;
    }
    read_sdk(staging.path(), &files(), None, cancel)
        .context("freeRASP ZIP 校验失败：需要完整且未修改的官方 v7.1.4 源码 ZIP")?;
    check_cancel(cancel)?;
    staging.as_file().sync_all()?;
    // ponytail: 同版本并发准备允许重复下载；校验后原子替换同一内容，无需额外锁服务。
    staging
        .persist(&cached)
        .map_err(|error| error.error)
        .context("保存 freeRASP 缓存失败")?;
    Ok(cached)
}

pub(crate) fn install_sdk(
    archive: &Path,
    working_root: &Path,
    cancel: &Arc<AtomicBool>,
) -> Result<()> {
    let destination = working_root.join(SDK_DIRECTORY);
    anyhow::ensure!(
        !destination.try_exists()?,
        "工作副本已包含 freeRASP SDK，拒绝覆盖"
    );
    let parent = destination.parent().context("SDK 输出目录无效")?;
    fs::create_dir_all(parent)?;
    let staging = tempfile::tempdir_in(parent)?;
    read_sdk(archive, &files(), Some(staging.path()), cancel)?;
    check_cancel(cancel)?;
    fs::rename(staging.path(), destination).context("写入工作副本 freeRASP SDK 失败")?;
    Ok(())
}

pub(crate) fn verify_installed_sdk(working_root: &Path) -> Result<()> {
    let root = working_root.join(SDK_DIRECTORY);
    for file in files() {
        let mut path = root.clone();
        for part in Path::new(&file.path).components() {
            path.push(part);
            anyhow::ensure!(
                !fs::symlink_metadata(&path)?.file_type().is_symlink(),
                "freeRASP 文件不能是符号链接"
            );
        }
        let input = File::open(&path)?;
        anyhow::ensure!(
            input.metadata()?.is_file() && input.metadata()?.len() == file.size,
            "freeRASP 文件大小不符：{}",
            file.path
        );
        let mut bytes = Vec::new();
        input.take(file.size + 1).read_to_end(&mut bytes)?;
        verify_content(&file, &bytes)?;
    }
    Ok(())
}

fn check_cancel(cancel: &AtomicBool) -> Result<()> {
    anyhow::ensure!(!cancel.load(Ordering::SeqCst), "iOS SDK 准备已取消");
    Ok(())
}

fn verify_content(file: &SdkFile, bytes: &[u8]) -> Result<()> {
    anyhow::ensure!(
        bytes.len() as u64 == file.size && format!("{:x}", Sha256::digest(bytes)) == file.sha256,
        "freeRASP 内容校验不符：{}",
        file.path
    );
    Ok(())
}

fn read_sdk(
    archive: &Path,
    expected: &[SdkFile],
    destination: Option<&Path>,
    cancel: &AtomicBool,
) -> Result<()> {
    check_cancel(cancel)?;
    anyhow::ensure!(
        fs::metadata(archive)
            .context("尚未准备 freeRASP 本机缓存")?
            .is_file(),
        "freeRASP 缓存必须是普通 ZIP 文件"
    );
    let input = File::open(archive).context("尚未准备 freeRASP 本机缓存")?;
    anyhow::ensure!(
        input.metadata()?.len() <= MAX_ARCHIVE_SIZE,
        "freeRASP ZIP 超过大小限制"
    );
    let mut zip = zip::ZipArchive::new(input).context("freeRASP 文件不是有效 ZIP")?;
    anyhow::ensure!(zip.len() <= 4096, "freeRASP ZIP 条目过多");
    let mut names = HashSet::new();
    let mut roots = Vec::new();
    for index in 0..zip.len() {
        check_cancel(cancel)?;
        let entry = zip.by_index(index)?;
        let name = entry.name();
        anyhow::ensure!(
            !name.contains('\\')
                && Path::new(name)
                    .components()
                    .all(|part| matches!(part, Component::Normal(_))),
            "freeRASP ZIP 包含不安全路径"
        );
        anyhow::ensure!(names.insert(name.to_string()), "freeRASP ZIP 包含重复条目");
        let kind = entry.unix_mode().unwrap_or(0) & 0o170000;
        anyhow::ensure!(
            matches!(kind, 0 | 0o100000 | 0o040000),
            "freeRASP ZIP 包含符号链接或特殊文件"
        );
        if name == "Package.swift"
            || (name.ends_with("/Package.swift") && name.matches('/').count() == 1)
        {
            roots.push(name.trim_end_matches("Package.swift").to_string());
        }
    }
    anyhow::ensure!(
        roots.len() == 1,
        "找不到唯一 freeRASP 包根目录；请选择官方源码 ZIP，而非 dSYM 或单独 framework"
    );
    for file in expected {
        check_cancel(cancel)?;
        let entry = zip
            .by_name(&format!("{}{}", roots[0], file.path))
            .with_context(|| format!("freeRASP ZIP 缺少 {}", file.path))?;
        anyhow::ensure!(
            !entry.is_dir() && entry.size() == file.size,
            "freeRASP 文件大小不符：{}",
            file.path
        );
        let mut bytes = Vec::new();
        entry.take(file.size + 1).read_to_end(&mut bytes)?;
        verify_content(file, &bytes)?;
        if let Some(root) = destination {
            // 仅提取编译进程序的白名单；不使用 ZIP 提供的路径写磁盘，也不执行归档内脚本。
            let path = root.join(&file.path);
            fs::create_dir_all(path.parent().context("SDK 文件路径无效")?)?;
            fs::write(&path, bytes)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(
                    path,
                    fs::Permissions::from_mode(if file.executable { 0o755 } else { 0o644 }),
                )?;
            }
            #[cfg(not(unix))]
            let _ = file.executable;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    fn sample_zip(path: &Path, extra: Option<&str>) {
        let mut zip = zip::ZipWriter::new(File::create(path).unwrap());
        zip.start_file("Official/Package.swift", SimpleFileOptions::default())
            .unwrap();
        zip.write_all(b"sample").unwrap();
        if let Some(name) = extra {
            zip.start_file(name, SimpleFileOptions::default()).unwrap();
            zip.write_all(b"ignored").unwrap();
        }
        zip.finish().unwrap();
    }

    fn sample_files() -> Vec<SdkFile> {
        vec![SdkFile {
            path: "Package.swift".into(),
            size: 6,
            sha256: format!("{:x}", Sha256::digest(b"sample")),
            executable: false,
        }]
    }

    #[test]
    fn validates_contents_and_extracts_only_allowlisted_files() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("input.zip");
        sample_zip(&archive, Some("Official/untrusted.sh"));
        let output = temp.path().join("output");
        let cancel = AtomicBool::new(false);
        read_sdk(&archive, &sample_files(), Some(&output), &cancel).unwrap();
        assert_eq!(fs::read(output.join("Package.swift")).unwrap(), b"sample");
        assert!(!output.join("untrusted.sh").exists());
        let mut wrong = sample_files();
        wrong[0].sha256 = "0".repeat(64);
        assert!(read_sdk(&archive, &wrong, None, &cancel).is_err());
        wrong[0].size = 5;
        assert!(read_sdk(&archive, &wrong, None, &cancel).is_err());
        wrong[0].path = "missing".into();
        assert!(read_sdk(&archive, &wrong, None, &cancel).is_err());
        cancel.store(true, Ordering::SeqCst);
        assert!(read_sdk(&archive, &sample_files(), None, &cancel)
            .unwrap_err()
            .to_string()
            .contains("已取消"));
    }

    #[test]
    fn rejects_unsafe_ambiguous_and_oversized_archives() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("input.zip");
        for path in [
            "../escape",
            "/absolute",
            "Official/../escape",
            "Official\\escape",
            "Second/Package.swift",
        ] {
            sample_zip(&archive, Some(path));
            assert!(
                read_sdk(&archive, &sample_files(), None, &AtomicBool::new(false)).is_err(),
                "{path}"
            );
        }
        let mut zip = zip::ZipWriter::new(File::create(&archive).unwrap());
        zip.add_symlink(
            "Official/Package.swift",
            "/tmp/outside",
            SimpleFileOptions::default(),
        )
        .unwrap();
        zip.finish().unwrap();
        assert!(read_sdk(&archive, &sample_files(), None, &AtomicBool::new(false)).is_err());
        sample_zip(&archive, Some("Official/package.swift"));
        let bytes = fs::read(&archive).unwrap();
        let bytes = bytes
            .windows(b"Official/package.swift".len())
            .enumerate()
            .filter_map(|(i, value)| (value == b"Official/package.swift").then_some(i + 9))
            .collect::<Vec<_>>()
            .into_iter()
            .fold(bytes, |mut bytes, index| {
                bytes[index] = b'P';
                bytes
            });
        fs::write(&archive, bytes).unwrap();
        assert!(read_sdk(&archive, &sample_files(), None, &AtomicBool::new(false)).is_err());
        File::create(&archive)
            .unwrap()
            .set_len(MAX_ARCHIVE_SIZE + 1)
            .unwrap();
        assert!(read_sdk(&archive, &sample_files(), None, &AtomicBool::new(false)).is_err());
    }

    #[test]
    fn invalid_import_preserves_existing_cache_and_cancel_creates_nothing() {
        let temp = tempfile::tempdir().unwrap();
        let cache = temp.path().join("cache");
        let cancelled = Arc::new(AtomicBool::new(true));
        assert!(prepare_ios_sdk(&cache, None, &cancelled).is_err());
        assert!(!cache.exists());
        fs::create_dir(&cache).unwrap();
        let existing = cache_path(&cache);
        fs::write(&existing, b"old cache").unwrap();
        let bad = temp.path().join("bad.zip");
        sample_zip(&bad, None);
        assert!(prepare_ios_sdk(&cache, Some(&bad), &Arc::new(AtomicBool::new(false))).is_err());
        assert_eq!(fs::read(&existing).unwrap(), b"old cache");
        assert_eq!(fs::read_dir(&cache).unwrap().count(), 1);
        // 损坏缓存直接拒绝，不能静默跳过保护，也不能自动覆盖已有内容。
        assert!(
            prepare_ios_sdk(&cache, None, &Arc::new(AtomicBool::new(false)))
                .unwrap_err()
                .to_string()
                .contains("缓存校验失败")
        );
    }

    #[test]
    fn embedded_file_list_has_unique_safe_paths_and_complete_notices() {
        let files = files();
        let names = files
            .iter()
            .map(|file| file.path.as_str())
            .collect::<HashSet<_>>();
        assert_eq!(names.len(), files.len());
        for name in [
            "Package.swift",
            "LICENSE.txt",
            "README.md",
            "Talsec/TalsecRuntime.xcframework/Info.plist",
        ] {
            assert!(names.contains(name));
        }
        assert!(files.iter().all(|file| file.size < MAX_ARCHIVE_SIZE
            && file.sha256.len() == 64
            && file.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
            && Path::new(&file.path)
                .components()
                .all(|part| matches!(part, Component::Normal(_)))));
    }

    #[test]
    #[ignore = "需要访问官方源；验证首次下载和缓存命中"]
    fn official_sdk_download_and_reuse() {
        let temp = tempfile::tempdir().unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let sdk = prepare_ios_sdk(temp.path(), None, &cancel).unwrap();
        assert!(ios_sdk_status(temp.path()).ready);
        assert_eq!(prepare_ios_sdk(temp.path(), None, &cancel).unwrap(), sdk);
    }

    #[test]
    #[ignore = "需用户提供官方 ZIP；验证真实 SDK 缓存复用与断网 SwiftPM 解析"]
    fn official_sdk_import_reuse_and_offline_resolve() {
        let input = PathBuf::from(
            std::env::var_os("SHELLSMITH_TEST_FREERASP_ZIP").expect("请指定官方 ZIP 路径"),
        );
        let temp = tempfile::tempdir().unwrap();
        let cache = temp.path().join("cache");
        let cancel = Arc::new(AtomicBool::new(false));
        let sdk = prepare_ios_sdk(&cache, Some(&input), &cancel).unwrap();
        assert!(ios_sdk_status(&cache).ready);
        let before = fs::metadata(&sdk).unwrap().modified().unwrap();
        assert_eq!(prepare_ios_sdk(&cache, None, &cancel).unwrap(), sdk);
        assert_eq!(fs::metadata(&sdk).unwrap().modified().unwrap(), before);
        let bad = temp.path().join("bad.zip");
        fs::write(&bad, b"invalid").unwrap();
        assert!(prepare_ios_sdk(&cache, Some(&bad), &cancel).is_err());
        assert!(ios_sdk_status(&cache).ready);
        for name in ["first", "second"] {
            let root = temp.path().join(name);
            install_sdk(&sdk, &root, &cancel).unwrap();
            verify_installed_sdk(&root).unwrap();
            let package = root.join(".shellsmith/ShellsmithRuntime");
            fs::create_dir_all(package.join("Sources/ShellsmithRuntime")).unwrap();
            fs::write(
                package.join("Package.swift"),
                crate::freerasp::package_manifest(false, true),
            )
            .unwrap();
            fs::write(
                package.join("Sources/ShellsmithRuntime/Smoke.swift"),
                "import TalsecRuntime\n",
            )
            .unwrap();
            if cfg!(target_os = "macos") {
                let result = std::process::Command::new("/usr/bin/sandbox-exec")
                    .args([
                        "-p",
                        "(version 1)(allow default)(deny network*)",
                        "swift",
                        "package",
                        "--disable-sandbox",
                        "--cache-path",
                    ])
                    .arg(root.join("empty-spm-cache"))
                    .args(["resolve", "--skip-update"])
                    .current_dir(&package)
                    .output()
                    .unwrap();
                assert!(
                    result.status.success(),
                    "{}\n{}",
                    String::from_utf8_lossy(&result.stdout),
                    String::from_utf8_lossy(&result.stderr)
                );
            }
            // 工作副本文件改动也必须在 Archive 前检出。
            fs::write(root.join(SDK_DIRECTORY).join("Package.swift"), b"changed").unwrap();
            assert!(verify_installed_sdk(&root).is_err());
        }
    }
}
