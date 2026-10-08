use std::path::{Path, PathBuf};
use tauri::Manager;

pub(crate) fn strip_unc_prefix(path: PathBuf) -> PathBuf {
    dunce::simplified(&path).to_path_buf()
}

fn resource_dir(app: &tauri::AppHandle) -> Option<PathBuf> {
    app.path().resource_dir().ok().map(strip_unc_prefix)
}

fn appimage_resource_dir() -> Option<PathBuf> {
    let appdir = std::env::var("APPDIR").ok()?;
    Some(PathBuf::from(appdir).join("usr/lib/mocika-shield"))
}

pub(crate) fn find_apktool_path(app: &tauri::AppHandle) -> Option<PathBuf> {
    for base in resource_dir(app).into_iter().chain(appimage_resource_dir()) {
        let p = base.join("tools/apktool.jar");
        if p.exists() {
            return Some(p);
        }
    }
    let dev = project_root_path().join("tools/apktool_3.0.1.jar");
    if dev.exists() {
        return Some(dev);
    }
    None
}

pub(crate) fn find_resources_path(app: &tauri::AppHandle) -> Option<PathBuf> {
    find_named_resources_path(app, "resources.zip")
}

pub(crate) fn find_named_resources_path(
    app: &tauri::AppHandle,
    file_name: &str,
) -> Option<PathBuf> {
    for base in resource_dir(app).into_iter().chain(appimage_resource_dir()) {
        let p = base.join("resources").join(file_name);
        if p.exists() {
            return Some(p);
        }
    }
    let dev = project_root_path()
        .join("shield-stub/build/outputs/resources")
        .join(file_name);
    if dev.exists() {
        return Some(dev);
    }
    None
}

pub(crate) fn find_apksigner_path(app: &tauri::AppHandle) -> Option<PathBuf> {
    for base in resource_dir(app).into_iter().chain(appimage_resource_dir()) {
        let p = base.join("tools/apksigner.jar");
        if p.exists() {
            return Some(p);
        }
    }
    let dev = project_root_path().join("tools/apksigner.jar");
    if dev.exists() {
        return Some(dev);
    }
    None
}

pub(crate) fn find_xop_pvm2_packer_path(app: &tauri::AppHandle) -> Option<PathBuf> {
    for base in resource_dir(app).into_iter().chain(appimage_resource_dir()) {
        let path = base.join("tools/xop-pvm2-packer.jar");
        if path.is_file() {
            return Some(path);
        }
    }
    let dev = project_root_path().join("tools/xop-pvm2-packer.jar");
    dev.is_file().then_some(dev)
}

pub(crate) fn find_bundletool_path(app: &tauri::AppHandle) -> Option<PathBuf> {
    for base in resource_dir(app).into_iter().chain(appimage_resource_dir()) {
        let path = base.join("tools/bundletool.jar");
        if path.is_file() {
            return Some(path);
        }
    }
    [
        project_root_path().join("tools/bundletool.jar"),
        project_root_path().join("target/e2e-tools/bundletool-all-1.18.3.jar"),
    ]
    .into_iter()
    .find(|path| path.is_file())
}

pub(crate) fn find_aapt2_path(app: &tauri::AppHandle) -> Option<PathBuf> {
    let executable = if cfg!(windows) { "aapt2.exe" } else { "aapt2" };
    for base in resource_dir(app).into_iter().chain(appimage_resource_dir()) {
        let path = base.join("tools").join(executable);
        if path.is_file() {
            return Some(path);
        }
    }
    for variable in ["ANDROID_HOME", "ANDROID_SDK_ROOT"] {
        if let Some(path) = std::env::var_os(variable)
            .and_then(|value| latest_aapt2(PathBuf::from(value), executable))
        {
            return Some(path);
        }
    }
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })?;
    for sdk in [
        PathBuf::from(&home).join("Library/Android/sdk"),
        PathBuf::from(&home).join("Android/Sdk"),
        PathBuf::from(&home).join("AppData/Local/Android/Sdk"),
    ] {
        if let Some(path) = latest_aapt2(sdk, executable) {
            return Some(path);
        }
    }
    None
}

fn latest_aapt2(sdk: PathBuf, executable: &str) -> Option<PathBuf> {
    let mut candidates = std::fs::read_dir(sdk.join("build-tools"))
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path().join(executable))
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    candidates.sort();
    candidates.pop()
}

pub(crate) fn project_root_path() -> PathBuf {
    let current = strip_unc_prefix(std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let mut path = current.clone();
    loop {
        if path.join("shield-stub").exists() && path.join("apps").exists() {
            return path;
        }
        if !path.pop() {
            break;
        }
    }
    current
}

pub(crate) fn parent_dir_string(path: &str) -> String {
    Path::new(path)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| path.to_string())
}
