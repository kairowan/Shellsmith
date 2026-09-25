use std::{env, fs, path::PathBuf};

const APP_ICON_PNG: &[u8] = include_bytes!("icons/png/128x128.png");

/// 将 Unix 时间戳转换为 YYYY-MM-DD（Howard Hinnant civil_from_days 算法）
fn build_date_utc() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    let z = secs / 86400 + 719468;
    let era = if z >= 0 {
        z / 146097
    } else {
        (z - 146096) / 146097
    };
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02}", y, m, d)
}

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("缺少 OUT_DIR 环境变量"));
    let icon_path = out_dir.join("shellsmith-app-icon.png");

    // Tauri 上下文需要可读取的运行时图标；使用正式品牌图标而非 1px 占位图。
    fs::write(&icon_path, APP_ICON_PNG).expect("写入应用图标失败");

    let tauri_config = serde_json::json!({
        "bundle": {
            "icon": [icon_path]
        }
    });

    println!("cargo:rustc-env=TAURI_CONFIG={}", tauri_config);

    let git_hash = std::process::Command::new("git")
        .args(["rev-parse", "--short=8", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=GIT_HASH={}", git_hash);
    println!("cargo:rustc-env=BUILD_DATE={}", build_date_utc());
    println!("cargo:rerun-if-changed=../../../.git/HEAD");
    println!("cargo:rerun-if-changed=../dist");
    println!("cargo:rerun-if-changed=icons/png/128x128.png");

    tauri_build::build();
}
