use crate::app_paths::parent_dir_string;
use std::path::{Path, PathBuf};
use url::Url;

/// 只允许打开的仓库路径前缀（GitHub 上的 Shellsmith 官方仓库）。
const ALLOWED_REPO_PATH: &str = "/kairowan/Shellsmith";
/// 链接长度上限，避免异常输入进入系统处理程序。
const MAX_URL_LENGTH: usize = 2048;

pub(crate) fn show_in_folder(path: String) -> Result<(), String> {
    let dir = parent_dir_string(&path);
    #[cfg(target_os = "linux")]
    std::process::Command::new("xdg-open")
        .arg(&dir)
        .spawn()
        .map_err(|e| e.to_string())?;
    #[cfg(target_os = "macos")]
    std::process::Command::new("open")
        .arg(&dir)
        .spawn()
        .map_err(|e| e.to_string())?;
    #[cfg(target_os = "windows")]
    std::process::Command::new("explorer")
        .arg(&dir)
        .spawn()
        .map_err(|e| e.to_string())?;
    Ok(())
}

pub(crate) fn check_file_exists(path: String) -> bool {
    PathBuf::from(path).exists()
}

pub(crate) fn delete_file(path: String) -> Result<(), String> {
    let p = PathBuf::from(&path);
    ensure_deletable_file(&p)?;
    if p.exists() {
        std::fs::remove_file(&p).map_err(|e| format!("删除文件失败: {e}"))?;
    }
    Ok(())
}

pub(crate) fn open_url(url: String) -> Result<(), String> {
    // 校验后只使用重新序列化出的规范形式，调用方传入的原始字符串不再参与后续处理。
    let url = canonical_allowed_url(&url)?;
    #[cfg(target_os = "linux")]
    std::process::Command::new("xdg-open")
        .arg(&url)
        .spawn()
        .map_err(|e| e.to_string())?;
    #[cfg(target_os = "macos")]
    std::process::Command::new("open")
        .arg(&url)
        .spawn()
        .map_err(|e| e.to_string())?;
    #[cfg(target_os = "windows")]
    open_with_shell_execute(&url)?;
    Ok(())
}

/// 校验白名单并返回规范化的链接。
///
/// 只允许 `https://github.com/kairowan/Shellsmith` 及其子路径，且链接字符必须落在
/// 保守白名单内。
///
/// 这里必须做**结构化解析 + 字符白名单**，不能只比较字符串前缀：早先的实现只比前缀，
/// 且 Windows 分支把原始字符串交给 `cmd /c start` 解析，于是
/// `https://github.com/kairowan/Shellsmith/&calc.exe` 里的 `&` 会被 cmd 当作命令分隔符，
/// 点击更新说明中的这类链接即可在本机执行任意程序。
///
/// 两点配套约束：
/// - 调用侧改用系统 shell API（见 `open_with_shell_execute`），不再经过任何 shell；
/// - 这里额外拒绝 `& | ^ % $ ' " \` \\` 等字符，使校验不依赖具体打开方式，避免将来
///   换回命令行实现时重新引入解析面。
pub(crate) fn canonical_allowed_url(url: &str) -> Result<String, String> {
    let trimmed = url.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_URL_LENGTH {
        return Err("链接长度不合法".to_string());
    }
    if let Some(character) = trimmed.chars().find(|value| !is_safe_url_char(*value)) {
        return Err(format!("链接包含不允许的字符 {character:?}"));
    }
    let parsed = Url::parse(trimmed).map_err(|_| "链接格式不合法".to_string())?;
    if parsed.scheme() != "https" {
        return Err("只允许打开 HTTPS 链接".to_string());
    }
    if parsed.host_str() != Some("github.com") {
        return Err("只允许打开 GitHub 链接".to_string());
    }
    if parsed.port().is_some() {
        return Err("链接不允许指定端口".to_string());
    }
    let path = parsed.path();
    if path != ALLOWED_REPO_PATH && !path.starts_with(&format!("{ALLOWED_REPO_PATH}/")) {
        return Err("只允许打开 Shellsmith 官方仓库相关链接".to_string());
    }
    Ok(parsed.to_string())
}

/// 允许出现在链接里的字符：ASCII 字母数字与少量 URL 语法字符。
///
/// 刻意不包含 `& | ^ < > " ' \` \\ % $ ( ) ; * !`、空格与控制字符，也不包含非 ASCII。
fn is_safe_url_char(character: char) -> bool {
    character.is_ascii_alphanumeric()
        || matches!(
            character,
            '-' | '.' | '_' | '~' | '/' | ':' | '?' | '#' | '=' | '+' | '@' | '[' | ']' | ','
        )
}

/// Windows 上用 `ShellExecuteW` 打开链接，不经过 `cmd.exe`。
///
/// 走 shell 会引入命令行解析面（`&`、`|`、`^`、`%VAR%` 等），而这里只需要把 URL
/// 交给系统默认处理程序，因此直接调用 shell API。
#[cfg(target_os = "windows")]
fn open_with_shell_execute(url: &str) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    let wide = |value: &str| -> Vec<u16> {
        std::ffi::OsStr::new(value)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    };
    let operation = wide("open");
    let target = wide(url);
    // 返回值 ≤ 32 表示失败（ShellExecuteW 的历史约定）。
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            operation.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    if result as isize <= 32 {
        return Err(format!(
            "打开链接失败（ShellExecuteW 返回 {}）",
            result as isize
        ));
    }
    Ok(())
}

fn ensure_deletable_file(path: &Path) -> Result<(), String> {
    if path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| matches!(value.to_ascii_lowercase().as_str(), "apk" | "idsig"))
        .unwrap_or(false)
    {
        return Ok(());
    }

    Err("只允许删除 APK 或 idsig 文件".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 只允许删除_apk_和_idsig() {
        assert!(ensure_deletable_file(Path::new("/tmp/app.apk")).is_ok());
        assert!(ensure_deletable_file(Path::new("/tmp/app.apk.idsig")).is_ok());
        assert!(ensure_deletable_file(Path::new("/tmp/config.toml")).is_err());
    }

    #[test]
    fn 只允许打开项目_github_链接() {
        assert!(canonical_allowed_url("https://github.com/kairowan/Shellsmith/releases").is_ok());
        assert!(canonical_allowed_url("http://github.com/kairowan/Shellsmith").is_err());
        assert!(canonical_allowed_url("https://github.com/other/repo").is_err());
    }

    #[test]
    fn 拒绝_windows_命令分隔符注入() {
        // 修复前可在 Windows 上执行任意程序的载荷：`&` 直接进入 cmd 命令行。
        // 现在既不再经过 shell，字符白名单也会直接拒绝它。
        assert!(canonical_allowed_url("https://github.com/kairowan/Shellsmith/&calc.exe").is_err());
        for payload in [
            "https://github.com/kairowan/Shellsmith/&calc.exe",
            "https://github.com/kairowan/Shellsmith/|whoami",
            "https://github.com/kairowan/Shellsmith/^calc",
            "https://github.com/kairowan/Shellsmith/%COMSPEC%",
            "https://github.com/kairowan/Shellsmith/\" & calc",
            "https://github.com/kairowan/Shellsmith/`calc`",
            "https://github.com/kairowan/Shellsmith/\\calc",
            "https://github.com/kairowan/Shellsmith/;calc",
            "https://github.com/kairowan/Shellsmith/$HOME",
            "https://github.com/kairowan/Shellsmith/\ncalc",
            "https://github.com/kairowan/Shellsmith/ calc",
        ] {
            assert!(
                canonical_allowed_url(payload).is_err(),
                "该载荷应被拒绝: {payload:?}"
            );
        }
    }

    #[test]
    fn 规范形式只包含白名单字符() {
        let canonical =
            canonical_allowed_url("https://github.com/kairowan/Shellsmith/releases/tag/v1.6.3")
                .unwrap();
        assert!(canonical.chars().all(is_safe_url_char), "{canonical}");
    }

    #[test]
    fn 拒绝其他主机协议端口与相似前缀() {
        assert!(canonical_allowed_url("https://github.com.evil.test/kairowan/Shellsmith").is_err());
        assert!(canonical_allowed_url("https://github.com:8443/kairowan/Shellsmith").is_err());
        assert!(canonical_allowed_url("javascript:alert(1)").is_err());
        assert!(canonical_allowed_url("file:///etc/passwd").is_err());
        // 相似前缀不能通过：`/kairowan/Shellsmith-evil` 不是仓库子路径。
        assert!(canonical_allowed_url("https://github.com/kairowan/Shellsmith-evil").is_err());
        // 用户信息段会被 URL 解析丢弃，但这里仍要求主机精确匹配，故含用户信息的形式同样拒绝。
        assert!(canonical_allowed_url("https://github.com@evil.test/kairowan/Shellsmith").is_err());
        assert!(canonical_allowed_url("").is_err());
    }

    #[test]
    fn 保留仓库子路径与查询片段() {
        let canonical =
            canonical_allowed_url("https://github.com/kairowan/Shellsmith/issues/17?foo=bar#top")
                .unwrap();
        assert!(canonical.starts_with("https://github.com/kairowan/Shellsmith/issues/17"));
        assert!(canonical_allowed_url("https://github.com/kairowan/Shellsmith").is_ok());
    }
}
