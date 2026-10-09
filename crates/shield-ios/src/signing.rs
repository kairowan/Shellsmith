use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) fn prepare_export_options(
    output_directory: &Path,
    provided: Option<&Path>,
    method: &str,
    team_id: &str,
) -> Result<PathBuf> {
    validate_export_request(provided, method)?;
    let target = output_directory.join("ExportOptions.plist");
    if let Some(source) = provided {
        let content = fs::read(source)
            .with_context(|| format!("读取 ExportOptions.plist 失败：{}", source.display()))?;
        fs::write(&target, content)?;
        return Ok(target);
    }
    let method = xml_escape(method);
    let team_id = xml_escape(team_id);
    // App Store 分发描述文件通常不在本机，导出必须允许 Xcode 联网换取；
    // 这里固定 destination=export，保证产出可校验的本地 IPA 而不是直接上传。
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>method</key>
    <string>{method}</string>
    <key>destination</key>
    <string>export</string>
    <key>teamID</key>
    <string>{team_id}</string>
    <key>signingStyle</key>
    <string>automatic</string>
    <key>stripSwiftSymbols</key>
    <true/>
    <key>uploadSymbols</key>
    <true/>
    <key>manageAppVersionAndBuildNumber</key>
    <false/>
</dict>
</plist>
"#
    );
    fs::write(&target, plist)?;
    Ok(target)
}

pub(crate) fn validate_export_request(provided: Option<&Path>, method: &str) -> Result<()> {
    if let Some(source) = provided {
        if !source.is_file() {
            anyhow::bail!("ExportOptions.plist 不存在：{}", source.display());
        }
        if source.metadata()?.len() > 1024 * 1024 {
            anyhow::bail!("ExportOptions.plist 超过 1 MiB 限制");
        }
        // destination=upload 时 xcodebuild 会把包直接上传，不写本地 IPA，
        // 加固流程拿不到可校验产物，必须提前说清楚而不是等到找不到 IPA。
        if plist_string_value(&source_text(source)?, "destination")
            .is_some_and(|value| value.eq_ignore_ascii_case("upload"))
        {
            anyhow::bail!(
                "ExportOptions.plist 的 destination 为 upload：xcodebuild 只会直接上传、不会生成本地 IPA。请改为 export 后再导出；需要上传请用导出的 IPA 单独提交"
            );
        }
        return Ok(());
    }
    let allowed = [
        "development",
        "ad-hoc",
        "app-store-connect",
        "enterprise",
        "debugging",
        "release-testing",
    ];
    if !allowed.contains(&method) {
        anyhow::bail!("不支持的 iOS 导出方式：{method}");
    }
    Ok(())
}

fn source_text(source: &Path) -> Result<String> {
    let bytes = fs::read(source)
        .with_context(|| format!("读取 ExportOptions.plist 失败：{}", source.display()))?;
    // Xcode 写出的 plist 是 XML；二进制 plist 读不出目标键时按“未声明”处理。
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// 读取 plist 中 `<key>name</key><string>value</string>` 形式的字符串值。
fn plist_string_value(content: &str, key: &str) -> Option<String> {
    let rest = content.split_once(&format!("<key>{key}</key>"))?.1;
    let rest = &rest[rest.find("<string>")? + "<string>".len()..];
    let value = &rest[..rest.find("</string>")?];
    Some(value.trim().to_string())
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_safe_export_options() {
        let temp = tempfile::tempdir().unwrap();
        let path = prepare_export_options(temp.path(), None, "development", "ABCDE12345").unwrap();
        let content = fs::read_to_string(path).unwrap();
        assert!(content.contains("<string>development</string>"));
        assert!(content.contains("<string>ABCDE12345</string>"));
        assert!(!content.contains("password"));
        assert!(validate_export_request(None, "unsupported").is_err());
    }

    #[test]
    fn 自动导出选项固定导出本地_ipa_并保留证书与符号设置() {
        let temp = tempfile::tempdir().unwrap();
        let path =
            prepare_export_options(temp.path(), None, "app-store-connect", "TEAM123456").unwrap();
        let content = fs::read_to_string(path).unwrap();
        assert!(content.contains("<key>method</key>\n    <string>app-store-connect</string>"));
        assert!(content.contains("<key>destination</key>\n    <string>export</string>"));
        assert!(content.contains("<key>signingStyle</key>\n    <string>automatic</string>"));
        assert!(content.contains("<key>uploadSymbols</key>\n    <true/>"));
        assert!(content.contains("<key>manageAppVersionAndBuildNumber</key>\n    <false/>"));
    }

    #[test]
    fn 提供的导出选项拒绝只上传不产出_ipa() {
        let temp = tempfile::tempdir().unwrap();
        let upload = temp.path().join("Upload.plist");
        fs::write(
            &upload,
            "<plist><dict><key>method</key><string>app-store-connect</string>\
             <key>destination</key><string>upload</string></dict></plist>",
        )
        .unwrap();
        let error = validate_export_request(Some(&upload), "app-store-connect")
            .unwrap_err()
            .to_string();
        assert!(error.contains("destination"));
        assert!(error.contains("export"));

        let export = temp.path().join("Export.plist");
        fs::write(
            &export,
            "<plist><dict><key>method</key><string>app-store-connect</string>\
             <key>destination</key><string>export</string></dict></plist>",
        )
        .unwrap();
        assert!(validate_export_request(Some(&export), "app-store-connect").is_ok());
    }

    #[test]
    fn plist_字符串键读取忽略空白并兼容大写() {
        let content = "<dict>\n<key>destination</key>\n<string> UPLOAD </string>\n</dict>";
        assert_eq!(
            plist_string_value(content, "destination").as_deref(),
            Some("UPLOAD")
        );
        assert_eq!(plist_string_value(content, "method"), None);
    }
}
