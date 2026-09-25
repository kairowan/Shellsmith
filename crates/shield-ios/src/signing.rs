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
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>method</key>
    <string>{method}</string>
    <key>teamID</key>
    <string>{team_id}</string>
    <key>signingStyle</key>
    <string>automatic</string>
    <key>stripSwiftSymbols</key>
    <true/>
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
}
