use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

use crate::protect::cache_identity::CacheIdentity;
use crate::EnvironmentPolicy;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NativeLibPackagingPolicy {
    Disabled,
    Enabled,
    Unspecified,
}

pub(crate) fn read_package_name(apk_dir: &Path) -> Result<String> {
    let content = fs::read_to_string(apk_dir.join("AndroidManifest.xml"))?;
    let start = content.find("<manifest").context("Manifest 缺少根标签")?;
    let end = find_tag_end(&content, start).context("Manifest 根标签未关闭")?;
    extract_xml_attr(&content[start..end], "package").context("Manifest 缺少包名")
}

pub(crate) fn read_native_lib_packaging_policy(apk_dir: &Path) -> Result<NativeLibPackagingPolicy> {
    let manifest_path = apk_dir.join("AndroidManifest.xml");
    let content = fs::read_to_string(&manifest_path).context("读取 AndroidManifest.xml 失败")?;
    let app_tag_start = content
        .find("<application")
        .context("AndroidManifest.xml 中未找到 <application> 标签")?;
    let app_tag_end = find_tag_end(&content, app_tag_start)
        .context("AndroidManifest.xml <application> 标签未正常关闭")?;
    let app_tag = &content[app_tag_start..app_tag_end];

    Ok(
        match extract_xml_attr(app_tag, "android:extractNativeLibs").as_deref() {
            Some("false") => NativeLibPackagingPolicy::Disabled,
            Some("true") => NativeLibPackagingPolicy::Enabled,
            Some(value) => {
                log::warn!("无法解析 extractNativeLibs 值 {value}，将保留原打包策略");
                NativeLibPackagingPolicy::Unspecified
            }
            None => NativeLibPackagingPolicy::Unspecified,
        },
    )
}

pub(crate) fn modify_manifest(
    apk_dir: &Path,
    stub_app: &str,
    stub_component_factory: Option<&str>,
    environment_policy: EnvironmentPolicy,
) -> Result<()> {
    let manifest_path = apk_dir.join("AndroidManifest.xml");
    let content = fs::read_to_string(&manifest_path).context("读取 AndroidManifest.xml 失败")?;
    if content.contains("android:name=\"dev.mocika.shield.ENV_POLICY\"")
        || content.contains("android:name='dev.mocika.shield.ENV_POLICY'")
    {
        anyhow::bail!("原 APK 已占用 Shellsmith 环境策略字段，无法安全写入运行策略");
    }
    if stub_component_factory.is_some()
        && (content.contains("android:name=\"dev.mocika.shield.ORIGINAL_COMPONENT_FACTORY\"")
            || content.contains("android:name='dev.mocika.shield.ORIGINAL_COMPONENT_FACTORY'"))
    {
        anyhow::bail!("原 APK 已占用 Shellsmith 原组件工厂字段，无法安全保存原配置");
    }

    let app_tag_start = content
        .find("<application")
        .context("AndroidManifest.xml 中未找到 <application> 标签")?;
    let app_tag_end = find_tag_end(&content, app_tag_start)
        .context("AndroidManifest.xml <application> 标签未正常关闭")?;
    let app_tag = &content[app_tag_start..app_tag_end];

    let orig_app = extract_xml_attr(app_tag, "android:name")
        .unwrap_or_else(|| "android.app.Application".to_string());
    let orig_component_factory = extract_xml_attr(app_tag, "android:appComponentFactory");
    log::info!("检测到原始 Application: {}", orig_app);

    let new_app_tag = set_xml_attr(app_tag, "android:name", stub_app);
    let new_app_tag = match stub_component_factory {
        Some(factory) => set_xml_attr(&new_app_tag, "android:appComponentFactory", factory),
        None => remove_xml_attr(&new_app_tag, "android:appComponentFactory"),
    };

    let already_injected = content.contains("android:name=\"ORIGINAL_APPLICATION\"");
    let meta_original = if already_injected {
        String::new()
    } else {
        format!(
            "\n        <meta-data\n            android:name=\"ORIGINAL_APPLICATION\"\n            android:value=\"{}\" />",
            orig_app
        )
    };
    let meta_environment = format!(
        "\n        <meta-data\n            android:name=\"dev.mocika.shield.ENV_POLICY\"\n            android:value=\"{}\" />",
        environment_policy.as_str()
    );
    let meta_component_factory = match (stub_component_factory, orig_component_factory) {
        (Some(_), Some(original)) => format!(
            "\n        <meta-data\n            android:name=\"dev.mocika.shield.ORIGINAL_COMPONENT_FACTORY\"\n            android:value=\"{}\" />",
            original
        ),
        _ => String::new(),
    };
    let injected_metadata = meta_original + &meta_component_factory + &meta_environment;

    let (prefix_tag, suffix) = if new_app_tag.trim_end().ends_with("/>") {
        let tag_body = new_app_tag
            .trim_end()
            .strip_suffix("/>")
            .unwrap_or(&new_app_tag)
            .trim_end_matches(|c: char| c.is_whitespace() || c == '/')
            .to_string();
        (
            format!("{}>", tag_body),
            injected_metadata + "\n    </application>",
        )
    } else {
        (new_app_tag.to_string(), injected_metadata)
    };

    let result = format!(
        "{}{}{}{}",
        &content[..app_tag_start],
        prefix_tag,
        suffix,
        &content[app_tag_end..]
    );

    fs::write(&manifest_path, result).context("写入 AndroidManifest.xml 失败")?;
    Ok(())
}

pub(crate) fn add_cache_identity(apk_dir: &Path, identity: &CacheIdentity) -> Result<()> {
    let manifest_path = apk_dir.join("AndroidManifest.xml");
    let content = fs::read_to_string(&manifest_path).context("读取 AndroidManifest.xml 失败")?;
    let close = content
        .rfind("</application>")
        .context("AndroidManifest.xml 中未找到 </application>")?;
    let metadata = format!(
        "\n        <meta-data android:name=\"dev.mocika.shield.CACHE_SCHEMA\" android:value=\"{}\" />\n        <meta-data android:name=\"dev.mocika.shield.CACHE_DEX_COUNT\" android:value=\"{}\" />\n        <meta-data android:name=\"dev.mocika.shield.CACHE_ROOT_SHA256\" android:value=\"{}\" />\n    ",
        identity.schema, identity.dex_count, identity.root_sha256
    );
    let result = format!("{}{}{}", &content[..close], metadata, &content[close..]);
    fs::write(manifest_path, result).context("写入缓存身份到 AndroidManifest.xml 失败")
}

pub(crate) fn add_xop_pvm2_marker(apk_dir: &Path) -> Result<()> {
    let manifest_path = apk_dir.join("AndroidManifest.xml");
    let content = fs::read_to_string(&manifest_path).context("读取 AndroidManifest.xml 失败")?;
    const FIELD: &str = "dev.mocika.shield.XOP_PVM2";
    if content.contains(FIELD) {
        anyhow::bail!("原 APK 已占用 Shellsmith PVM2 能力字段");
    }
    let close = content
        .rfind("</application>")
        .context("AndroidManifest.xml 中未找到 </application>")?;
    let metadata =
        format!("\n        <meta-data android:name=\"{FIELD}\" android:value=\"true\" />\n    ");
    let result = format!("{}{}{}", &content[..close], metadata, &content[close..]);
    fs::write(manifest_path, result).context("写入 PVM2 能力到 AndroidManifest.xml 失败")
}

pub(crate) fn configure_byos(apk_dir: &Path, auth: crate::ByosAuth) -> Result<()> {
    // apktool 将 uses-sdk 移入此配置；不自动提高宿主应用声明的系统下限。
    let config = fs::read_to_string(apk_dir.join("apktool.yml"))?;
    let min_api = config.lines().find_map(|line| {
        line.trim()
            .strip_prefix("minSdkVersion:")
            .and_then(|v| v.trim().trim_matches(['\'', '"']).parse::<u32>().ok())
    });
    anyhow::ensure!(
        min_api.is_some_and(|api| api >= auth.min_android_api()),
        "BYOS {} 要求输入 APK 的 minSdkVersion 至少为 {}，请先调整应用构建配置",
        auth.as_str(),
        auth.min_android_api()
    );
    let path = apk_dir.join("AndroidManifest.xml");
    let mut content = fs::read_to_string(&path)?;
    anyhow::ensure!(
        !content.contains("dev.mocika.shield.BYOS"),
        "原 APK 已占用 BYOS 能力字段"
    );
    let close = content
        .rfind("</application>")
        .context("Manifest 缺少 application")?;
    content.insert_str(
        close,
        "<meta-data android:name=\"dev.mocika.shield.BYOS\" android:value=\"true\" />\n",
    );
    if !content.contains("\"android.permission.INTERNET\"") {
        let start = content
            .find("<application")
            .context("Manifest 缺少 application")?;
        content.insert_str(
            start,
            "<uses-permission android:name=\"android.permission.INTERNET\" />\n",
        );
    }
    // Android 11+ 的包可见性限制会影响 SDK 对 Play 商店的签名检查。
    if auth == crate::ByosAuth::PlayIntegrity && !content.contains("\"com.android.vending\"") {
        let query = "<package android:name=\"com.android.vending\" />";
        if let Some(close) = content.rfind("</queries>") {
            content.insert_str(close, query);
        } else if let Some(start) = content.find("<queries") {
            let end = find_tag_end(&content, start).context("Manifest queries 标签无效")?;
            anyhow::ensure!(
                content[start..end].trim_end().ends_with("/>"),
                "Manifest queries 标签未闭合"
            );
            content.replace_range(start..end, &format!("<queries>{query}</queries>"));
        } else {
            let start = content
                .find("<application")
                .context("Manifest 缺少 application")?;
            content.insert_str(start, &format!("<queries>{query}</queries>\n"));
        }
    }
    fs::write(path, content)?;
    Ok(())
}

pub(crate) fn configure_key_source(
    apk_dir: &Path,
    auth: Option<crate::ByosAuth>,
    risk_events: bool,
) -> Result<()> {
    let path = apk_dir.join("AndroidManifest.xml");
    let mut content = fs::read_to_string(&path)?;
    anyhow::ensure!(
        !content.contains("dev.mocika.shield.KEY_SOURCE")
            && !content.contains("dev.mocika.shield.RISK_PROTOCOL")
            && !apk_dir.join("assets/shellsmith-risk-v1.json").exists(),
        "原 APK 已占用 Shellsmith 密钥来源或风险协议配置"
    );
    let close = content
        .rfind("</application>")
        .context("Manifest 缺少 application")?;
    let source = if auth.is_some() { "byos" } else { "local" };
    let protocol = u8::from(risk_events && auth == Some(crate::ByosAuth::DeviceApproval));
    content.insert_str(close, &format!("<meta-data android:name=\"dev.mocika.shield.KEY_SOURCE\" android:value=\"{source}\" />\n<meta-data android:name=\"dev.mocika.shield.RISK_PROTOCOL\" android:value=\"{protocol}\" />\n"));
    fs::write(path, content)?;
    Ok(())
}

pub(crate) fn add_memory_payload_metrics(apk_dir: &Path, identity: &CacheIdentity) -> Result<()> {
    let manifest_path = apk_dir.join("AndroidManifest.xml");
    let content = fs::read_to_string(&manifest_path).context("读取 AndroidManifest.xml 失败")?;
    const FIELD: &str = "dev.mocika.shield.PAYLOAD_DEX_BYTES";
    if content.contains(FIELD) {
        anyhow::bail!("原 APK 已占用 Shellsmith 载荷大小字段，无法安全写入内存预算数据");
    }
    let close = content
        .rfind("</application>")
        .context("AndroidManifest.xml 中未找到 </application>")?;
    let metadata = format!(
        "\n        <meta-data android:name=\"{FIELD}\" android:value=\"bytes:{}\" />\n    ",
        identity.total_dex_bytes
    );
    let result = format!("{}{}{}", &content[..close], metadata, &content[close..]);
    fs::write(manifest_path, result).context("写入内存预算元数据到 AndroidManifest.xml 失败")
}

/// 写入各 ABI 壳库的明文摘要，供运行时在加载原生库前比对。
///
/// 值为 `abi:hex` 以逗号连接，例如 `arm64-v8a:ab12…,armeabi-v7a:cd34…`。
/// 该字段本身不构成机密性保证：能改写 APK 的攻击者同样能改这里的值，
/// 它的作用是让「替换壳库但忘记同步摘要」这类改动在启动时立刻暴露。
pub(crate) fn add_native_integrity(
    apk_dir: &Path,
    digests: &std::collections::BTreeMap<String, String>,
) -> Result<()> {
    if digests.is_empty() {
        return Ok(());
    }
    let manifest_path = apk_dir.join("AndroidManifest.xml");
    let content = fs::read_to_string(&manifest_path).context("读取 AndroidManifest.xml 失败")?;
    const FIELD: &str = "dev.mocika.shield.NATIVE_INTEGRITY";
    if content.contains(FIELD) {
        anyhow::bail!("原 APK 已占用 Shellsmith 原生库完整性字段");
    }
    let value = digests
        .iter()
        .map(|(abi, digest)| format!("{abi}:{digest}"))
        .collect::<Vec<_>>()
        .join(",");
    let close = content
        .rfind("</application>")
        .context("AndroidManifest.xml 中未找到 </application>")?;
    let metadata =
        format!("\n        <meta-data android:name=\"{FIELD}\" android:value=\"{value}\" />\n    ");
    let result = format!("{}{}{}", &content[..close], metadata, &content[close..]);
    fs::write(manifest_path, result).context("写入原生库完整性到 AndroidManifest.xml 失败")
}

fn find_tag_end(content: &str, start: usize) -> Option<usize> {
    let s = &content[start..];
    let mut in_quote: Option<u8> = None;
    for (i, &b) in s.as_bytes().iter().enumerate() {
        match in_quote {
            Some(q) if b == q => in_quote = None,
            Some(_) => {}
            None => match b {
                b'"' | b'\'' => in_quote = Some(b),
                b'>' => return Some(start + i + 1),
                _ => {}
            },
        }
    }
    None
}

fn extract_xml_attr(tag: &str, attr: &str) -> Option<String> {
    for &q in b"\"'" {
        let needle = format!("{}={}", attr, q as char);
        if let Some(p) = tag.find(&needle) {
            let val_start = p + needle.len();
            let val_end = tag[val_start..].find(q as char)? + val_start;
            return Some(tag[val_start..val_end].to_string());
        }
    }
    None
}

fn set_xml_attr(tag: &str, attr: &str, value: &str) -> String {
    for &q in b"\"'" {
        let needle = format!("{}={}", attr, q as char);
        if let Some(p) = tag.find(&needle) {
            let val_start = p + needle.len();
            let val_end = match tag[val_start..].find(q as char) {
                Some(e) => e + val_start,
                None => return tag.to_string(),
            };
            return format!(
                "{}{}{}\"{}\"{}",
                &tag[..p],
                attr,
                '=',
                value,
                &tag[val_end + 1..]
            );
        }
    }
    let close = find_tag_end(tag, 0).unwrap_or(tag.len());
    let insert = close - if tag[..close].ends_with("/>") { 2 } else { 1 };
    format!(
        "{} {}=\"{}\"{}",
        &tag[..insert],
        attr,
        value,
        &tag[insert..]
    )
}

fn remove_xml_attr(tag: &str, attr: &str) -> String {
    for &q in b"\"'" {
        let needle = format!("{}={}", attr, q as char);
        if let Some(attr_start) = tag.find(&needle) {
            let val_start = attr_start + needle.len();
            let val_end = match tag[val_start..].find(q as char) {
                Some(e) => val_start + e + 1,
                None => continue,
            };
            let rest = tag[val_end..].trim_start_matches(' ');
            let prefix = &tag[..attr_start];
            let prefix = if prefix.ends_with(' ') {
                prefix
            } else {
                prefix.trim_end_matches(' ')
            };
            return format!("{}{}", prefix, rest);
        }
    }
    tag.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 密钥来源和风险协议按实际模式与运行时能力写入() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("AndroidManifest.xml");
        for (auth, supported, source, protocol) in [
            (None, false, "local", 0),
            (Some(crate::ByosAuth::DeviceApproval), false, "byos", 0),
            (Some(crate::ByosAuth::DeviceApproval), true, "byos", 1),
            (Some(crate::ByosAuth::PlayIntegrity), false, "byos", 0),
        ] {
            fs::write(&path, "<manifest><application></application></manifest>").unwrap();
            configure_key_source(dir.path(), auth, supported).unwrap();
            let result = fs::read_to_string(&path).unwrap();
            assert!(result.contains(&format!("KEY_SOURCE\" android:value=\"{source}\"")));
            assert!(result.contains(&format!("RISK_PROTOCOL\" android:value=\"{protocol}\"")));
            assert!(configure_key_source(dir.path(), auth, supported).is_err());
        }
    }

    #[test]
    fn byos_requires_supported_sdk_and_adds_permission_once() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = "<manifest><application></application></manifest>";
        for (auth, required_api) in [
            (crate::ByosAuth::DeviceApproval, 24),
            (crate::ByosAuth::PlayIntegrity, 29),
        ] {
            for version in [
                "19", "23", "24", "25", "26", "27", "28", "invalid", "29", "30", "35",
            ] {
                fs::write(
                    dir.path().join("apktool.yml"),
                    format!("sdkInfo:\n  minSdkVersion: '{version}'\n"),
                )
                .unwrap();
                fs::write(dir.path().join("AndroidManifest.xml"), manifest).unwrap();
                let accepted = version.parse::<u32>().is_ok_and(|api| api >= required_api);
                assert_eq!(configure_byos(dir.path(), auth).is_ok(), accepted);
                let result = fs::read_to_string(dir.path().join("AndroidManifest.xml")).unwrap();
                if accepted {
                    assert_eq!(result.matches("android.permission.INTERNET").count(), 1);
                    assert!(result.contains("dev.mocika.shield.BYOS"));
                    assert_eq!(
                        result.contains("com.android.vending"),
                        auth == crate::ByosAuth::PlayIntegrity
                    );
                    assert!(configure_byos(dir.path(), auth).is_err());
                } else {
                    assert_eq!(result, manifest);
                }
            }
        }
        fs::write(dir.path().join("AndroidManifest.xml"), "<manifest><uses-permission android:name=\"android.permission.INTERNET\"/><application></application></manifest>").unwrap();
        configure_byos(dir.path(), crate::ByosAuth::PlayIntegrity).unwrap();
        assert_eq!(
            fs::read_to_string(dir.path().join("AndroidManifest.xml"))
                .unwrap()
                .matches("android.permission.INTERNET")
                .count(),
            1
        );
        fs::write(dir.path().join("AndroidManifest.xml"), manifest).unwrap();
        configure_byos(dir.path(), crate::ByosAuth::DeviceApproval).unwrap();
        assert!(!fs::read_to_string(dir.path().join("AndroidManifest.xml"))
            .unwrap()
            .contains("com.android.vending"));
        for queries in [
            "<queries/>",
            "<queries><package android:name=\"other.app\"/></queries>",
            "<queries><package android:name=\"com.android.vending\"/></queries>",
        ] {
            fs::write(
                dir.path().join("AndroidManifest.xml"),
                format!("<manifest>{queries}<application></application></manifest>"),
            )
            .unwrap();
            configure_byos(dir.path(), crate::ByosAuth::PlayIntegrity).unwrap();
            let result = fs::read_to_string(dir.path().join("AndroidManifest.xml")).unwrap();
            assert_eq!(result.matches("<queries>").count(), 1);
            assert_eq!(result.matches("com.android.vending").count(), 1);
            assert_eq!(result.contains("other.app"), queries.contains("other.app"));
        }
    }

    #[test]
    fn find_tag_end_simple_tag() {
        let s = r#"<application android:label="app">"#;
        assert_eq!(find_tag_end(s, 0), Some(s.len()));
    }

    #[test]
    fn find_tag_end_self_closing() {
        let s = r#"<application />"#;
        assert_eq!(find_tag_end(s, 0), Some(s.len()));
    }

    #[test]
    fn find_tag_end_gt_inside_quoted_attr_skipped() {
        let s = r#"<application android:label="a>b">"#;
        assert_eq!(find_tag_end(s, 0), Some(s.len()));
    }

    #[test]
    fn find_tag_end_with_nonzero_start() {
        let s = "HEADER<application>";
        assert_eq!(find_tag_end(s, 6), Some(s.len()));
    }

    #[test]
    fn extract_xml_attr_double_quoted() {
        let tag = r#"<application android:name="com.example.App">"#;
        assert_eq!(
            extract_xml_attr(tag, "android:name"),
            Some("com.example.App".to_string())
        );
    }

    #[test]
    fn extract_xml_attr_not_found_returns_none() {
        let tag = r#"<application android:label="app">"#;
        assert_eq!(extract_xml_attr(tag, "android:name"), None);
    }

    #[test]
    fn set_xml_attr_replaces_existing_value() {
        let tag = r#"<application android:name="com.example.App">"#;
        let result = set_xml_attr(tag, "android:name", "dev.mocika.StubApp");
        assert!(result.contains(r#"android:name="dev.mocika.StubApp""#));
        assert!(!result.contains("com.example.App"));
    }

    #[test]
    fn set_xml_attr_inserts_when_absent() {
        let tag = r#"<application android:label="app">"#;
        let result = set_xml_attr(tag, "android:name", "dev.mocika.StubApp");
        assert!(result.contains(r#"android:name="dev.mocika.StubApp""#));
    }

    #[test]
    fn remove_xml_attr_removes_found_attr() {
        let tag = r#"<application android:appComponentFactory="abc" android:name="App">"#;
        let result = remove_xml_attr(tag, "android:appComponentFactory");
        assert!(!result.contains("android:appComponentFactory"));
        assert!(result.contains(r#"android:name="App""#));
    }

    #[test]
    fn remove_xml_attr_not_found_returns_original() {
        let tag = r#"<application android:name="App">"#;
        let result = remove_xml_attr(tag, "android:nonExistent");
        assert_eq!(result, tag);
    }

    #[test]
    fn read_native_lib_packaging_policy_distinguishes_three_states() {
        for (value, expected) in [
            (Some("false"), NativeLibPackagingPolicy::Disabled),
            (Some("true"), NativeLibPackagingPolicy::Enabled),
            (None, NativeLibPackagingPolicy::Unspecified),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let attribute = value
                .map(|it| format!(r#" android:extractNativeLibs="{it}""#))
                .unwrap_or_default();
            let manifest =
                format!(r#"<manifest><application{attribute} android:name="App" /></manifest>"#);
            fs::write(dir.path().join("AndroidManifest.xml"), manifest).unwrap();

            assert_eq!(
                read_native_lib_packaging_policy(dir.path()).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn native_integrity_writes_per_abi_digests() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = r#"<manifest><application android:name="App"></application></manifest>"#;
        fs::write(dir.path().join("AndroidManifest.xml"), manifest).unwrap();

        let mut digests = std::collections::BTreeMap::new();
        digests.insert("arm64-v8a".to_string(), "aabb".to_string());
        digests.insert("armeabi-v7a".to_string(), "ccdd".to_string());
        add_native_integrity(dir.path(), &digests).unwrap();

        let result = fs::read_to_string(dir.path().join("AndroidManifest.xml")).unwrap();
        assert!(result.contains("dev.mocika.shield.NATIVE_INTEGRITY"));
        assert!(result.contains("arm64-v8a:aabb,armeabi-v7a:ccdd"));
    }

    #[test]
    fn native_integrity_skips_empty_and_rejects_occupied_field() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = r#"<manifest><application android:name="App"></application></manifest>"#;
        fs::write(dir.path().join("AndroidManifest.xml"), manifest).unwrap();

        // 空摘要不写入任何字段
        add_native_integrity(dir.path(), &std::collections::BTreeMap::new()).unwrap();
        let untouched = fs::read_to_string(dir.path().join("AndroidManifest.xml")).unwrap();
        assert!(!untouched.contains("NATIVE_INTEGRITY"));

        // 原 APK 已占用该字段时拒绝写入，避免覆盖既有值
        let occupied = r#"<manifest><application>
        <meta-data android:name="dev.mocika.shield.NATIVE_INTEGRITY" android:value="x" />
        </application></manifest>"#;
        fs::write(dir.path().join("AndroidManifest.xml"), occupied).unwrap();
        let mut digests = std::collections::BTreeMap::new();
        digests.insert("arm64-v8a".to_string(), "aabb".to_string());
        assert!(add_native_integrity(dir.path(), &digests).is_err());
    }

    #[test]
    fn modify_manifest_preserves_extract_native_libs() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = r#"<manifest><application android:name="App" android:extractNativeLibs="false" /></manifest>"#;
        fs::write(dir.path().join("AndroidManifest.xml"), manifest).unwrap();

        modify_manifest(
            dir.path(),
            "dev.mocika.StubApp",
            None,
            EnvironmentPolicy::Compatible,
        )
        .unwrap();

        let result = fs::read_to_string(dir.path().join("AndroidManifest.xml")).unwrap();
        assert!(result.contains(r#"android:extractNativeLibs="false""#));
    }

    #[test]
    fn modify_manifest_replaces_application_name_and_injects_meta() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = concat!(
            r#"<?xml version="1.0" encoding="utf-8"?>"#,
            "\n<manifest package=\"com.example\">\n",
            "    <application android:name=\"com.example.App\">\n",
            "    </application>\n</manifest>"
        );
        fs::write(dir.path().join("AndroidManifest.xml"), manifest).unwrap();
        modify_manifest(
            dir.path(),
            "dev.mocika.StubApp",
            None,
            EnvironmentPolicy::Strict,
        )
        .unwrap();
        let result = fs::read_to_string(dir.path().join("AndroidManifest.xml")).unwrap();
        assert!(result.contains(r#"android:name="dev.mocika.StubApp""#));
        assert!(result.contains("ORIGINAL_APPLICATION"));
        assert!(result.contains("com.example.App"));
        assert!(result.contains("dev.mocika.shield.ENV_POLICY"));
        assert!(result.contains("strict"));
    }

    #[test]
    fn 内存候选保存并替换原组件工厂() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = concat!(
            "<manifest><application android:name=\"com.example.App\" ",
            "android:appComponentFactory=\"androidx.core.app.CoreComponentFactory\">",
            "</application></manifest>"
        );
        fs::write(dir.path().join("AndroidManifest.xml"), manifest).unwrap();

        modify_manifest(
            dir.path(),
            "msk.StubApp",
            Some("msk.StubFactory"),
            EnvironmentPolicy::Compatible,
        )
        .unwrap();

        let result = fs::read_to_string(dir.path().join("AndroidManifest.xml")).unwrap();
        assert!(result.contains(r#"android:appComponentFactory="msk.StubFactory""#));
        assert!(result.contains("dev.mocika.shield.ORIGINAL_COMPONENT_FACTORY"));
        assert!(result.contains("androidx.core.app.CoreComponentFactory"));
    }

    #[test]
    fn 内存候选未声明原组件工厂时不生成原工厂元数据() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("AndroidManifest.xml"),
            r#"<manifest><application android:name="App" /></manifest>"#,
        )
        .unwrap();

        modify_manifest(
            dir.path(),
            "msk.StubApp",
            Some("msk.StubFactory"),
            EnvironmentPolicy::Compatible,
        )
        .unwrap();

        let result = fs::read_to_string(dir.path().join("AndroidManifest.xml")).unwrap();
        assert!(result.contains(r#"android:appComponentFactory="msk.StubFactory""#));
        assert!(!result.contains("dev.mocika.shield.ORIGINAL_COMPONENT_FACTORY"));
    }

    #[test]
    fn 内存候选拒绝原应用占用原组件工厂字段() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("AndroidManifest.xml"),
            concat!(
                "<manifest><application>",
                "<meta-data android:name=\"dev.mocika.shield.ORIGINAL_COMPONENT_FACTORY\" ",
                "android:value=\"occupied\" />",
                "</application></manifest>"
            ),
        )
        .unwrap();

        let error = modify_manifest(
            dir.path(),
            "msk.StubApp",
            Some("msk.StubFactory"),
            EnvironmentPolicy::Compatible,
        )
        .unwrap_err();
        assert!(error.to_string().contains("已占用"));
    }

    #[test]
    fn modify_manifest_self_closing_application_expanded() {
        let dir = tempfile::tempdir().unwrap();
        for application in [
            "<application/>",
            "<application android:name=\"com.example.App\" />",
        ] {
            let manifest = format!("<manifest package=\"com.example\">{application}</manifest>");
            fs::write(dir.path().join("AndroidManifest.xml"), manifest).unwrap();
            modify_manifest(
                dir.path(),
                "dev.mocika.StubApp",
                Some("dev.mocika.Factory"),
                EnvironmentPolicy::Compatible,
            )
            .unwrap();
            let result = fs::read_to_string(dir.path().join("AndroidManifest.xml")).unwrap();
            assert!(result.contains(r#"android:name="dev.mocika.StubApp""#));
            assert!(result.contains("</application>"));
            assert!(result.contains("ORIGINAL_APPLICATION"));
            assert!(result.contains(r#"android:appComponentFactory="dev.mocika.Factory""#));
            assert!(!result.contains("/ android:"));
        }
    }

    #[test]
    fn modify_manifest_already_injected_no_duplicate_meta() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = concat!(
            r#"<?xml version="1.0" encoding="utf-8"?>"#,
            "\n<manifest package=\"com.example\">\n",
            "    <application android:name=\"dev.mocika.StubApp\">\n",
            "        <meta-data android:name=\"ORIGINAL_APPLICATION\"",
            " android:value=\"com.example.App\" />\n",
            "    </application>\n</manifest>"
        );
        fs::write(dir.path().join("AndroidManifest.xml"), manifest).unwrap();
        modify_manifest(
            dir.path(),
            "dev.mocika.StubApp",
            None,
            EnvironmentPolicy::Compatible,
        )
        .unwrap();
        let result = fs::read_to_string(dir.path().join("AndroidManifest.xml")).unwrap();
        assert_eq!(result.matches("ORIGINAL_APPLICATION").count(), 1);
    }

    #[test]
    fn modify_manifest_rejects_occupied_environment_policy() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = r#"<manifest><application><meta-data android:name="dev.mocika.shield.ENV_POLICY" android:value="strict" /></application></manifest>"#;
        fs::write(dir.path().join("AndroidManifest.xml"), manifest).unwrap();

        let error = modify_manifest(
            dir.path(),
            "dev.mocika.StubApp",
            None,
            EnvironmentPolicy::Compatible,
        )
        .unwrap_err();
        assert!(error.to_string().contains("已占用"));
    }

    #[test]
    fn 内存候选写入可稳定按字符串读取的载荷大小() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("AndroidManifest.xml"),
            "<manifest><application></application></manifest>",
        )
        .unwrap();
        let identity = CacheIdentity {
            schema: 1,
            dex_count: 2,
            total_dex_bytes: 118_489_088,
            root_sha256: "a".repeat(64),
        };

        add_memory_payload_metrics(dir.path(), &identity).unwrap();

        let result = fs::read_to_string(dir.path().join("AndroidManifest.xml")).unwrap();
        assert!(result.contains("dev.mocika.shield.PAYLOAD_DEX_BYTES"));
        assert!(result.contains("bytes:118489088"));
    }

    #[test]
    fn pvm2_marker_is_explicit_and_rejects_collision() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("AndroidManifest.xml"),
            "<manifest><application></application></manifest>",
        )
        .unwrap();
        add_xop_pvm2_marker(dir.path()).unwrap();
        let result = fs::read_to_string(dir.path().join("AndroidManifest.xml")).unwrap();
        assert!(result.contains("dev.mocika.shield.XOP_PVM2"));
        assert!(result.contains("android:value=\"true\""));
        assert!(add_xop_pvm2_marker(dir.path()).is_err());
    }
}
