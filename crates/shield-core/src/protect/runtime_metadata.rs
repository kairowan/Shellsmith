use anyhow::{Context, Result};

use crate::protect::native_alias::NativeAliasProtocol;

const STANDARD_RUNTIME_PROTOCOL: u32 = 2;
const MEMORY_RUNTIME_PROTOCOL: u32 = 3;
const CACHE_SCHEMA: u32 = 1;
const MEMORY_DEX_MIN_API: u32 = 31;

#[derive(Debug, Clone)]
pub(crate) struct RuntimeMetadata {
    pub(crate) stub_application: String,
    pub(crate) stub_component_factory: Option<String>,
    pub(crate) native_alias: NativeAliasProtocol,
    pub(crate) environment_policy: bool,
    pub(crate) memory_dex: bool,
    pub(crate) xop_pvm2: bool,
    pub(crate) xop_vm_bridge: Option<String>,
    pub(crate) xop_vm_bridge_method: Option<String>,
    pub(crate) assets_pas2: bool,
    pub(crate) assets_bridge: Option<String>,
    pub(crate) assets_bridge_method: Option<String>,
    pub(crate) native_so_text: bool,
    pub(crate) native_so_functions: bool,
}

impl RuntimeMetadata {
    pub(crate) fn parse(json: &str) -> Result<Self> {
        let runtime_protocol =
            parse_u32(json, "runtime_protocol").context("metadata.json 缺少 runtime_protocol")?;
        let cache_schema =
            parse_u32(json, "cache_schema").context("metadata.json 缺少 cache_schema")?;
        let environment_policy = parse_bool(json, "environment_policy")
            .context("metadata.json 缺少 environment_policy")?;
        let memory_dex = parse_bool(json, "memory_dex").context("metadata.json 缺少 memory_dex")?;
        // 旧资源包不具备已静态链入的 Xop 解释器，缺失时必须失败关闭。
        let xop_pvm2 = parse_bool(json, "xop_pvm2").unwrap_or(false);
        let (xop_vm_bridge, xop_vm_bridge_method) = if xop_pvm2 {
            let bridge =
                parse_string(json, "xop_vm_bridge").context("metadata.json 缺少 xop_vm_bridge")?;
            let method = parse_string(json, "xop_vm_bridge_method")
                .context("metadata.json 缺少 xop_vm_bridge_method")?;
            if !is_java_class_name(&bridge) {
                anyhow::bail!("metadata.json 的 xop_vm_bridge 不是有效类名");
            }
            if !is_java_identifier(&method) {
                anyhow::bail!("metadata.json 的 xop_vm_bridge_method 不是有效方法名");
            }
            (Some(bridge), Some(method))
        } else {
            (None, None)
        };
        let assets_pas2 = parse_bool(json, "assets_pas2").unwrap_or(false);
        let (assets_bridge, assets_bridge_method) = if assets_pas2 {
            let bridge =
                parse_string(json, "assets_bridge").context("metadata.json 缺少 assets_bridge")?;
            let method = parse_string(json, "assets_bridge_method")
                .context("metadata.json 缺少 assets_bridge_method")?;
            if !is_java_class_name(&bridge) || !is_java_identifier(&method) {
                anyhow::bail!("metadata.json 的 PAS2 bridge 契约无效");
            }
            (Some(bridge), Some(method))
        } else {
            (None, None)
        };
        let native_so_text = parse_bool(json, "native_so_text").unwrap_or(false);
        let native_so_functions = parse_bool(json, "native_so_functions").unwrap_or(false);
        if cache_schema != CACHE_SCHEMA {
            anyhow::bail!("不支持的 DEX 缓存协议: {cache_schema}");
        }
        let stub_component_factory = match (runtime_protocol, memory_dex) {
            (STANDARD_RUNTIME_PROTOCOL, false) => None,
            (MEMORY_RUNTIME_PROTOCOL, true) => {
                let min_api = parse_u32(json, "memory_dex_min_api")
                    .context("metadata.json 缺少 memory_dex_min_api")?;
                if min_api != MEMORY_DEX_MIN_API {
                    anyhow::bail!("不支持的内存 DEX 最低 API: {min_api}");
                }
                Some(
                    parse_string(json, "stub_component_factory")
                        .context("metadata.json 缺少 stub_component_factory")?,
                )
            }
            (STANDARD_RUNTIME_PROTOCOL, true) | (MEMORY_RUNTIME_PROTOCOL, false) => {
                anyhow::bail!("Runtime 协议与内存 DEX 能力声明不一致");
            }
            _ => anyhow::bail!("不支持的 Runtime 资源协议: {runtime_protocol}"),
        };
        let stub_application = parse_string(json, "stub_application")
            .context("metadata.json 缺少 stub_application")?;
        if !is_java_class_name(&stub_application) {
            anyhow::bail!("metadata.json 的 stub_application 不是有效类名");
        }
        if let Some(factory) = stub_component_factory.as_deref() {
            if !is_java_class_name(factory) {
                anyhow::bail!("metadata.json 的 stub_component_factory 不是有效类名");
            }
        }
        Ok(Self {
            stub_application,
            stub_component_factory,
            native_alias: NativeAliasProtocol::parse(json)?,
            environment_policy,
            memory_dex,
            xop_pvm2,
            xop_vm_bridge,
            xop_vm_bridge_method,
            assets_pas2,
            assets_bridge,
            assets_bridge_method,
            native_so_text,
            native_so_functions,
        })
    }
}

fn is_java_class_name(value: &str) -> bool {
    !value.is_empty() && value.split('.').all(is_java_identifier)
}

fn is_java_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    matches!(characters.next(), Some(first) if first.is_ascii_alphabetic() || first == '_' || first == '$')
        && characters.all(|character| {
            character.is_ascii_alphanumeric() || character == '_' || character == '$'
        })
}

fn value_after_key<'a>(json: &'a str, field: &str) -> Option<&'a str> {
    let needle = format!("\"{field}\"");
    let after_key = &json[json.find(&needle)? + needle.len()..];
    after_key
        .trim_start()
        .strip_prefix(':')
        .map(str::trim_start)
}

fn parse_string(json: &str, field: &str) -> Option<String> {
    let value = value_after_key(json, field)?.strip_prefix('"')?;
    Some(value[..value.find('"')?].to_string())
}

fn parse_u32(json: &str, field: &str) -> Option<u32> {
    let value = value_after_key(json, field)?;
    let end = value
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(value.len());
    value[..end].parse().ok()
}

fn parse_bool(json: &str, field: &str) -> Option<bool> {
    let value = value_after_key(json, field)?;
    if value.starts_with("true") {
        Some(true)
    } else if value.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const METADATA: &str = r#"{
        "stub_application":"msk.d",
        "native_library":"libmocikashield.so",
        "native_name_placeholder":"mocikanativeslot",
        "native_name_length":16,
        "native_name_scheme":1,
        "runtime_protocol":2,
        "cache_schema":1,
        "environment_policy":false,
        "memory_dex":false
    }"#;

    #[test]
    fn parses_supported_capabilities() {
        let metadata = RuntimeMetadata::parse(METADATA).unwrap();
        assert_eq!(metadata.stub_application, "msk.d");
        assert_eq!(metadata.native_alias.name_length, 16);
        assert!(!metadata.environment_policy);
        assert!(!metadata.memory_dex);
        assert!(!metadata.xop_pvm2);
        assert!(!metadata.assets_pas2);
        assert!(!metadata.native_so_text);
        assert!(!metadata.native_so_functions);
        assert!(metadata.stub_component_factory.is_none());
    }

    #[test]
    fn parses_native_so_text_capability() {
        let metadata = RuntimeMetadata::parse(&METADATA.replace(
            "\"memory_dex\":false",
            "\"memory_dex\":false,\n        \"native_so_text\":true",
        ))
        .unwrap();
        assert!(metadata.native_so_text);
    }

    #[test]
    fn parses_native_so_function_capability() {
        let metadata = RuntimeMetadata::parse(&METADATA.replace(
            "\"memory_dex\":false",
            "\"memory_dex\":false,\n        \"native_so_functions\":true",
        ))
        .unwrap();
        assert!(metadata.native_so_functions);
    }

    #[test]
    fn parses_embedded_xop_pvm2_capability() {
        let metadata = RuntimeMetadata::parse(&METADATA.replace(
            "\"memory_dex\":false",
            "\"memory_dex\":false,\n        \"xop_pvm2\":true,\n        \"xop_vm_bridge\":\"msk.v\",\n        \"xop_vm_bridge_method\":\"a\"",
        ))
        .unwrap();
        assert!(metadata.xop_pvm2);
        assert_eq!(metadata.xop_vm_bridge.as_deref(), Some("msk.v"));
        assert_eq!(metadata.xop_vm_bridge_method.as_deref(), Some("a"));
    }

    #[test]
    fn parses_pas2_asset_bridge() {
        let metadata = RuntimeMetadata::parse(&METADATA.replace(
            "\"memory_dex\":false",
            "\"memory_dex\":false,\n        \"assets_pas2\":true,\n        \"assets_bridge\":\"msk.a\",\n        \"assets_bridge_method\":\"open\"",
        ))
        .unwrap();
        assert!(metadata.assets_pas2);
        assert_eq!(metadata.assets_bridge.as_deref(), Some("msk.a"));
        assert_eq!(metadata.assets_bridge_method.as_deref(), Some("open"));
    }

    #[test]
    fn rejects_unsupported_or_inconsistent_protocol() {
        assert!(RuntimeMetadata::parse(
            &METADATA.replace("\"runtime_protocol\":2", "\"runtime_protocol\":3")
        )
        .is_err());
        assert!(RuntimeMetadata::parse(
            &METADATA.replace("\"memory_dex\":false", "\"memory_dex\":true")
        )
        .is_err());
    }

    #[test]
    fn parses_memory_candidate_protocol() {
        let candidate = METADATA
            .replace("\"runtime_protocol\":2", "\"runtime_protocol\":3")
            .replace(
                "\"memory_dex\":false",
                "\"memory_dex\":true,\n        \"memory_dex_min_api\":31,\n        \"stub_component_factory\":\"msk.f\"",
            );
        let metadata = RuntimeMetadata::parse(&candidate).unwrap();
        assert!(metadata.memory_dex);
        assert_eq!(metadata.stub_component_factory.as_deref(), Some("msk.f"));
    }

    #[test]
    fn rejects_invalid_candidate_factory_name() {
        let candidate = METADATA
            .replace("\"runtime_protocol\":2", "\"runtime_protocol\":3")
            .replace(
                "\"memory_dex\":false",
                "\"memory_dex\":true,\n        \"memory_dex_min_api\":31,\n        \"stub_component_factory\":\"invalid factory\"",
            );
        assert!(RuntimeMetadata::parse(&candidate).is_err());
    }
}
