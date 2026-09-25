use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const AROUTER_ROUTES_PREFIX: &str = "com/alibaba/android/arouter/routes/";
const AROUTER_REGISTRY_PREFIXES: [&str; 3] = [
    "ARouter$$Root$$",
    "ARouter$$Providers$$",
    "ARouter$$Interceptors$$",
];

const THEROUTER_SERVICE_PREFIX: &str = "a/ServiceProvider__TheRouter__";
const THEROUTER_ROUTE_PREFIX: &str = "a/RouterMap__TheRouter__";
const THEROUTER_AUTOWIRED_SUFFIX: &str = "__TheRouter__Autowired";
const THEROUTER_INDEX_METHODS: [&str; 3] = [
    "getServiceProviderIndex",
    "getRouterMapIndex",
    "getAutowiredIndex",
];

#[derive(Debug, Default, PartialEq, Eq)]
pub struct TheRouterRegistry {
    pub holder: Option<String>,
    pub services: Vec<String>,
    pub routes: Vec<String>,
    pub autowired: Vec<String>,
}

impl TheRouterRegistry {
    pub fn is_empty(&self) -> bool {
        self.services.is_empty() && self.routes.is_empty() && self.autowired.is_empty()
    }

    pub fn to_index_text(&self) -> String {
        let mut lines = Vec::new();
        if let Some(holder) = &self.holder {
            lines.push(format!("HOLDER\t{holder}"));
        }
        lines.extend(self.services.iter().map(|name| format!("SERVICE\t{name}")));
        lines.extend(self.routes.iter().map(|name| format!("ROUTE\t{name}")));
        lines.extend(
            self.autowired
                .iter()
                .map(|name| format!("AUTOWIRED\t{name}")),
        );
        lines.join("\n")
    }
}

/// 扫描 DEX 目录，提取所有 ARouter 路由表类的全限定名。
/// 解析 DEX header 的 class_defs 段，不依赖任何运行时 API。
pub fn scan_arouter_routes(dex_dir: &Path) -> Result<Vec<String>> {
    let mut routes = Vec::new();

    let mut dex_paths: Vec<_> = fs::read_dir(dex_dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("dex"))
        .collect();
    dex_paths.sort();

    for path in &dex_paths {
        let data = fs::read(path)?;
        for name in parse_dex_class_names(&data)? {
            if is_arouter_registry_class(&name) {
                let java_name = name.replace('/', ".");
                routes.push(java_name);
            }
        }
    }

    routes.sort();
    routes.dedup();
    Ok(routes)
}

/// Build the class index used by TheRouter's non-ASM fallback. TheRouter normally
/// scans `ApplicationInfo.sourceDir`; after DEXB packing that APK contains only the
/// Stub DEX, so the generated provider classes must be indexed before encryption.
pub fn scan_therouter_registry(dex_dir: &Path) -> Result<TheRouterRegistry> {
    let mut result = TheRouterRegistry::default();
    let mut holder_methods: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut defined_classes = BTreeSet::new();
    let mut dex_paths: Vec<_> = fs::read_dir(dex_dir)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("dex"))
        .collect();
    dex_paths.sort();

    for path in dex_paths {
        let data = fs::read(path)?;
        for name in parse_dex_class_names(&data)? {
            defined_classes.insert(name.clone());
            let java_name = name.replace('/', ".");
            if is_therouter_generated_class(&name, THEROUTER_SERVICE_PREFIX, None) {
                result.services.push(java_name);
            } else if is_therouter_generated_class(&name, THEROUTER_ROUTE_PREFIX, None) {
                result.routes.push(java_name);
            } else if is_therouter_generated_class(&name, "", Some(THEROUTER_AUTOWIRED_SUFFIX)) {
                result.autowired.push(java_name);
            }
        }
        collect_method_holders(&data, &mut holder_methods)?;
    }

    result.services.sort();
    result.services.dedup();
    result.routes.sort();
    result.routes.dedup();
    result.autowired.sort();
    result.autowired.dedup();
    result.holder = holder_methods
        .into_iter()
        .find(|(class_name, methods)| {
            defined_classes.contains(class_name)
                && THEROUTER_INDEX_METHODS
                    .iter()
                    .all(|method| methods.contains(*method))
        })
        .map(|(class_name, _)| class_name.replace('/', "."));
    Ok(result)
}

fn is_therouter_generated_class(name: &str, prefix: &str, suffix: Option<&str>) -> bool {
    if name.contains('$') {
        return false;
    }
    if !prefix.is_empty() {
        return name
            .strip_prefix(prefix)
            .is_some_and(|tail| !tail.is_empty());
    }
    suffix.is_some_and(|value| {
        name.strip_suffix(value)
            .is_some_and(|target| !target.is_empty())
    })
}

fn collect_method_holders(
    data: &[u8],
    holders: &mut BTreeMap<String, BTreeSet<String>>,
) -> Result<()> {
    validate_dex(data)?;
    let method_ids_size = u32_le(data, 88) as usize;
    let method_ids_off = u32_le(data, 92) as usize;
    let type_ids_size = u32_le(data, 64) as usize;
    let type_ids_off = u32_le(data, 68) as usize;
    let string_ids_size = u32_le(data, 56) as usize;
    let string_ids_off = u32_le(data, 60) as usize;

    for index in 0..method_ids_size {
        let offset = method_ids_off + index * 8;
        if offset + 8 > data.len() {
            break;
        }
        let class_idx = u16_le(data, offset) as usize;
        let name_idx = u32_le(data, offset + 4) as usize;
        let Some(method_name) = resolve_string(data, name_idx, string_ids_size, string_ids_off)
        else {
            continue;
        };
        if !THEROUTER_INDEX_METHODS.contains(&method_name) || class_idx >= type_ids_size {
            continue;
        }
        let type_offset = type_ids_off + class_idx * 4;
        if type_offset + 4 > data.len() {
            continue;
        }
        let descriptor_idx = u32_le(data, type_offset) as usize;
        let Some(descriptor) =
            resolve_string(data, descriptor_idx, string_ids_size, string_ids_off)
        else {
            continue;
        };
        if let Some(class_name) = descriptor
            .strip_prefix('L')
            .and_then(|value| value.strip_suffix(';'))
        {
            holders
                .entry(class_name.to_string())
                .or_default()
                .insert(method_name.to_string());
        }
    }
    Ok(())
}

/// 检查至少一个 DEX 类是否命中用户显式配置的描述符前缀。
/// 前缀格式与 Xop 一致：包前缀以 `/` 结尾，单类描述符以 `;` 结尾。
pub(crate) fn any_class_matches_prefixes(dex_dir: &Path, prefixes: &[String]) -> Result<bool> {
    let mut dex_paths: Vec<_> = fs::read_dir(dex_dir)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name == "classes.dex" || (name.starts_with("classes") && name.ends_with(".dex"))
                })
        })
        .collect();
    dex_paths.sort();

    for path in dex_paths {
        let data = fs::read(path)?;
        for class_name in parse_dex_class_names(&data)? {
            if prefixes
                .iter()
                .any(|prefix| descriptor_prefix_matches_name(prefix, &class_name))
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn descriptor_prefix_matches_name(prefix: &str, class_name: &str) -> bool {
    if let Some(package_prefix) = prefix.strip_prefix('L').and_then(|p| p.strip_suffix('/')) {
        class_name
            .strip_prefix(package_prefix)
            .is_some_and(|suffix| suffix.starts_with('/'))
    } else if let Some(class_descriptor) =
        prefix.strip_prefix('L').and_then(|p| p.strip_suffix(';'))
    {
        class_name == class_descriptor
    } else {
        false
    }
}

fn is_arouter_registry_class(name: &str) -> bool {
    let Some(simple_name) = name.strip_prefix(AROUTER_ROUTES_PREFIX) else {
        return false;
    };
    AROUTER_REGISTRY_PREFIXES.iter().any(|prefix| {
        simple_name
            .strip_prefix(prefix)
            .is_some_and(|module_name| !module_name.is_empty() && !module_name.contains('$'))
    })
}

/// 解析 DEX 文件，提取所有类的描述符（内部格式，如 "Lcom/foo/Bar;"）
/// 转换为斜线分隔路径（如 "com/foo/Bar"）。
///
/// DEX 格式参考：https://source.android.com/docs/core/runtime/dex-format
/// 仅解析 header、string_ids、type_ids、class_defs 四个区段，满足类名提取需求。
fn parse_dex_class_names(data: &[u8]) -> Result<Vec<String>> {
    validate_dex(data)?;

    let string_ids_size = u32_le(data, 56) as usize;
    let string_ids_off = u32_le(data, 60) as usize;
    let type_ids_size = u32_le(data, 64) as usize;
    let type_ids_off = u32_le(data, 68) as usize;
    let class_defs_size = u32_le(data, 96) as usize;
    let class_defs_off = u32_le(data, 100) as usize;

    let mut names = Vec::with_capacity(class_defs_size);

    for i in 0..class_defs_size {
        let def_off = class_defs_off + i * 32;
        if def_off + 4 > data.len() {
            break;
        }
        let class_idx = u32_le(data, def_off) as usize;
        if class_idx >= type_ids_size {
            continue;
        }

        let type_off = type_ids_off + class_idx * 4;
        if type_off + 4 > data.len() {
            continue;
        }
        let string_idx = u32_le(data, type_off) as usize;
        if string_idx >= string_ids_size {
            continue;
        }

        let sid_off = string_ids_off + string_idx * 4;
        if sid_off + 4 > data.len() {
            continue;
        }
        let string_data_off = u32_le(data, sid_off) as usize;

        if let Some(descriptor) = read_mutf8_string(data, string_data_off) {
            // 描述符格式: "Lcom/foo/Bar;" → 取中间部分 "com/foo/Bar"
            if descriptor.starts_with('L') && descriptor.ends_with(';') {
                names.push(descriptor[1..descriptor.len() - 1].to_string());
            }
        }
    }

    Ok(names)
}

fn validate_dex(data: &[u8]) -> Result<()> {
    if data.len() < 112 {
        anyhow::bail!("DEX 文件过小，不是有效的 DEX");
    }
    if &data[0..4] != b"dex\n" {
        anyhow::bail!("Magic 不匹配，不是有效的 DEX 文件");
    }
    Ok(())
}

fn resolve_string(
    data: &[u8],
    string_idx: usize,
    string_ids_size: usize,
    string_ids_off: usize,
) -> Option<&str> {
    if string_idx >= string_ids_size {
        return None;
    }
    let id_offset = string_ids_off.checked_add(string_idx.checked_mul(4)?)?;
    if id_offset + 4 > data.len() {
        return None;
    }
    read_mutf8_string(data, u32_le(data, id_offset) as usize)
}

/// 读取 DEX MUTF-8 编码字符串（string_data_item）。
/// 格式：ULEB128 长度前缀 + MUTF-8 字节 + NUL 终止符。
/// ARouter 路由表类名全为 ASCII，简化实现足够。
fn read_mutf8_string(data: &[u8], offset: usize) -> Option<&str> {
    if offset >= data.len() {
        return None;
    }
    // 跳过 ULEB128 长度前缀（每字节高位为 1 则继续，最后一字节高位为 0）
    let mut pos = offset;
    while pos < data.len() && data[pos] & 0x80 != 0 {
        pos += 1;
    }
    if pos >= data.len() {
        return None;
    }
    pos += 1; // 跳过最后一个 ULEB128 字节

    let start = pos;
    while pos < data.len() && data[pos] != 0 {
        pos += 1;
    }
    std::str::from_utf8(&data[start..pos]).ok()
}

#[inline]
fn u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

#[inline]
fn u16_le(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

#[cfg(test)]
mod tests {
    use super::{
        descriptor_prefix_matches_name, is_arouter_registry_class, is_therouter_generated_class,
        TheRouterRegistry, THEROUTER_AUTOWIRED_SUFFIX, THEROUTER_ROUTE_PREFIX,
        THEROUTER_SERVICE_PREFIX,
    };

    #[test]
    fn 只接受_arouter_可注册入口类() {
        assert!(is_arouter_registry_class(
            "com/alibaba/android/arouter/routes/ARouter$$Root$$featurehome"
        ));
        assert!(is_arouter_registry_class(
            "com/alibaba/android/arouter/routes/ARouter$$Providers$$arouterapi"
        ));
        assert!(is_arouter_registry_class(
            "com/alibaba/android/arouter/routes/ARouter$$Interceptors$$app"
        ));
        assert!(!is_arouter_registry_class(
            "com/alibaba/android/arouter/routes/ARouter$$Group$$home"
        ));
        assert!(!is_arouter_registry_class(
            "com/alibaba/android/arouter/routes/ARouter$$Root$$featurehome$1"
        ));
    }

    #[test]
    fn xop_前缀只命中真实包边界或完整类名() {
        assert!(descriptor_prefix_matches_name(
            "Lcom/acme/payment/",
            "com/acme/payment/Checkout"
        ));
        assert!(!descriptor_prefix_matches_name(
            "Lcom/acme/pay/",
            "com/acme/payment/Checkout"
        ));
        assert!(descriptor_prefix_matches_name(
            "Lcom/acme/payment/Checkout;",
            "com/acme/payment/Checkout"
        ));
        assert!(!descriptor_prefix_matches_name(
            "Lcom/acme/payment/Checkout;",
            "com/acme/payment/Checkout$Companion"
        ));
    }

    #[test]
    fn therouter_索引只收集可实例化生成类() {
        assert!(is_therouter_generated_class(
            "a/ServiceProvider__TheRouter__123",
            THEROUTER_SERVICE_PREFIX,
            None,
        ));
        assert!(is_therouter_generated_class(
            "a/RouterMap__TheRouter__app",
            THEROUTER_ROUTE_PREFIX,
            None,
        ));
        assert!(is_therouter_generated_class(
            "com/acme/Home__TheRouter__Autowired",
            "",
            Some(THEROUTER_AUTOWIRED_SUFFIX),
        ));
        assert!(!is_therouter_generated_class(
            "a/ServiceProvider__TheRouter__123$Factory",
            THEROUTER_SERVICE_PREFIX,
            None,
        ));

        let registry = TheRouterRegistry {
            holder: Some("f8.b".to_string()),
            services: vec!["a.ServiceProvider__TheRouter__123".to_string()],
            routes: vec![],
            autowired: vec![],
        };
        assert_eq!(
            "HOLDER\tf8.b\nSERVICE\ta.ServiceProvider__TheRouter__123",
            registry.to_index_text(),
        );
    }
}
