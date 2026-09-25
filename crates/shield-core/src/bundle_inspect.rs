use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use zip::ZipArchive;

/// AAB 的模块级结构快照。这里不直接改写 AAB，避免把 APK 解包器误用到
/// bundle 容器；后续保护应在 AGP 产物阶段或由 bundletool 生成的 split APK 上完成。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AabModuleInspection {
    pub name: String,
    pub has_manifest: bool,
    pub dex_entries: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AabInspection {
    pub path: PathBuf,
    pub modules: Vec<String>,
    pub has_base: bool,
    pub has_bundle_config: bool,
    pub dex_entries: usize,
    pub manifest_entries: usize,
    pub dynamic_feature_modules: Vec<String>,
    pub module_details: Vec<AabModuleInspection>,
}

pub fn inspect_aab(path: &Path) -> Result<AabInspection> {
    if !path.is_file() {
        anyhow::bail!("AAB 文件不存在：{}", path.display());
    }
    let file = File::open(path).with_context(|| format!("打开 AAB 失败：{}", path.display()))?;
    let mut archive = ZipArchive::new(file).context("解析 AAB ZIP 失败")?;
    let mut dynamic_feature_modules = Vec::new();
    let mut has_bundle_config = false;
    let mut dex_entries = 0;
    let mut manifest_entries = 0;
    let mut module_details: BTreeMap<String, AabModuleInspection> = BTreeMap::new();

    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .with_context(|| format!("读取 AAB 条目 {index} 失败"))?;
        let name = entry.name();
        if name == "BundleConfig.pb" {
            has_bundle_config = true;
        }
        if let Some((module, rest)) = name.split_once("/") {
            let detail =
                module_details
                    .entry(module.to_string())
                    .or_insert_with(|| AabModuleInspection {
                        name: module.to_string(),
                        has_manifest: false,
                        dex_entries: Vec::new(),
                    });
            if rest == "manifest/AndroidManifest.xml" {
                manifest_entries += 1;
                detail.has_manifest = true;
            }
            if rest.ends_with(".dex") {
                dex_entries += 1;
                detail.dex_entries.push(rest.to_string());
            }
            if module != "base"
                && (rest == "manifest/AndroidManifest.xml" || rest.starts_with("dex/"))
                && !dynamic_feature_modules.iter().any(|value| value == module)
            {
                dynamic_feature_modules.push(module.to_string());
            }
        }
    }

    let mut module_details: Vec<_> = module_details
        .into_values()
        .filter(|detail| detail.has_manifest || !detail.dex_entries.is_empty())
        .collect();
    module_details.sort_by(|left, right| left.name.cmp(&right.name));
    let modules: Vec<String> = module_details
        .iter()
        .map(|detail| detail.name.clone())
        .collect();
    dynamic_feature_modules.sort();
    Ok(AabInspection {
        path: path.to_path_buf(),
        has_base: modules.iter().any(|module| module == "base"),
        has_bundle_config,
        modules,
        dex_entries,
        manifest_entries,
        dynamic_feature_modules,
        module_details,
    })
}

pub fn validate_aab_for_module_processing(inspection: &AabInspection) -> Result<()> {
    if !inspection.has_base {
        anyhow::bail!("AAB 缺少 base 模块，无法继续模块化处理");
    }
    if !inspection.has_bundle_config {
        anyhow::bail!("AAB 缺少 BundleConfig.pb，文件可能不是完整的 bundle 产物");
    }
    if inspection.dex_entries == 0 {
        anyhow::bail!("AAB 未找到任何 DEX 条目");
    }
    if inspection.manifest_entries == 0 {
        anyhow::bail!("AAB 未找到模块 Manifest");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn 能识别_base和动态模块() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sample.aab");
        let file = File::create(&path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        for name in [
            "BundleConfig.pb",
            "BUNDLE-METADATA/com.android.tools.build.libraries/dependencies",
            "META-INF/MANIFEST.MF",
            "base/manifest/AndroidManifest.xml",
            "base/dex/classes.dex",
            "feature/manifest/AndroidManifest.xml",
            "feature/dex/classes2.dex",
        ] {
            zip.start_file(name, options).unwrap();
            zip.write_all(b"x").unwrap();
        }
        zip.finish().unwrap();

        let result = inspect_aab(&path).unwrap();
        assert!(result.has_base);
        assert!(result.has_bundle_config);
        assert_eq!(result.dex_entries, 2);
        assert_eq!(result.dynamic_feature_modules, vec!["feature"]);
        assert_eq!(result.module_details[0].name, "base");
        assert_eq!(
            result.module_details[0].dex_entries,
            vec!["dex/classes.dex"]
        );
        assert!(result.module_details[1].has_manifest);
        validate_aab_for_module_processing(&result).unwrap();
    }

    #[test]
    fn ignores_bundle_metadata_and_signature_directories_as_modules() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("single-base.aab");
        let file = File::create(&path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        for name in [
            "BundleConfig.pb",
            "BUNDLE-METADATA/com.android.tools.build.libraries/dependencies",
            "META-INF/MANIFEST.MF",
            "base/manifest/AndroidManifest.xml",
            "base/dex/classes.dex",
        ] {
            zip.start_file(name, options).unwrap();
            zip.write_all(b"x").unwrap();
        }
        zip.finish().unwrap();

        let result = inspect_aab(&path).unwrap();
        assert_eq!(result.modules, vec!["base"]);
        assert!(result.dynamic_feature_modules.is_empty());
    }
}
