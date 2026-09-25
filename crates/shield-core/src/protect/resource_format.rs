use anyhow::{Context, Result};
use std::fs;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;
use walkdir::WalkDir;
use zip::{ZipArchive, ZipWriter};

const JPEG_SIGNATURE: [u8; 3] = [0xFF, 0xD8, 0xFF];

/// Apktool 必须重编 Manifest，但不能因此丢掉输入 APK 已有的资源名混淆。
/// 用输入 APK 的原始 `resources.arsc` 和 `res/` 条目覆盖重编结果，其他受保护
/// 条目（Manifest、Stub DEX、Native Runtime）保持不变。
pub(crate) fn restore_original_resources(original_apk: &Path, rebuilt_apk: &Path) -> Result<usize> {
    let original_file = fs::File::open(original_apk)
        .with_context(|| format!("打开原 APK 失败：{}", original_apk.display()))?;
    let rebuilt_file = fs::File::open(rebuilt_apk)
        .with_context(|| format!("打开重编 APK 失败：{}", rebuilt_apk.display()))?;
    let mut original = ZipArchive::new(original_file).context("解析原 APK ZIP 失败")?;
    let mut rebuilt = ZipArchive::new(rebuilt_file).context("解析重编 APK ZIP 失败")?;

    let original_resources = resource_index(&mut original)?;
    if original_resources.is_empty() {
        return Ok(0);
    }

    let parent = rebuilt_apk
        .parent()
        .with_context(|| format!("无法确定输出 APK 父目录：{}", rebuilt_apk.display()))?;
    let mut temp = NamedTempFile::new_in(parent).context("创建资源恢复临时 APK 失败")?;
    {
        let mut writer = ZipWriter::new(BufWriter::new(temp.as_file_mut()));
        writer.set_raw_comment(rebuilt.comment().to_vec().into_boxed_slice());
        if let Some(comment) = rebuilt.zip64_comment() {
            writer.set_raw_zip64_comment(Some(comment.to_vec().into_boxed_slice()));
        }

        for index in 0..rebuilt.len() {
            let entry = rebuilt
                .by_index(index)
                .with_context(|| format!("读取重编 APK 条目失败：index={index}"))?;
            if !is_resource_entry(entry.name()) {
                writer
                    .raw_copy_file(entry)
                    .context("复制受保护 APK 条目失败")?;
            }
        }
        for index in 0..original.len() {
            let entry = original
                .by_index(index)
                .with_context(|| format!("读取原 APK 资源条目失败：index={index}"))?;
            if is_resource_entry(entry.name()) {
                writer
                    .raw_copy_file(entry)
                    .context("恢复原 APK 混淆资源条目失败")?;
            }
        }

        let mut output = writer.finish().context("完成资源恢复 APK 写入失败")?;
        output.flush().context("刷新资源恢复 APK 失败")?;
    }
    drop(original);
    drop(rebuilt);

    temp.persist(rebuilt_apk).map_err(|error| {
        anyhow::anyhow!(
            "替换资源恢复后的 APK 失败：{} -> {}：{}",
            error.file.path().display(),
            rebuilt_apk.display(),
            error.error
        )
    })?;

    verify_original_resources(original_apk, rebuilt_apk)?;
    Ok(original_resources.len())
}

pub(crate) fn verify_original_resources(
    original_apk: &Path,
    protected_apk: &Path,
) -> Result<usize> {
    let original_file = fs::File::open(original_apk).context("打开原 APK 资源索引失败")?;
    let protected_file = fs::File::open(protected_apk).context("打开加固 APK 资源索引失败")?;
    let mut original = ZipArchive::new(original_file).context("解析原 APK 资源索引失败")?;
    let mut protected = ZipArchive::new(protected_file).context("解析加固 APK 资源索引失败")?;
    let expected = resource_index(&mut original)?;
    if resource_index(&mut protected)? != expected {
        anyhow::bail!("原 APK 资源名称或内容未被完整保留，拒绝继续签名");
    }
    Ok(expected.len())
}

fn is_resource_entry(name: &str) -> bool {
    name == "resources.arsc" || name.starts_with("res/")
}

fn resource_index<R: std::io::Read + std::io::Seek>(
    archive: &mut ZipArchive<R>,
) -> Result<Vec<(String, u64, u32)>> {
    let mut index = Vec::new();
    for position in 0..archive.len() {
        let entry = archive
            .by_index(position)
            .with_context(|| format!("读取 APK 资源索引失败：index={position}"))?;
        if is_resource_entry(entry.name()) {
            index.push((entry.name().to_string(), entry.size(), entry.crc32()));
        }
    }
    index.sort();
    Ok(index)
}

/// 修正 aapt2 无法编译的“JPEG 内容伪装为 PNG”资源。
///
/// 仅处理解包目录的 `res`，并通过改名保留原始 JPEG 字节；九宫格资源和同名目标
/// 则拒绝处理，避免改变 Android 资源语义或覆盖用户文件。
pub(crate) fn normalize_mislabeled_jpeg_resources(apk_dir: &Path) -> Result<usize> {
    let resource_dir = apk_dir.join("res");
    if !resource_dir.is_dir() {
        return Ok(0);
    }

    let mut png_paths = Vec::<PathBuf>::new();
    for entry in WalkDir::new(&resource_dir).follow_links(false) {
        let entry =
            entry.with_context(|| format!("遍历资源目录失败：{}", resource_dir.display()))?;
        if entry.file_type().is_file() && is_png_extension(entry.path()) {
            png_paths.push(entry.into_path());
        }
    }

    let mut renamed = 0;
    for path in png_paths {
        if !has_jpeg_signature(&path)? {
            continue;
        }
        if is_nine_patch(&path) {
            anyhow::bail!(
                "检测到 JPEG 内容伪装为九宫格 PNG，无法安全自动修正：{}。请改为有效 .9.png 资源",
                path.display()
            );
        }
        let target = path.with_extension("jpg");
        if target.exists() {
            anyhow::bail!(
                "检测到 JPEG 内容伪装为 PNG，但同名 .jpg 已存在：{}。请手动处理资源冲突",
                target.display()
            );
        }
        fs::rename(&path, &target).with_context(|| {
            format!(
                "将 JPEG 伪装 PNG 资源改名失败：{} -> {}",
                path.display(),
                target.display()
            )
        })?;
        renamed += 1;
    }
    Ok(renamed)
}

fn is_png_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("png"))
}

fn is_nine_patch(path: &Path) -> bool {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .is_some_and(|stem| stem.ends_with(".9"))
}

fn has_jpeg_signature(path: &Path) -> Result<bool> {
    let bytes = fs::read(path).with_context(|| format!("读取资源文件失败：{}", path.display()))?;
    Ok(bytes.starts_with(&JPEG_SIGNATURE))
}
