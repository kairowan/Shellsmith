use super::resource_format::{normalize_mislabeled_jpeg_resources, restore_original_resources};
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

const JPEG_PREFIX: &[u8] = &[0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];

#[test]
fn jpeg_伪装_png_会无损改名为_jpg() {
    let dir = tempfile::tempdir().unwrap();
    let resource = dir.path().join("res/mipmap-xhdpi/ic_bottom_sucai.png");
    fs::create_dir_all(resource.parent().unwrap()).unwrap();
    fs::write(&resource, JPEG_PREFIX).unwrap();

    let renamed = normalize_mislabeled_jpeg_resources(dir.path()).unwrap();

    let target = resource.with_extension("jpg");
    assert_eq!(renamed, 1);
    assert!(!resource.exists());
    assert_eq!(fs::read(target).unwrap(), JPEG_PREFIX);
}

#[test]
fn 九宫格_png_伪装_jpeg_会被拒绝而不改名() {
    let dir = tempfile::tempdir().unwrap();
    let resource = dir.path().join("res/drawable/button.9.png");
    fs::create_dir_all(resource.parent().unwrap()).unwrap();
    fs::write(&resource, JPEG_PREFIX).unwrap();

    let error = normalize_mislabeled_jpeg_resources(dir.path()).unwrap_err();

    assert!(error.to_string().contains("九宫格"));
    assert!(resource.exists());
}

#[test]
fn 已存在同名_jpg_时拒绝覆盖() {
    let dir = tempfile::tempdir().unwrap();
    let resource = dir.path().join("res/mipmap-hdpi/icon.png");
    let target = resource.with_extension("jpg");
    fs::create_dir_all(resource.parent().unwrap()).unwrap();
    fs::write(&resource, JPEG_PREFIX).unwrap();
    fs::write(&target, b"existing").unwrap();

    let error = normalize_mislabeled_jpeg_resources(dir.path()).unwrap_err();

    assert!(error.to_string().contains("同名 .jpg"));
    assert!(resource.exists());
    assert_eq!(fs::read(target).unwrap(), b"existing");
}

fn make_apk(path: &Path, entries: &[(&str, &[u8])]) {
    let file = fs::File::create(path).unwrap();
    let mut writer = ZipWriter::new(file);
    for (name, content) in entries {
        writer
            .start_file(
                *name,
                SimpleFileOptions::default().compression_method(CompressionMethod::Deflated),
            )
            .unwrap();
        writer.write_all(content).unwrap();
    }
    writer.finish().unwrap();
}

fn read_entry(path: &Path, name: &str) -> Option<Vec<u8>> {
    let file = fs::File::open(path).unwrap();
    let mut archive = ZipArchive::new(file).unwrap();
    let mut entry = archive.by_name(name).ok()?;
    let mut content = Vec::new();
    entry.read_to_end(&mut content).unwrap();
    Some(content)
}

#[test]
fn 重编后恢复原资源名称和内容但保留新的壳条目() {
    let dir = tempfile::tempdir().unwrap();
    let original = dir.path().join("original.apk");
    let rebuilt = dir.path().join("rebuilt.apk");
    make_apk(
        &original,
        &[
            ("AndroidManifest.xml", b"original manifest"),
            ("classes.dex", b"business dex"),
            ("resources.arsc", b"obfuscated table"),
            ("res/-3.png", b"obfuscated resource"),
        ],
    );
    make_apk(
        &rebuilt,
        &[
            ("AndroidManifest.xml", b"protected manifest"),
            ("classes.dex", b"stub dex"),
            ("resources.arsc", b"readable table"),
            ("res/drawable/readable_name.png", b"rebuilt resource"),
            ("lib/arm64-v8a/libshield.so", b"runtime"),
        ],
    );
    let original_bytes = fs::read(&original).unwrap();

    assert_eq!(restore_original_resources(&original, &rebuilt).unwrap(), 2);

    assert_eq!(fs::read(&original).unwrap(), original_bytes);
    assert_eq!(
        read_entry(&rebuilt, "resources.arsc").unwrap(),
        b"obfuscated table"
    );
    assert_eq!(
        read_entry(&rebuilt, "res/-3.png").unwrap(),
        b"obfuscated resource"
    );
    assert!(read_entry(&rebuilt, "res/drawable/readable_name.png").is_none());
    assert_eq!(
        read_entry(&rebuilt, "AndroidManifest.xml").unwrap(),
        b"protected manifest"
    );
    assert_eq!(read_entry(&rebuilt, "classes.dex").unwrap(), b"stub dex");
    assert_eq!(
        read_entry(&rebuilt, "lib/arm64-v8a/libshield.so").unwrap(),
        b"runtime"
    );
}
