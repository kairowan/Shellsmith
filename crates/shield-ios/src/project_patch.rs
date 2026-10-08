use crate::confidential;
use crate::freerasp;
use crate::project_inspect::IosTargetInspection;
use crate::ShellsmithIosConfig;
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const GENERATED_DIRECTORY: &str = ".shellsmith";

pub(crate) fn copy_project_tree(
    source: &Path,
    destination: &Path,
    cancel: &Arc<AtomicBool>,
) -> Result<PathBuf> {
    if destination.exists() && destination.read_dir()?.next().is_some() {
        anyhow::bail!("工作副本目录必须不存在或为空：{}", destination.display());
    }
    fs::create_dir_all(destination)?;
    copy_directory(source, destination, source, cancel)?;
    Ok(destination.to_path_buf())
}

pub(crate) fn integrate_runtime(
    working_root: &Path,
    working_project: &Path,
    target: &IosTargetInspection,
    config: &ShellsmithIosConfig,
    confidential_path: Option<&Path>,
) -> Result<()> {
    if source_contains(
        working_root,
        "extension SecurityThreatCenter: SecurityThreatHandler",
    )? {
        anyhow::bail!(
            "工程已自行接入 freeRASP SecurityThreatHandler；为避免重复全局协议实现，先移除旧接入或使用 compat"
        );
    }
    let runtime_root = working_root
        .join(GENERATED_DIRECTORY)
        .join("ShellsmithRuntime");
    let sources = runtime_root.join("Sources").join("ShellsmithRuntime");
    fs::create_dir_all(&sources)?;
    let uses_confidential = config.confidential_enabled();
    let uses_rasp = config.protection.profile.uses_rasp();
    fs::write(
        runtime_root.join("Package.swift"),
        freerasp::package_manifest(uses_confidential, uses_rasp),
    )?;
    fs::write(
        sources.join("ShellsmithRuntime.swift"),
        freerasp::runtime_source(uses_rasp),
    )?;
    fs::write(
        sources.join("ShellsmithProtection.swift"),
        freerasp::protection_source(config),
    )?;
    let attest = freerasp::app_attest_source(matches!(
        config.protection.profile,
        crate::IosProtectionProfile::Strict
    ));
    if !attest.is_empty() {
        fs::write(sources.join("ShellsmithAppAttest.swift"), attest)?;
    }
    if uses_confidential {
        confidential::copy_and_validate(
            confidential_path.context("缺少 Swift Confidential 配置")?,
            &sources,
        )?;
    }

    let entrypoint = resolve_entrypoint(working_root, config)?;
    match entrypoint.extension().and_then(|value| value.to_str()) {
        Some("swift") => patch_swift_entrypoint(&entrypoint)?,
        Some("m") => {
            if uses_confidential {
                anyhow::bail!("Objective-C 启动工程不能使用 Swift Confidential 保护 OC 字符串；请取消 confidential.yml 后重试");
            }
            patch_objc_entrypoint(&entrypoint)?;
        }
        _ => anyhow::bail!(
            "iOS 启动入口必须是 Swift @main 文件或包含 didFinishLaunchingWithOptions 的 Objective-C .m 文件"
        ),
    }
    let pbxproj = find_pbxproj_for_target(working_root, working_project, target)?;
    let project_directory = pbxproj
        .parent()
        .and_then(Path::parent)
        .context("无法确定 Xcode project 目录")?;
    let relative_package = relative_path(project_directory, &runtime_root)?;
    patch_pbxproj(&pbxproj, &target.name, &relative_package)?;
    Ok(())
}

fn copy_directory(
    source: &Path,
    destination: &Path,
    source_root: &Path,
    cancel: &Arc<AtomicBool>,
) -> Result<()> {
    if cancel.load(Ordering::SeqCst) {
        anyhow::bail!("iOS 保护任务已取消");
    }
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let name = entry.file_name();
        if should_skip(&name) {
            continue;
        }
        let source_path = entry.path();
        let destination_path = destination.join(&name);
        let metadata = fs::symlink_metadata(&source_path)?;
        if metadata.file_type().is_symlink() {
            copy_symlink(&source_path, &destination_path, source_root)?;
        } else if metadata.is_dir() {
            fs::create_dir_all(&destination_path)?;
            copy_directory(&source_path, &destination_path, source_root, cancel)?;
        } else if metadata.is_file() {
            fs::copy(&source_path, &destination_path).with_context(|| {
                format!(
                    "复制工程文件失败：{} -> {}",
                    source_path.display(),
                    destination_path.display()
                )
            })?;
            fs::set_permissions(&destination_path, metadata.permissions())?;
        }
    }
    Ok(())
}

fn should_skip(name: &OsStr) -> bool {
    matches!(
        name.to_str(),
        Some(".git" | ".build" | "DerivedData" | "build" | ".DS_Store" | GENERATED_DIRECTORY)
    )
}

fn copy_symlink(source: &Path, destination: &Path, source_root: &Path) -> Result<()> {
    let link = fs::read_link(source)?;
    let resolved = if link.is_absolute() {
        link.clone()
    } else {
        source.parent().unwrap_or(source_root).join(&link)
    };
    let canonical = resolved
        .canonicalize()
        .with_context(|| format!("解析工程符号链接失败：{}", source.display()))?;
    let root = source_root.canonicalize()?;
    if !canonical.starts_with(&root) {
        anyhow::bail!("工程包含指向源码目录外的符号链接：{}", source.display());
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(link, destination)?;
    #[cfg(not(unix))]
    anyhow::bail!("当前系统不能复制 iOS 工程符号链接");
    Ok(())
}

fn source_contains(root: &Path, needle: &str) -> Result<bool> {
    let mut files = Vec::new();
    collect_files(root, "swift", &mut files)?;
    for path in files {
        if fs::read_to_string(path).is_ok_and(|content| content.contains(needle)) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn resolve_entrypoint(working_root: &Path, config: &ShellsmithIosConfig) -> Result<PathBuf> {
    if let Some(configured) = &config.project.entrypoint {
        let original_root = config
            .project
            .path
            .parent()
            .context("原工程路径缺少父目录")?;
        let relative = if configured.is_absolute() {
            configured
                .strip_prefix(original_root)
                .context("entrypoint 必须位于工程源码根目录内")?
        } else {
            configured.as_path()
        };
        let candidate = working_root.join(relative);
        if !candidate.is_file() {
            anyhow::bail!("iOS 启动入口不存在：{}", candidate.display());
        }
        return Ok(candidate);
    }
    let mut files = Vec::new();
    collect_files(working_root, "swift", &mut files)?;
    let matches = files
        .into_iter()
        .filter(|path| {
            fs::read_to_string(path).is_ok_and(|content| find_swift_main(&content).is_some())
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [path] => return Ok(path.clone()),
        [] => {}
        _ => anyhow::bail!("发现多个 Swift @main 启动入口；请在配置中填写 project.entrypoint"),
    }
    let mut files = Vec::new();
    // ponytail: only auto-patch a single UIKit launch callback; custom launch flows need a dedicated adapter.
    collect_files(working_root, "m", &mut files)?;
    let matches = files
        .into_iter()
        .filter(|path| {
            fs::read_to_string(path).is_ok_and(|content| find_objc_launch_body(&content).is_some())
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [path] => Ok(path.clone()),
        [] => anyhow::bail!("没有找到 Swift @main 或 Objective-C didFinishLaunchingWithOptions 启动入口；请在配置中填写 project.entrypoint"),
        _ => anyhow::bail!("发现多个 Objective-C 启动回调；请在配置中填写 project.entrypoint"),
    }
}

fn patch_objc_entrypoint(path: &Path) -> Result<()> {
    let mut content = fs::read_to_string(path)
        .with_context(|| format!("读取 Objective-C 启动入口失败：{}", path.display()))?;
    let launch_open = find_objc_launch_body(&content)
        .context("Objective-C 启动入口缺少 didFinishLaunchingWithOptions 方法实现")?;
    let mask = swift_code_mask(&content);
    let call = "[ShellsmithProtectionBootstrap start]";
    if content
        .match_indices(call)
        .any(|(index, _)| mask[index..index + call.len()].iter().all(|value| *value))
    {
        return Ok(());
    }
    content.insert_str(
        launch_open + 1,
        "\n    [ShellsmithProtectionBootstrap start];",
    );
    content.insert_str(0, "@import ShellsmithRuntime;\n");
    fs::write(path, content)?;
    Ok(())
}

fn find_objc_launch_body(content: &str) -> Option<usize> {
    let mask = swift_code_mask(content);
    let mut cursor = 0;
    while let Some(callback) = find_code_word(
        content,
        &mask,
        "didFinishLaunchingWithOptions",
        cursor,
        content.len(),
    ) {
        cursor = callback + "didFinishLaunchingWithOptions".len();
        let before = (0..callback)
            .rev()
            .find(|index| mask[*index] && matches!(content.as_bytes()[*index], b';' | b'{' | b'}'))
            .map_or(0, |index| index + 1);
        let signature = content.as_bytes()[before..callback]
            .iter()
            .enumerate()
            .filter_map(|(offset, byte)| mask[before + offset].then_some(*byte))
            .collect::<Vec<_>>();
        if !signature
            .windows(b"application:".len())
            .any(|part| part == b"application:")
            || !signature.contains(&b'-')
            || !signature.windows(b"BOOL".len()).any(|part| part == b"BOOL")
        {
            continue;
        }
        let colon = content.as_bytes()[cursor..]
            .iter()
            .position(|byte| !byte.is_ascii_whitespace())?
            + cursor;
        if content.as_bytes().get(colon) != Some(&b':') {
            continue;
        }
        let open = find_code_char(content, colon + 1, content.len(), b'{')?;
        if content.as_bytes()[colon + 1..open]
            .iter()
            .enumerate()
            .any(|(offset, byte)| mask[colon + 1 + offset] && *byte == b';')
        {
            continue;
        }
        if matching_brace(content, open).is_some() {
            return Some(open);
        }
    }
    None
}

fn find_code_word(
    content: &str,
    mask: &[bool],
    word: &str,
    start: usize,
    end: usize,
) -> Option<usize> {
    let bytes = content.as_bytes();
    bytes[start..end]
        .windows(word.len())
        .enumerate()
        .find_map(|(offset, found)| {
            let index = start + offset;
            (found == word.as_bytes()
                && mask[index..index + word.len()].iter().all(|value| *value)
                && (index == 0 || !is_identifier(bytes[index - 1]))
                && bytes
                    .get(index + word.len())
                    .is_none_or(|byte| !is_identifier(*byte)))
            .then_some(index)
        })
}

fn collect_files(root: &Path, extension: &str, output: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if should_skip(&entry.file_name()) || entry.file_name() == "Pods" {
            continue;
        }
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, extension, output)?;
        } else if path.extension().and_then(|value| value.to_str()) == Some(extension) {
            output.push(path);
        }
    }
    Ok(())
}

fn patch_swift_entrypoint(path: &Path) -> Result<()> {
    let mut content = fs::read_to_string(path)
        .with_context(|| format!("读取 Swift 启动入口失败：{}", path.display()))?;
    if content.contains("ShellsmithProtection.start(") {
        return Ok(());
    }
    let main_index = find_swift_main(&content).context("启动入口缺少 @main")?;
    let type_open = content[main_index..]
        .find('{')
        .map(|index| main_index + index)
        .context("无法识别 @main 类型主体")?;
    let type_close = matching_brace(&content, type_open).context("@main 类型大括号不完整")?;
    let call =
        "// Shellsmith 自动生成：应用启动时尽早启用保护。\n        ShellsmithProtection.start()\n";
    let insertion = if code_contains_conformance(&content, main_index, type_open, "App") {
        find_top_level_initializer(&content, type_open, type_close)
            .map(|brace| (brace + 1, format!("\n        {call}")))
            .unwrap_or_else(|| {
                (
                    type_open + 1,
                    format!("\n    init() {{\n        {call}    }}\n"),
                )
            })
    } else if code_contains_conformance(&content, main_index, type_close, "UIApplicationDelegate") {
        content[main_index..type_close]
            .find("didFinishLaunchingWithOptions")
            .and_then(|relative| {
                let signature = main_index + relative;
                find_code_char(&content, signature, type_close, b'{')
            })
            .map(|brace| (brace + 1, format!("\n        {call}")))
            .unwrap_or_else(|| {
                (
                    type_open + 1,
                    format!(
                        "\n    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {{\n        {call}        return true\n    }}\n"
                    ),
                )
            })
    } else {
        anyhow::bail!("无法识别 @main 是 SwiftUI App 还是 UIApplicationDelegate；请手动接入 ShellsmithProtection.start()")
    };
    content.insert_str(insertion.0, &insertion.1);
    if !content
        .lines()
        .any(|line| line.trim() == "import ShellsmithRuntime")
    {
        let import_at = content
            .lines()
            .take_while(|line| {
                let value = line.trim();
                value.is_empty() || value.starts_with("//") || value.starts_with("import ")
            })
            .map(|line| line.len() + 1)
            .sum::<usize>()
            .min(content.len());
        content.insert_str(import_at, "import ShellsmithRuntime\n");
    }
    fs::write(path, content)?;
    Ok(())
}

fn find_top_level_initializer(content: &str, open: usize, close: usize) -> Option<usize> {
    let bytes = content.as_bytes();
    let mask = swift_code_mask(content);
    let mut depth = 1usize;
    let mut index = open + 1;
    while index < close {
        if !mask[index] {
            index += 1;
            continue;
        }
        match bytes[index] {
            b'{' => depth += 1,
            b'}' => depth = depth.saturating_sub(1),
            b'i' if depth == 1 && content[index..close].starts_with("init") => {
                let before_ok = index == 0 || !is_identifier(bytes[index - 1]);
                let after = bytes.get(index + 4).copied();
                if before_ok && matches!(after, Some(b'(' | b' ' | b'\t' | b'\n')) {
                    if let Some(brace) = find_code_char(content, index, close, b'{') {
                        return Some(brace);
                    }
                }
            }
            _ => {}
        }
        index += 1;
    }
    None
}

fn code_contains_conformance(content: &str, start: usize, end: usize, needle: &str) -> bool {
    let mask = swift_code_mask(content);
    let bytes = content.as_bytes();
    content[start..end]
        .match_indices(needle)
        .any(|(offset, _)| {
            let begin = start + offset;
            let before = (0..begin)
                .rev()
                .find(|index| !bytes[*index].is_ascii_whitespace())
                .and_then(|index| bytes.get(index).copied());
            let after = bytes.get(begin + needle.len()).copied();
            mask[begin..begin + needle.len()].iter().all(|value| *value)
                && matches!(before, Some(b':' | b','))
                && !after.is_some_and(is_identifier)
        })
}

fn find_code_char(content: &str, start: usize, end: usize, needle: u8) -> Option<usize> {
    let mask = swift_code_mask(content);
    content.as_bytes()[start..end]
        .iter()
        .enumerate()
        .find_map(|(offset, byte)| {
            (*byte == needle && mask[start + offset]).then_some(start + offset)
        })
}

fn is_identifier(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn matching_brace(content: &str, open: usize) -> Option<usize> {
    let mask = swift_code_mask(content);
    let mut depth = 0usize;
    for (offset, byte) in content.as_bytes()[open..].iter().enumerate() {
        if !mask[open + offset] {
            continue;
        }
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(open + offset);
                }
            }
            _ => {}
        }
    }
    None
}

fn find_swift_main(content: &str) -> Option<usize> {
    let mask = swift_code_mask(content);
    content
        .as_bytes()
        .windows(b"@main".len())
        .enumerate()
        .find_map(|(index, bytes)| {
            (bytes == b"@main"
                && mask[index..index + b"@main".len()]
                    .iter()
                    .all(|value| *value))
            .then_some(index)
        })
}

fn swift_code_mask(content: &str) -> Vec<bool> {
    let bytes = content.as_bytes();
    let mut mask = vec![true; bytes.len()];
    let mut index = 0usize;
    let mut line_comment = false;
    let mut block_comment = false;
    let mut string_delimiter = 0usize;
    let mut quote = b'"';
    let mut escaped = false;
    while index < bytes.len() {
        if line_comment {
            mask[index] = false;
            if bytes[index] == b'\n' {
                line_comment = false;
            }
            index += 1;
            continue;
        }
        if block_comment {
            mask[index] = false;
            if index + 1 < bytes.len() && bytes[index] == b'*' && bytes[index + 1] == b'/' {
                mask[index + 1] = false;
                block_comment = false;
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        if string_delimiter != 0 {
            mask[index] = false;
            if escaped {
                escaped = false;
                index += 1;
                continue;
            }
            if bytes[index] == b'\\' && string_delimiter == 1 {
                escaped = true;
                index += 1;
                continue;
            }
            if string_delimiter == 3
                && index + 2 < bytes.len()
                && &bytes[index..index + 3] == b"\"\"\""
            {
                mask[index + 1] = false;
                mask[index + 2] = false;
                string_delimiter = 0;
                index += 3;
            } else if string_delimiter == 1 && bytes[index] == quote {
                string_delimiter = 0;
                index += 1;
            } else {
                index += 1;
            }
            continue;
        }
        if index + 1 < bytes.len() && bytes[index] == b'/' && bytes[index + 1] == b'/' {
            mask[index] = false;
            mask[index + 1] = false;
            line_comment = true;
            index += 2;
        } else if index + 1 < bytes.len() && bytes[index] == b'/' && bytes[index + 1] == b'*' {
            mask[index] = false;
            mask[index + 1] = false;
            block_comment = true;
            index += 2;
        } else if index + 2 < bytes.len() && &bytes[index..index + 3] == b"\"\"\"" {
            mask[index] = false;
            mask[index + 1] = false;
            mask[index + 2] = false;
            string_delimiter = 3;
            index += 3;
        } else if bytes[index] == b'\"' {
            mask[index] = false;
            string_delimiter = 1;
            quote = b'"';
            index += 1;
        } else if bytes[index] == b'\'' {
            mask[index] = false;
            string_delimiter = 1;
            quote = b'\'';
            index += 1;
        } else {
            index += 1;
        }
    }
    mask
}

fn find_pbxproj_for_target(
    working_root: &Path,
    working_project: &Path,
    target: &IosTargetInspection,
) -> Result<PathBuf> {
    if working_project.extension().and_then(|value| value.to_str()) == Some("xcodeproj") {
        return Ok(working_project.join("project.pbxproj"));
    }
    let mut candidates = Vec::new();
    collect_pbxproj(working_root, &mut candidates)?;
    candidates
        .into_iter()
        .find(|path| {
            fs::read_to_string(path).is_ok_and(|content| {
                content.contains(&format!("name = {};", target.name))
                    || content.contains(&format!("/* {} */ = {{", target.name))
            })
        })
        .context("无法在 workspace 中定位应用 target 所属的 project.pbxproj")
}

fn collect_pbxproj(root: &Path, output: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if should_skip(&entry.file_name()) || entry.file_name() == "Pods" {
            continue;
        }
        let path = entry.path();
        if path.file_name() == Some(OsStr::new("project.pbxproj")) {
            output.push(path);
        } else if path.is_dir() {
            collect_pbxproj(&path, output)?;
        }
    }
    Ok(())
}

fn patch_pbxproj(path: &Path, target_name: &str, package_path: &Path) -> Result<()> {
    let mut content = fs::read_to_string(path)
        .with_context(|| format!("读取 project.pbxproj 失败：{}", path.display()))?;
    if content.contains("ShellsmithRuntime in Frameworks") {
        return Ok(());
    }
    let package_display = package_path.to_string_lossy().replace('\\', "/");
    let package_id = stable_id(target_name, &package_display, "package");
    let product_id = stable_id(target_name, &package_display, "product");
    let build_id = stable_id(target_name, &package_display, "build");

    let target_id = find_native_target_id(&content, target_name)
        .with_context(|| format!("project.pbxproj 中没有 target：{target_name}"))?;
    let target_block = object_block(&content, &target_id).context("target 对象结构不完整")?;
    let build_phase_ids = list_ids(&content[target_block.0..target_block.1], "buildPhases");
    let framework_phase = build_phase_ids
        .iter()
        .find(|id| {
            object_block(&content, id).is_some_and(|(start, end)| {
                content[start..end].contains("isa = PBXFrameworksBuildPhase;")
            })
        })
        .context("应用 target 缺少 PBXFrameworksBuildPhase")?
        .clone();

    insert_list_item_in_object(
        &mut content,
        &framework_phase,
        "files",
        &format!("{build_id} /* ShellsmithRuntime in Frameworks */"),
    )?;
    insert_list_item_in_object(
        &mut content,
        &target_id,
        "packageProductDependencies",
        &format!("{product_id} /* ShellsmithRuntime */"),
    )?;
    let project_id = find_first_object_with_isa(&content, "PBXProject")
        .context("project.pbxproj 缺少 PBXProject")?;
    insert_list_item_in_object(
        &mut content,
        &project_id,
        "packageReferences",
        &format!(
            "{package_id} /* XCLocalSwiftPackageReference \"{}\" */",
            package_display
        ),
    )?;

    insert_section_entry(
        &mut content,
        "PBXBuildFile",
        &format!(
            "\t\t{build_id} /* ShellsmithRuntime in Frameworks */ = {{isa = PBXBuildFile; productRef = {product_id} /* ShellsmithRuntime */; }};\n"
        ),
    )?;
    insert_section_entry(
        &mut content,
        "XCLocalSwiftPackageReference",
        &format!(
            "\t\t{package_id} /* XCLocalSwiftPackageReference \"{package_display}\" */ = {{\n\t\t\tisa = XCLocalSwiftPackageReference;\n\t\t\trelativePath = \"{package_display}\";\n\t\t}};\n"
        ),
    )?;
    insert_section_entry(
        &mut content,
        "XCSwiftPackageProductDependency",
        &format!(
            "\t\t{product_id} /* ShellsmithRuntime */ = {{\n\t\t\tisa = XCSwiftPackageProductDependency;\n\t\t\tpackage = {package_id} /* XCLocalSwiftPackageReference \"{package_display}\" */;\n\t\t\tproductName = ShellsmithRuntime;\n\t\t}};\n"
        ),
    )?;
    fs::write(path, content)?;
    Ok(())
}

fn find_native_target_id(content: &str, target_name: &str) -> Option<String> {
    let section = section_range(content, "PBXNativeTarget")?;
    let mut cursor = section.0;
    while cursor < section.1 {
        let equals = content[cursor..section.1]
            .find(" = {")
            .map(|value| cursor + value)?;
        let line_start = content[..equals].rfind('\n').map_or(0, |value| value + 1);
        let id = content[line_start..equals]
            .split_whitespace()
            .next()?
            .to_string();
        let (start, end) = object_block(content, &id)?;
        let block = &content[start..end];
        if block
            .lines()
            .any(|line| line.trim() == format!("name = {target_name};"))
            || block.contains(&format!("name = \"{target_name}\";"))
        {
            return Some(id);
        }
        cursor = end;
    }
    None
}

fn find_first_object_with_isa(content: &str, isa: &str) -> Option<String> {
    let needle = format!("isa = {isa};");
    let isa_index = content.find(&needle)?;
    let object_start = content[..isa_index].rfind(" = {")?;
    let line_start = content[..object_start]
        .rfind('\n')
        .map_or(0, |value| value + 1);
    content[line_start..object_start]
        .split_whitespace()
        .next()
        .map(str::to_string)
}

fn object_block(content: &str, id: &str) -> Option<(usize, usize)> {
    let marker = format!("{id} ");
    let start = content.find(&marker)?;
    let open = content[start..].find('{').map(|value| start + value)?;
    matching_brace(content, open).map(|close| (start, close + 1))
}

fn list_ids(block: &str, field: &str) -> Vec<String> {
    let marker = format!("{field} = (");
    let Some(start) = block.find(&marker).map(|value| value + marker.len()) else {
        return Vec::new();
    };
    let Some(end) = block[start..].find(");").map(|value| start + value) else {
        return Vec::new();
    };
    block[start..end]
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|value| value.len() == 24 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .map(str::to_string)
        .collect()
}

fn insert_list_item_in_object(
    content: &mut String,
    object_id: &str,
    field: &str,
    item: &str,
) -> Result<()> {
    if content.contains(item) {
        return Ok(());
    }
    let (start, end) = object_block(content, object_id)
        .with_context(|| format!("找不到 Xcode 对象：{object_id}"))?;
    let block = &content[start..end];
    let marker = format!("{field} = (");
    if let Some(relative) = block.find(&marker) {
        let insertion = start + relative + marker.len();
        content.insert_str(insertion, &format!("\n\t\t\t\t{item},"));
        return Ok(());
    }
    let closing = end - 1;
    content.insert_str(
        closing,
        &format!("\t\t\t{field} = (\n\t\t\t\t{item},\n\t\t\t);\n\t\t"),
    );
    Ok(())
}

fn insert_section_entry(content: &mut String, section: &str, entry: &str) -> Result<()> {
    let end_marker = format!("/* End {section} section */");
    if let Some(end) = content.find(&end_marker) {
        content.insert_str(end, entry);
        return Ok(());
    }
    let anchor = content
        .find("\t};\n\trootObject")
        .context("project.pbxproj 缺少 objects 结束标记")?;
    let section_text =
        format!("/* Begin {section} section */\n{entry}/* End {section} section */\n\n");
    content.insert_str(anchor, &section_text);
    Ok(())
}

fn section_range(content: &str, section: &str) -> Option<(usize, usize)> {
    let begin = content.find(&format!("/* Begin {section} section */"))?;
    let end = content[begin..]
        .find(&format!("/* End {section} section */"))
        .map(|value| begin + value)?;
    Some((begin, end))
}

fn stable_id(target: &str, package: &str, role: &str) -> String {
    let digest = Sha256::digest(format!("shellsmith:{target}:{package}:{role}"));
    digest[..12]
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect()
}

fn relative_path(from: &Path, to: &Path) -> Result<PathBuf> {
    let from = from.canonicalize()?;
    let to = to.canonicalize()?;
    let from_components = from.components().collect::<Vec<_>>();
    let to_components = to.components().collect::<Vec<_>>();
    let common = from_components
        .iter()
        .zip(&to_components)
        .take_while(|(left, right)| left == right)
        .count();
    let mut relative = PathBuf::new();
    for component in &from_components[common..] {
        if matches!(component, Component::Normal(_)) {
            relative.push("..");
        }
    }
    for component in &to_components[common..] {
        relative.push(component.as_os_str());
    }
    Ok(relative)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IosProjectConfig, IosProtectionConfig};

    #[test]
    fn patches_swiftui_entrypoint_once() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        fs::write(
            temp.path(),
            "import SwiftUI\n\n@main\nstruct DemoApp: App {\n    var body: some Scene { WindowGroup { Text(\"Hi\") } }\n}\n",
        )
        .unwrap();
        patch_swift_entrypoint(temp.path()).unwrap();
        patch_swift_entrypoint(temp.path()).unwrap();
        let content = fs::read_to_string(temp.path()).unwrap();
        assert_eq!(content.matches("ShellsmithProtection.start()").count(), 1);
        assert_eq!(content.matches("import ShellsmithRuntime").count(), 1);
    }

    #[test]
    fn patches_existing_app_delegate_callback() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        fs::write(
            temp.path(),
            "import UIKit\n@main\nclass AppDelegate: UIResponder, UIApplicationDelegate {\nfunc application(_ application: UIApplication, didFinishLaunchingWithOptions options: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {\nreturn true\n}\n}\n",
        )
        .unwrap();
        patch_swift_entrypoint(temp.path()).unwrap();
        let content = fs::read_to_string(temp.path()).unwrap();
        let start = content.find("ShellsmithProtection.start()").unwrap();
        let returns = content.find("return true").unwrap();
        assert!(start < returns);
    }

    #[test]
    fn ignores_main_and_braces_inside_comments_and_strings() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        fs::write(
            temp.path(),
            "// @main struct Fake { let value = \"{\" }\nimport SwiftUI\n@main\nstruct DemoApp: App {\n    var body: some Scene { WindowGroup { Text(\"Hi\") } }\n}\n",
        )
        .unwrap();
        patch_swift_entrypoint(temp.path()).unwrap();
        let content = fs::read_to_string(temp.path()).unwrap();
        assert_eq!(content.matches("ShellsmithProtection.start()").count(), 1);
    }

    #[test]
    fn patches_pure_objc_app_delegate_once_without_touching_main() {
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path().join("Demo.xcodeproj");
        fs::create_dir(&project).unwrap();
        let main = temp.path().join("main.m");
        let main_source = "#import <UIKit/UIKit.h>\nint main(int argc, char * argv[]) { @autoreleasepool { return UIApplicationMain(argc, argv, nil, @\"AppDelegate\"); } }\n";
        fs::write(&main, main_source).unwrap();
        let entrypoint = temp.path().join("AppDelegate.m");
        fs::write(
            &entrypoint,
            "// didFinishLaunchingWithOptions in a comment\n// [ShellsmithProtectionBootstrap start]\n#import \"AppDelegate.h\"\n@implementation AppDelegate\n- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {\n    char brace = '{';\n    NSString *example = @\"didFinishLaunchingWithOptions\";\n    return YES;\n}\n@end\n",
        )
        .unwrap();
        let config = ShellsmithIosConfig {
            project: IosProjectConfig {
                path: project,
                scheme: "Demo".into(),
                configuration: "Release".into(),
                team_id: "ABCDE12345".into(),
                bundle_ids: vec!["com.example.demo".into()],
                entrypoint: None,
            },
            protection: IosProtectionConfig::default(),
            confidential: None,
            rasp: None,
        };
        assert_eq!(
            resolve_entrypoint(temp.path(), &config).unwrap(),
            entrypoint
        );
        patch_objc_entrypoint(&entrypoint).unwrap();
        patch_objc_entrypoint(&entrypoint).unwrap();
        let content = fs::read_to_string(&entrypoint).unwrap();
        assert_eq!(content.matches("@import ShellsmithRuntime;").count(), 1);
        assert_eq!(
            content
                .matches("[ShellsmithProtectionBootstrap start]")
                .count(),
            2
        );
        assert!(
            content
                .rfind("[ShellsmithProtectionBootstrap start]")
                .unwrap()
                < content.rfind("return YES").unwrap()
        );
        assert_eq!(fs::read_to_string(main).unwrap(), main_source);
        assert!(
            freerasp::protection_source(&config).contains("@objc(ShellsmithProtectionBootstrap)")
        );
    }

    #[test]
    fn objc_file_without_launch_callback_fails_without_changes() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        let original = "#import \"AppDelegate.h\"\n@implementation AppDelegate\n// didFinishLaunchingWithOptions\n- (void)applicationDidBecomeActive:(UIApplication *)application { NSLog(@\"ready\"); }\n@end\n";
        fs::write(temp.path(), original).unwrap();
        assert!(patch_objc_entrypoint(temp.path()).is_err());
        assert_eq!(fs::read_to_string(temp.path()).unwrap(), original);
    }

    #[test]
    fn patches_local_package_into_application_target() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("project.pbxproj");
        fs::write(
            &path,
            r#"// !$*UTF8*$!
{
	objects = {
/* Begin PBXBuildFile section */
/* End PBXBuildFile section */
/* Begin PBXFrameworksBuildPhase section */
		BBBBBBBBBBBBBBBBBBBBBBBB /* Frameworks */ = {
			isa = PBXFrameworksBuildPhase;
			files = (
			);
		};
/* End PBXFrameworksBuildPhase section */
/* Begin PBXNativeTarget section */
		AAAAAAAAAAAAAAAAAAAAAAAA /* Demo */ = {
			isa = PBXNativeTarget;
			buildPhases = (
				BBBBBBBBBBBBBBBBBBBBBBBB /* Frameworks */,
			);
			name = Demo;
			productType = "com.apple.product-type.application";
		};
/* End PBXNativeTarget section */
/* Begin PBXProject section */
		CCCCCCCCCCCCCCCCCCCCCCCC /* Project object */ = {
			isa = PBXProject;
			targets = (
				AAAAAAAAAAAAAAAAAAAAAAAA,
			);
		};
/* End PBXProject section */
	};
	rootObject = CCCCCCCCCCCCCCCCCCCCCCCC;
}
"#,
        )
        .unwrap();
        patch_pbxproj(&path, "Demo", Path::new(".shellsmith/ShellsmithRuntime")).unwrap();
        patch_pbxproj(&path, "Demo", Path::new(".shellsmith/ShellsmithRuntime")).unwrap();
        let content = fs::read_to_string(path).unwrap();
        assert_eq!(
            content
                .matches("ShellsmithRuntime in Frameworks */ =")
                .count(),
            1
        );
        assert!(content.contains("XCLocalSwiftPackageReference"));
        assert!(content.contains("packageProductDependencies = ("));
    }
}
