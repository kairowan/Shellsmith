use crate::confidential;
use crate::freerasp;
use crate::project_inspect::IosTargetInspection;
use crate::ShellsmithIosConfig;
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
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
    let source_canonical = source.canonicalize()?;
    let destination_canonical = destination.canonicalize()?;
    if destination_canonical.starts_with(&source_canonical) {
        anyhow::bail!("工作副本目录不能位于源码目录内：{}", destination.display());
    }
    copy_directory(source, destination, source, destination, cancel)?;
    Ok(destination.to_path_buf())
}

pub(crate) fn integrate_runtime(
    working_root: &Path,
    working_project: &Path,
    target: &IosTargetInspection,
    config: &ShellsmithIosConfig,
    confidential_path: Option<&Path>,
) -> Result<()> {
    ensure_within_root(working_root, working_project, "Xcode 工程")?;
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
    ensure_within_root(working_root, &entrypoint, "iOS 启动入口")?;
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
    ensure_within_root(working_root, &pbxproj, "project.pbxproj")?;
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
    destination_root: &Path,
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
            copy_symlink(
                &source_path,
                &destination_path,
                source_root,
                destination_root,
            )?;
        } else if metadata.is_dir() {
            fs::create_dir_all(&destination_path)?;
            copy_directory(
                &source_path,
                &destination_path,
                source_root,
                destination_root,
                cancel,
            )?;
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

fn copy_symlink(
    source: &Path,
    destination: &Path,
    source_root: &Path,
    destination_root: &Path,
) -> Result<()> {
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

    // 绝对链接若原样复制，会继续指向原工程。将其重映射为副本内部的相对链接，
    // 这样后续补丁只会修改工作副本，不会写回用户工程。
    let copied_link = if link.is_absolute() {
        let relative_to_root = canonical
            .strip_prefix(&root)
            .context("无法计算符号链接在源码根目录内的相对路径")?;
        let copied_target = destination_root.canonicalize()?.join(relative_to_root);
        let destination_parent = destination
            .parent()
            .unwrap_or(destination_root)
            .canonicalize()?;
        lexical_relative_path(&destination_parent, &copied_target)?
    } else {
        link
    };

    #[cfg(unix)]
    std::os::unix::fs::symlink(copied_link, destination)?;
    #[cfg(not(unix))]
    anyhow::bail!("当前系统不能复制 iOS 工程符号链接");
    Ok(())
}

/// 计算两个绝对路径之间的相对路径。目标允许尚未复制完成，因此这里只做词法计算，
/// 不对目标调用 canonicalize。
fn lexical_relative_path(from: &Path, to: &Path) -> Result<PathBuf> {
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
    if relative.as_os_str().is_empty() {
        relative.push(".");
    }
    Ok(relative)
}

fn ensure_within_root(root: &Path, path: &Path, label: &str) -> Result<()> {
    let root = root
        .canonicalize()
        .with_context(|| format!("无法解析{label}根目录: {}", root.display()))?;
    let resolved = path
        .canonicalize()
        .with_context(|| format!("无法解析{label}: {}", path.display()))?;
    if !resolved.starts_with(&root) {
        anyhow::bail!("{label}位于工作副本之外: {}", path.display());
    }
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
        ensure_within_root(working_root, &candidate, "iOS 启动入口")?;
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
    let canonical_root = root.canonicalize()?;
    let mut visited_dirs = HashSet::new();
    let mut visited_files = HashSet::new();
    collect_files_inner(
        canonical_root.as_path(),
        root,
        extension,
        output,
        &mut visited_dirs,
        &mut visited_files,
    )
}

fn collect_files_inner(
    root: &Path,
    directory: &Path,
    extension: &str,
    output: &mut Vec<PathBuf>,
    visited_dirs: &mut HashSet<PathBuf>,
    visited_files: &mut HashSet<PathBuf>,
) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if should_skip(&entry.file_name()) || entry.file_name() == "Pods" {
            continue;
        }
        let path = entry.path();
        let canonical = path
            .canonicalize()
            .with_context(|| format!("解析工程路径或符号链接失败：{}", path.display()))?;
        if !canonical.starts_with(root) {
            anyhow::bail!("工程符号链接指向工作副本之外：{}", path.display());
        }
        if canonical.is_dir() {
            if visited_dirs.insert(canonical) {
                collect_files_inner(root, &path, extension, output, visited_dirs, visited_files)?;
            }
        } else if canonical.is_file()
            && path.extension().and_then(|value| value.to_str()) == Some(extension)
            && visited_files.insert(canonical)
        {
            output.push(path);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StartCallState {
    Absent,
    Direct,
    NestedOrConditional,
}

fn patch_swift_entrypoint(path: &Path) -> Result<()> {
    let mut content = fs::read_to_string(path)
        .with_context(|| format!("读取 Swift 启动入口失败：{}", path.display()))?;
    let main_index = find_swift_main(&content).context("启动入口缺少 @main")?;
    let type_open = find_code_char(&content, main_index, content.len(), b'{')
        .context("无法识别 @main 类型主体")?;
    let type_close = matching_brace(&content, type_open).context("@main 类型大括号不完整")?;
    let call =
        "// Shellsmith 自动生成：应用启动时尽早启用保护。\n        ShellsmithProtection.start()\n";

    if code_contains_conformance(&content, main_index, type_open, "App") {
        if let Some(init_open) = find_swiftui_noarg_initializer(&content, type_open, type_close)? {
            let init_close =
                matching_brace(&content, init_open).context("SwiftUI App 的 init 大括号不完整")?;
            match start_call_state(&content, init_open + 1, init_close) {
                StartCallState::Direct => {}
                StartCallState::NestedOrConditional => anyhow::bail!(
                    "SwiftUI App 的启动调用位于条件分支或嵌套作用域，无法确认每次启动都会执行；请手动调整"
                ),
                StartCallState::Absent => {
                    content.insert_str(init_open + 1, &format!("\n        {call}"));
                }
            }
        } else {
            content.insert_str(
                type_open + 1,
                &format!("\n    init() {{\n        {call}    }}\n"),
            );
        }
    } else if code_contains_conformance(&content, main_index, type_close, "UIApplicationDelegate") {
        if let Some(callback_open) = find_swift_launch_callback(&content, main_index, type_close)? {
            let callback_close =
                matching_brace(&content, callback_open).context("UIKit 启动回调大括号不完整")?;
            match start_call_state(&content, callback_open + 1, callback_close) {
                StartCallState::Direct => {}
                StartCallState::NestedOrConditional => anyhow::bail!(
                    "UIKit 启动回调中的保护调用位于条件分支或嵌套作用域，无法确认每次启动都会执行；请手动调整"
                ),
                StartCallState::Absent => {
                    content.insert_str(callback_open + 1, &format!("\n        {call}"));
                }
            }
        } else {
            content.insert_str(
                type_open + 1,
                &format!(
                    "\n    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {{\n        {call}        return true\n    }}\n"
                ),
            );
        }
    } else {
        anyhow::bail!("无法识别 @main 是 SwiftUI App 还是 UIApplicationDelegate；请手动接入 ShellsmithProtection.start()")
    }

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

fn find_swift_launch_callback(content: &str, start: usize, end: usize) -> Result<Option<usize>> {
    let mask = swift_code_mask(content);
    let bytes = content.as_bytes();
    let mut cursor = start;
    let mut scanned = 0usize;
    let mut conditional_depth = 0i32;
    let mut candidates = Vec::new();
    while let Some(callback) =
        find_code_word(content, &mask, "didFinishLaunchingWithOptions", cursor, end)
    {
        advance_conditional_depth(
            content,
            &mask,
            &mut scanned,
            callback,
            &mut conditional_depth,
        );
        cursor = callback + "didFinishLaunchingWithOptions".len();
        let before = (0..callback)
            .rev()
            .find(|index| mask[*index] && matches!(bytes[*index], b';' | b'{' | b'}'))
            .map_or(start, |index| index + 1);
        let mut func_start = None;
        let mut search = before;
        while let Some(found) = find_code_word(content, &mask, "func", search, callback) {
            func_start = Some(found);
            search = found + "func".len();
        }
        let Some(func_start) = func_start else {
            continue;
        };
        let signature = masked_code_text(content, &mask, func_start, callback);
        let compact = signature.split_whitespace().collect::<Vec<_>>().join(" ");
        if !compact.contains("func application") || !compact.contains("UIApplication") {
            continue;
        }
        if let Some(open) = find_code_char(content, callback, end, b'{') {
            if matching_brace(content, open).is_some() {
                candidates.push((open, conditional_depth > 0));
            }
        }
    }

    match candidates.as_slice() {
        [] => Ok(None),
        [(open, false)] => Ok(Some(*open)),
        _ => anyhow::bail!(
            "UIKit 启动回调位于条件编译或存在多个候选，无法确认 Release 构建一定执行保护调用；请在配置中指定稳定的启动入口"
        ),
    }
}

fn advance_conditional_depth(
    content: &str,
    mask: &[bool],
    from: &mut usize,
    to: usize,
    depth: &mut i32,
) {
    while *from < to {
        *depth = (*depth + swift_conditional_delta(content, mask, *from)).max(0);
        *from += 1;
    }
}

/// 只把代码屏蔽后的有效 `#if` / `#endif` 计入条件层级。
/// Swift 允许注释或 `{` 出现在同一行指令前，因此不能依赖原始行首空白。
fn swift_conditional_delta(content: &str, mask: &[bool], index: usize) -> i32 {
    if !mask[index] || content.as_bytes()[index] != b'#' {
        return 0;
    }
    let rest = &content[index..];
    if starts_swift_directive(rest, "#endif") {
        -1
    } else if starts_swift_directive(rest, "#if") {
        1
    } else {
        0
    }
}

fn starts_swift_directive(rest: &str, directive: &str) -> bool {
    rest.starts_with(directive)
        && rest
            .as_bytes()
            .get(directive.len())
            .is_none_or(|byte| !is_identifier(*byte))
}

fn masked_code_text(content: &str, mask: &[bool], start: usize, end: usize) -> String {
    let bytes = content.as_bytes();
    let mut text = Vec::with_capacity(end.saturating_sub(start));
    for index in start..end {
        text.push(if mask[index] { bytes[index] } else { b' ' });
    }
    String::from_utf8_lossy(&text).into_owned()
}

fn start_call_state(content: &str, start: usize, end: usize) -> StartCallState {
    let mask = swift_code_mask(content);
    let bytes = content.as_bytes();
    let needle = b"ShellsmithProtection.start(";
    let mut depth = 0i32;
    let mut conditional_depth = 0i32;
    let mut nested = false;
    let mut index = start;
    while index < end {
        if !mask[index] {
            index += 1;
            continue;
        }
        conditional_depth =
            (conditional_depth + swift_conditional_delta(content, &mask, index)).max(0);
        if bytes[index..end].starts_with(needle)
            && mask[index..index + needle.len()].iter().all(|value| *value)
        {
            if depth == 0 && conditional_depth == 0 {
                return StartCallState::Direct;
            }
            nested = true;
        }
        match bytes[index] {
            b'{' => depth += 1,
            b'}' => depth -= 1,
            _ => {}
        }
        index += 1;
    }
    if nested {
        StartCallState::NestedOrConditional
    } else {
        StartCallState::Absent
    }
}

/// 只定位参与 SwiftUI 启动的无参 `init()`。参数化重载和其他自定义初始化方法不能
/// 证明应用启动时执行过保护调用；存在多个或条件编译候选时拒绝猜测。
fn find_swiftui_noarg_initializer(
    content: &str,
    open: usize,
    close: usize,
) -> Result<Option<usize>> {
    let bytes = content.as_bytes();
    let mask = swift_code_mask(content);
    let mut depth = 1usize;
    let mut conditional_depth = 0i32;
    let mut candidates = Vec::new();
    let mut saw_init = false;
    let mut index = open + 1;
    while index < close {
        if !mask[index] {
            index += 1;
            continue;
        }
        conditional_depth =
            (conditional_depth + swift_conditional_delta(content, &mask, index)).max(0);

        match bytes[index] {
            b'{' => depth += 1,
            b'}' => depth = depth.saturating_sub(1),
            b'i' if depth == 1
                && content[index..close].starts_with("init")
                && (index == 0 || !is_identifier(bytes[index - 1]))
                && bytes
                    .get(index + 4)
                    .is_none_or(|byte| !is_identifier(*byte)) =>
            {
                let previous = content[..index]
                    .chars()
                    .rev()
                    .find(|value| !value.is_whitespace());
                if previous == Some('.') {
                    index += 4;
                    continue;
                }
                saw_init = true;
                let cursor = skip_swift_trivia(content, &mask, index + 4, close);
                if cursor < close && matches!(bytes[cursor], b'?' | b'!') {
                    index += 4;
                    continue;
                }
                if cursor >= close || bytes[cursor] != b'(' {
                    index += 4;
                    continue;
                }
                let Some(close_paren) = matching_paren(content, &mask, cursor, close) else {
                    index += 4;
                    continue;
                };
                let has_parameters = content[cursor + 1..close_paren]
                    .bytes()
                    .enumerate()
                    .any(|(offset, byte)| mask[cursor + 1 + offset] && !byte.is_ascii_whitespace());
                if has_parameters {
                    index = close_paren + 1;
                    continue;
                }
                let body_open = skip_swift_trivia(content, &mask, close_paren + 1, close);
                let Some(body_open) = find_code_char(content, body_open, close, b'{') else {
                    index = close_paren + 1;
                    continue;
                };
                if content[close_paren + 1..body_open]
                    .bytes()
                    .enumerate()
                    .any(|(offset, byte)| mask[close_paren + 1 + offset] && byte == b';')
                {
                    index = close_paren + 1;
                    continue;
                }
                let body_close = matching_brace(content, body_open)
                    .context("SwiftUI App 的无参 init 大括号不完整")?;
                candidates.push((body_open, conditional_depth > 0));
                index = body_close + 1;
                continue;
            }
            _ => {}
        }
        index += 1;
    }

    match candidates.as_slice() {
        [] if saw_init => anyhow::bail!(
            "@main 类型存在自定义 init，但没有可唯一确认的无参 init()；请手动接入 ShellsmithProtection.start()"
        ),
        [] => Ok(None),
        [(body_open, false)] => Ok(Some(*body_open)),
        _ => anyhow::bail!(
            "@main 类型存在多个或条件编译的无参 init()，无法唯一确定启动路径；请手动接入 ShellsmithProtection.start()"
        ),
    }
}

fn skip_swift_trivia(content: &str, mask: &[bool], mut index: usize, end: usize) -> usize {
    while index < end && (content.as_bytes()[index].is_ascii_whitespace() || !mask[index]) {
        index += 1;
    }
    index
}

fn matching_paren(content: &str, mask: &[bool], open: usize, end: usize) -> Option<usize> {
    let mut depth = 0i32;
    let mut index = open;
    while index < end {
        if mask[index] {
            match content.as_bytes()[index] {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(index);
                    }
                }
                _ => {}
            }
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
    let mut block_comment_depth = 0usize;
    let mut string_delimiter = 0usize;
    let mut raw_hashes = 0usize;
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
        if block_comment_depth > 0 {
            mask[index] = false;
            if index + 1 < bytes.len() && bytes[index] == b'/' && bytes[index + 1] == b'*' {
                mask[index + 1] = false;
                block_comment_depth += 1;
                index += 2;
            } else if index + 1 < bytes.len() && bytes[index] == b'*' && bytes[index + 1] == b'/' {
                mask[index + 1] = false;
                block_comment_depth -= 1;
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        if string_delimiter != 0 {
            mask[index] = false;
            if raw_hashes == 0 && escaped {
                escaped = false;
                index += 1;
                continue;
            }
            if raw_hashes == 0 && bytes[index] == b'\\' && string_delimiter == 1 {
                escaped = true;
                index += 1;
                continue;
            }
            if string_delimiter == 3 {
                if index + 2 < bytes.len() && &bytes[index..index + 3] == b"\"\"\"" {
                    mask[index + 1] = false;
                    mask[index + 2] = false;
                    let mut end = index + 3;
                    let mut hashes = 0;
                    while end < bytes.len() && hashes < raw_hashes && bytes[end] == b'#' {
                        mask[end] = false;
                        hashes += 1;
                        end += 1;
                    }
                    if hashes == raw_hashes {
                        string_delimiter = 0;
                        raw_hashes = 0;
                        index = end;
                    } else {
                        index += 3;
                    }
                } else {
                    index += 1;
                }
            } else if bytes[index] == quote {
                let mut end = index + 1;
                let mut hashes = 0;
                while end < bytes.len() && hashes < raw_hashes && bytes[end] == b'#' {
                    mask[end] = false;
                    hashes += 1;
                    end += 1;
                }
                if hashes == raw_hashes {
                    string_delimiter = 0;
                    raw_hashes = 0;
                    index = end;
                } else {
                    index += 1;
                }
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
            block_comment_depth = 1;
            index += 2;
        } else if bytes[index] == b'#' {
            let mut hashes = 0usize;
            let mut quote_at = index;
            while quote_at < bytes.len() && bytes[quote_at] == b'#' {
                hashes += 1;
                quote_at += 1;
            }
            if quote_at < bytes.len() && bytes[quote_at] == b'"' {
                let triple =
                    quote_at + 2 < bytes.len() && &bytes[quote_at..quote_at + 3] == b"\"\"\"";
                let end = quote_at + if triple { 3 } else { 1 };
                for value in mask.iter_mut().take(end).skip(index) {
                    *value = false;
                }
                string_delimiter = if triple { 3 } else { 1 };
                raw_hashes = hashes;
                quote = b'"';
                index = end;
            } else {
                index += 1;
            }
        } else if index + 2 < bytes.len() && &bytes[index..index + 3] == b"\"\"\"" {
            mask[index] = false;
            mask[index + 1] = false;
            mask[index + 2] = false;
            string_delimiter = 3;
            raw_hashes = 0;
            index += 3;
        } else if bytes[index] == b'\"' {
            mask[index] = false;
            string_delimiter = 1;
            raw_hashes = 0;
            quote = b'"';
            index += 1;
        } else if bytes[index] == b'\'' {
            mask[index] = false;
            string_delimiter = 1;
            raw_hashes = 0;
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
    let mut files = Vec::new();
    collect_files(root, "pbxproj", &mut files)?;
    output.extend(
        files
            .into_iter()
            .filter(|path| path.file_name() == Some(OsStr::new("project.pbxproj"))),
    );
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
    // 只匹配对象声明，不能从 containerPortal 等 ID 引用向后寻找花括号。
    content.match_indices(&marker).find_map(|(start, _)| {
        let mut suffix = content[start + id.len()..].trim_start();
        if let Some(comment) = suffix.strip_prefix("/*") {
            suffix = comment.split_once("*/")?.1.trim_start();
        }
        suffix = suffix.strip_prefix('=')?.trim_start();
        if !suffix.starts_with('{') {
            return None;
        }
        let open = content.len() - suffix.len();
        matching_brace(content, open).map(|close| (start, close + 1))
    })
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

    #[cfg(unix)]
    #[test]
    fn 工作副本保留_pods_工作区锁文件和相对头文件链接() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let destination = temp.path().join("output/project");
        fs::create_dir_all(source.join("Pods/Headers/Public/PodSDK")).unwrap();
        for (path, content) in [
            ("Demo.xcworkspace/contents.xcworkspacedata", "<Workspace/>"),
            ("Demo.xcodeproj/project.pbxproj", "Demo"),
            ("Pods/Pods.xcodeproj/project.pbxproj", "Pods"),
            ("Pods/PodSDK/PodSDK.h", "#pragma once"),
            ("Podfile.lock", "PODS: [PodSDK]"),
            ("Pods/Manifest.lock", "PODS: [PodSDK]"),
        ] {
            let file = source.join(path);
            fs::create_dir_all(file.parent().unwrap()).unwrap();
            fs::write(file, content).unwrap();
        }
        std::os::unix::fs::symlink(
            "../../../PodSDK/PodSDK.h",
            source.join("Pods/Headers/Public/PodSDK/PodSDK.h"),
        )
        .unwrap();
        copy_project_tree(&source, &destination, &Arc::new(AtomicBool::new(false))).unwrap();
        assert!(destination
            .join("Demo.xcworkspace/contents.xcworkspacedata")
            .is_file());
        assert!(destination
            .join("Pods/Pods.xcodeproj/project.pbxproj")
            .is_file());
        assert_eq!(
            fs::read(destination.join("Podfile.lock")).unwrap(),
            fs::read(destination.join("Pods/Manifest.lock")).unwrap()
        );
        let copied_header = destination
            .join("Pods/Headers/Public/PodSDK/PodSDK.h")
            .canonicalize()
            .unwrap();
        assert!(copied_header.starts_with(destination.canonicalize().unwrap()));
        assert_eq!(fs::read_to_string(copied_header).unwrap(), "#pragma once");
        fs::write(
            destination.join("Demo.xcodeproj/project.pbxproj"),
            "副本接入保护",
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(source.join("Demo.xcodeproj/project.pbxproj")).unwrap(),
            "Demo"
        );
    }

    #[test]
    fn 工作副本不能位于源码目录内() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("App.swift"), "let value = 1\n").unwrap();
        let destination = source.join("output/project");
        assert!(
            copy_project_tree(&source, &destination, &Arc::new(AtomicBool::new(false))).is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn 内部绝对符号链接复制后只指向工作副本() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let destination = temp.path().join("output/project");
        fs::create_dir_all(source.join("Real")).unwrap();
        fs::create_dir_all(source.join("Links")).unwrap();
        let original = source.join("Real/Entry.swift");
        fs::write(&original, "let value = 1\n").unwrap();
        let link = source.join("Links/Entry.swift");
        std::os::unix::fs::symlink(&original, &link).unwrap();

        copy_project_tree(&source, &destination, &Arc::new(AtomicBool::new(false))).unwrap();

        let copied_link = destination.join("Links/Entry.swift");
        assert!(fs::symlink_metadata(&copied_link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(!fs::read_link(&copied_link).unwrap().is_absolute());
        let copied_target = copied_link.canonicalize().unwrap();
        assert!(copied_target.starts_with(destination.canonicalize().unwrap()));

        fs::write(&copied_link, "let value = 2\n").unwrap();
        assert_eq!(fs::read_to_string(&original).unwrap(), "let value = 1\n");
        assert_eq!(
            fs::read_to_string(destination.join("Real/Entry.swift")).unwrap(),
            "let value = 2\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn 工程文件的绝对符号链接复制后不写回原工程() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let destination = temp.path().join("output/project");
        fs::create_dir_all(source.join("Project")).unwrap();
        fs::create_dir_all(source.join("Demo.xcodeproj")).unwrap();
        let original = source.join("Project/project.pbxproj");
        fs::write(&original, "// original\n").unwrap();
        std::os::unix::fs::symlink(&original, source.join("Demo.xcodeproj/project.pbxproj"))
            .unwrap();

        copy_project_tree(&source, &destination, &Arc::new(AtomicBool::new(false))).unwrap();
        fs::write(
            destination.join("Demo.xcodeproj/project.pbxproj"),
            "// patched copy\n",
        )
        .unwrap();
        assert_eq!(fs::read_to_string(&original).unwrap(), "// original\n");
        assert_eq!(
            fs::read_to_string(destination.join("Project/project.pbxproj")).unwrap(),
            "// patched copy\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn 指向源码外的绝对符号链接被拒绝() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let destination = temp.path().join("output/project");
        fs::create_dir_all(&source).unwrap();
        let outside = temp.path().join("outside.swift");
        fs::write(&outside, "let outside = true\n").unwrap();
        std::os::unix::fs::symlink(&outside, source.join("External.swift")).unwrap();

        assert!(
            copy_project_tree(&source, &destination, &Arc::new(AtomicBool::new(false))).is_err()
        );
        assert_eq!(
            fs::read_to_string(&outside).unwrap(),
            "let outside = true\n"
        );
    }

    #[test]
    fn 注释和字符串里的启动文字仍插入真实调用() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        fs::write(
            temp.path(),
            "import SwiftUI\n@main\nstruct DemoApp: App {\n    // ShellsmithProtection.start()\n    let text = \"ShellsmithProtection.start(\"\n    var body: some Scene { WindowGroup { Text(text) } }\n}\n",
        )
        .unwrap();
        patch_swift_entrypoint(temp.path()).unwrap();
        let content = fs::read_to_string(temp.path()).unwrap();
        let mask = swift_code_mask(&content);
        let needle = "ShellsmithProtection.start()";
        let code_calls = content
            .match_indices(needle)
            .filter(|(index, _)| {
                mask[*index..*index + needle.len()]
                    .iter()
                    .all(|value| *value)
            })
            .count();
        assert_eq!(code_calls, 1);
        assert!(content.contains("init() {"));
    }

    #[test]
    fn 无关方法里的启动调用不能阻止真实入口注入() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        fs::write(
            temp.path(),
            "import SwiftUI\n@main\nstruct DemoApp: App {\n    func helper() { ShellsmithProtection.start() }\n    var body: some Scene { WindowGroup { Text(\"Hi\") } }\n}\n",
        )
        .unwrap();
        patch_swift_entrypoint(temp.path()).unwrap();
        let content = fs::read_to_string(temp.path()).unwrap();
        assert_eq!(content.matches("ShellsmithProtection.start()").count(), 2);
        assert!(content.contains("init() {"));
    }

    #[test]
    fn 已有直接启动调用时保持幂等() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        let source = "import SwiftUI\nimport ShellsmithRuntime\n@main\nstruct DemoApp: App {\n    init() {\n        ShellsmithProtection.start()\n    }\n    var body: some Scene { WindowGroup { Text(\"Hi\") } }\n}\n";
        fs::write(temp.path(), source).unwrap();
        patch_swift_entrypoint(temp.path()).unwrap();
        patch_swift_entrypoint(temp.path()).unwrap();
        let content = fs::read_to_string(temp.path()).unwrap();
        assert_eq!(content.matches("ShellsmithProtection.start()").count(), 1);
        assert_eq!(content.matches("import ShellsmithRuntime").count(), 1);
    }

    #[test]
    fn 条件分支里的启动调用被明确拒绝且不修改文件() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        let source = "import SwiftUI\n@main\nstruct DemoApp: App {\n    init() {\n        if Bool.random() {\n            ShellsmithProtection.start()\n        }\n    }\n    var body: some Scene { WindowGroup { Text(\"Hi\") } }\n}\n";
        fs::write(temp.path(), source).unwrap();
        assert!(patch_swift_entrypoint(temp.path()).is_err());
        assert_eq!(fs::read_to_string(temp.path()).unwrap(), source);
    }

    #[test]
    fn 原始字符串和嵌套注释中的大括号不干扰定位() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        fs::write(
            temp.path(),
            "import SwiftUI\n@main\nstruct DemoApp: App {\n    /* 外层 /* 内层 } */ 仍然是注释 */\n    let raw = #\"{ @main ShellsmithProtection.start(\"#\n    var body: some Scene { WindowGroup { Text(raw) } }\n}\n",
        )
        .unwrap();
        patch_swift_entrypoint(temp.path()).unwrap();
        let content = fs::read_to_string(temp.path()).unwrap();
        assert_eq!(content.matches("ShellsmithProtection.start()").count(), 1);
    }

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
    fn swiftui_选择无参_init_而不是带参重载() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        fs::write(
            temp.path(),
            "import SwiftUI\n@main\nstruct DemoApp: App {\n    init(preview: Bool) { print(\"PREVIEW\") }\n    init() { print(\"REAL STARTUP\") }\n    var body: some Scene { WindowGroup { Text(\"Hi\") } }\n}\n",
        )
        .unwrap();
        patch_swift_entrypoint(temp.path()).unwrap();
        let content = fs::read_to_string(temp.path()).unwrap();
        let noarg = content.find("init() {").unwrap();
        let call = content.find("ShellsmithProtection.start()").unwrap();
        let startup = content.find("REAL STARTUP").unwrap();
        assert!(noarg < call && call < startup);
        assert_eq!(content.matches("ShellsmithProtection.start()").count(), 1);
    }

    #[test]
    fn swiftui_只有带参_init_时明确拒绝() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        let source = "import SwiftUI\n@main\nstruct DemoApp: App {\n    init(preview: Bool) { print(preview) }\n    var body: some Scene { WindowGroup { Text(\"Hi\") } }\n}\n";
        fs::write(temp.path(), source).unwrap();
        assert!(patch_swift_entrypoint(temp.path()).is_err());
        assert_eq!(fs::read_to_string(temp.path()).unwrap(), source);
    }

    #[test]
    fn swiftui_条件编译的无参_init_不被猜测() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        let source = "import SwiftUI\n@main\nstruct DemoApp: App {\n#if DEBUG\n    init() { print(\"DEBUG\") }\n#endif\n    var body: some Scene { WindowGroup { Text(\"Hi\") } }\n}\n";
        fs::write(temp.path(), source).unwrap();
        assert!(patch_swift_entrypoint(temp.path()).is_err());
        assert_eq!(fs::read_to_string(temp.path()).unwrap(), source);
    }

    #[test]
    fn uikit_条件编译包裹启动回调时拒绝自动接入() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        let source = "import UIKit\n@main\nclass AppDelegate: UIResponder, UIApplicationDelegate {\n#if DEBUG\n    func application(_ application: UIApplication,\n                     didFinishLaunchingWithOptions options: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {\n        return true\n    }\n#endif\n}\n";
        fs::write(temp.path(), source).unwrap();
        assert!(patch_swift_entrypoint(temp.path()).is_err());
        assert_eq!(fs::read_to_string(temp.path()).unwrap(), source);
    }

    #[test]
    fn uikit_注释前缀的条件编译同样被拒绝() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        let source = "import UIKit\n@main\nclass AppDelegate: UIResponder, UIApplicationDelegate {\n/* 启动说明 */ #if DEBUG\n    func application(_ application: UIApplication, didFinishLaunchingWithOptions options: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {\n        return true\n    }\n#endif\n}\n";
        fs::write(temp.path(), source).unwrap();
        assert!(patch_swift_entrypoint(temp.path()).is_err());
        assert_eq!(fs::read_to_string(temp.path()).unwrap(), source);
    }

    #[test]
    fn uikit_行内条件编译同样被拒绝() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        let source = "import UIKit\n@main\nclass AppDelegate: UIResponder, UIApplicationDelegate { #if DEBUG\n    func application(_ application: UIApplication, didFinishLaunchingWithOptions options: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {\n        return true\n    }\n#endif\n}\n";
        fs::write(temp.path(), source).unwrap();
        assert!(patch_swift_entrypoint(temp.path()).is_err());
        assert_eq!(fs::read_to_string(temp.path()).unwrap(), source);
    }

    #[test]
    fn uikit_字符串里的伪条件指令不影响正常回调() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        fs::write(
            temp.path(),
            "import UIKit\n@main\nclass AppDelegate: UIResponder, UIApplicationDelegate {\n    let marker = \"#if DEBUG\"\n    func application(_ application: UIApplication, didFinishLaunchingWithOptions options: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {\n        return true\n    }\n}\n",
        )
        .unwrap();
        patch_swift_entrypoint(temp.path()).unwrap();
        let content = fs::read_to_string(temp.path()).unwrap();
        assert_eq!(content.matches("func application(").count(), 1);
        assert_eq!(content.matches("ShellsmithProtection.start()").count(), 1);
    }

    #[test]
    fn uikit_回调前的注释不会导致重复方法() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        fs::write(
            temp.path(),
            "import UIKit\n@main\nclass AppDelegate: UIResponder, UIApplicationDelegate {\n    // 启动设置\n    func application(_ application: UIApplication,\n                     didFinishLaunchingWithOptions options: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {\n        return true\n    }\n}\n",
        )
        .unwrap();
        patch_swift_entrypoint(temp.path()).unwrap();
        let content = fs::read_to_string(temp.path()).unwrap();
        assert_eq!(content.matches("func application(").count(), 1);
        let call = content.find("ShellsmithProtection.start()").unwrap();
        let returns = content.find("return true").unwrap();
        assert!(call < returns);
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
        let project = temp.path().join("Demo.xcodeproj");
        fs::create_dir(&project).unwrap();
        let path = project.join("project.pbxproj");
        fs::write(
            &path,
            r#"// !$*UTF8*$!
{
	archiveVersion = 1;
	classes = {};
	objectVersion = 56;
	objects = {
/* Begin PBXBuildFile section */
		000000000000000000000050 /* main.m in Sources */ = {isa = PBXBuildFile; fileRef = 000000000000000000000040 /* main.m */; };
		000000000000000000000051 /* Share.m in Sources */ = {isa = PBXBuildFile; fileRef = 000000000000000000000041 /* Share.m */; };
		000000000000000000000052 /* Share.appex in Embed */ = {isa = PBXBuildFile; fileRef = 000000000000000000000043 /* Share.appex */; settings = {ATTRIBUTES = (RemoveHeadersOnCopy, ); }; };
/* End PBXBuildFile section */
/* Begin PBXContainerItemProxy section */
		DDDDDDDDDDDDDDDDDDDDDDDD /* PBXContainerItemProxy */ = {
			isa = PBXContainerItemProxy;
			containerPortal = CCCCCCCCCCCCCCCCCCCCCCCC /* Project object */;
			proxyType = 1;
			remoteGlobalIDString = EEEEEEEEEEEEEEEEEEEEEEEE;
			remoteInfo = "Share Extension";
		};
/* End PBXContainerItemProxy section */
/* Begin PBXCopyFilesBuildPhase section */
		000000000000000000000013 /* Embed */ = {isa = PBXCopyFilesBuildPhase; buildActionMask = 2147483647; dstPath = ""; dstSubfolderSpec = 13; files = (000000000000000000000052 /* Share.appex in Embed */, ); runOnlyForDeploymentPostprocessing = 0; };
/* End PBXCopyFilesBuildPhase section */
/* Begin PBXFileReference section */
		000000000000000000000040 /* main.m */ = {isa = PBXFileReference; lastKnownFileType = sourcecode.c.objc; path = main.m; sourceTree = "<group>"; };
		000000000000000000000041 /* Share.m */ = {isa = PBXFileReference; lastKnownFileType = sourcecode.c.objc; path = Share.m; sourceTree = "<group>"; };
		000000000000000000000042 /* Demo.app */ = {isa = PBXFileReference; explicitFileType = wrapper.application; path = Demo.app; sourceTree = BUILT_PRODUCTS_DIR; };
		000000000000000000000043 /* Share.appex */ = {isa = PBXFileReference; explicitFileType = "wrapper.app-extension"; path = Share.appex; sourceTree = BUILT_PRODUCTS_DIR; };
/* End PBXFileReference section */
/* Begin PBXFrameworksBuildPhase section */
		BBBBBBBBBBBBBBBBBBBBBBBB /* Frameworks */ = {
			isa = PBXFrameworksBuildPhase;
			buildActionMask = 2147483647;
			files = (
			);
			runOnlyForDeploymentPostprocessing = 0;
		};
		000000000000000000000014 /* Share Frameworks */ = {isa = PBXFrameworksBuildPhase; buildActionMask = 2147483647; files = (); runOnlyForDeploymentPostprocessing = 0; };
/* End PBXFrameworksBuildPhase section */
/* Begin PBXGroup section */
		000000000000000000000030 = {isa = PBXGroup; children = (000000000000000000000040, 000000000000000000000041, 000000000000000000000031, ); sourceTree = "<group>"; };
		000000000000000000000031 /* Products */ = {isa = PBXGroup; children = (000000000000000000000042, 000000000000000000000043, ); name = Products; sourceTree = "<group>"; };
/* End PBXGroup section */
/* Begin PBXNativeTarget section */
		AAAAAAAAAAAAAAAAAAAAAAAA /* Demo */ = {
			isa = PBXNativeTarget;
			buildConfigurationList = 000000000000000000000022;
			buildPhases = (
				000000000000000000000011 /* Sources */,
				BBBBBBBBBBBBBBBBBBBBBBBB /* Frameworks */,
				000000000000000000000013 /* Embed */,
			);
			dependencies = (000000000000000000000060, );
			name = Demo;
			productName = Demo;
			productReference = 000000000000000000000042;
			productType = "com.apple.product-type.application";
		};
		EEEEEEEEEEEEEEEEEEEEEEEE /* Share Extension */ = {
			isa = PBXNativeTarget;
			buildConfigurationList = 000000000000000000000024;
			buildPhases = (
				000000000000000000000015 /* Sources */,
				000000000000000000000014 /* Share Frameworks */,
			);
			dependencies = ();
			name = "Share Extension";
			productName = Share;
			productReference = 000000000000000000000043;
			productType = "com.apple.product-type.app-extension";
		};
/* End PBXNativeTarget section */
/* Begin PBXProject section */
		CCCCCCCCCCCCCCCCCCCCCCCC /* Project object */ = {
			isa = PBXProject;
			buildConfigurationList = 000000000000000000000020;
			compatibilityVersion = "Xcode 14.0";
			developmentRegion = en;
			knownRegions = (en, Base, );
			mainGroup = 000000000000000000000030;
			productRefGroup = 000000000000000000000031;
			projectDirPath = "";
			projectRoot = "";
			targets = (
				AAAAAAAAAAAAAAAAAAAAAAAA,
				EEEEEEEEEEEEEEEEEEEEEEEE,
			);
		};
/* End PBXProject section */
/* Begin PBXSourcesBuildPhase section */
		000000000000000000000011 /* Sources */ = {isa = PBXSourcesBuildPhase; buildActionMask = 2147483647; files = (000000000000000000000050, ); runOnlyForDeploymentPostprocessing = 0; };
		000000000000000000000015 /* Sources */ = {isa = PBXSourcesBuildPhase; buildActionMask = 2147483647; files = (000000000000000000000051, ); runOnlyForDeploymentPostprocessing = 0; };
/* End PBXSourcesBuildPhase section */
/* Begin PBXTargetDependency section */
		000000000000000000000060 = {isa = PBXTargetDependency; target = EEEEEEEEEEEEEEEEEEEEEEEE; targetProxy = DDDDDDDDDDDDDDDDDDDDDDDDDD; };
/* End PBXTargetDependency section */
/* Begin XCBuildConfiguration section */
		000000000000000000000021 = {isa = XCBuildConfiguration; buildSettings = {CLANG_ENABLE_MODULES = YES; CLANG_ENABLE_OBJC_ARC = YES; SDKROOT = iphoneos; IPHONEOS_DEPLOYMENT_TARGET = 15.0; SWIFT_VERSION = 5.0; CODE_SIGNING_ALLOWED = NO; }; name = Release; };
		000000000000000000000023 = {isa = XCBuildConfiguration; buildSettings = {GENERATE_INFOPLIST_FILE = YES; PRODUCT_NAME = Demo; PRODUCT_BUNDLE_IDENTIFIER = com.example.demo; MARKETING_VERSION = 1.0; CURRENT_PROJECT_VERSION = 1; TARGETED_DEVICE_FAMILY = "1,2"; }; name = Release; };
		000000000000000000000025 = {isa = XCBuildConfiguration; buildSettings = {INFOPLIST_FILE = "Share-Info.plist"; PRODUCT_NAME = Share; PRODUCT_BUNDLE_IDENTIFIER = com.example.demo.share; SKIP_INSTALL = YES; APPLICATION_EXTENSION_API_ONLY = YES; TARGETED_DEVICE_FAMILY = "1,2"; }; name = Release; };
/* End XCBuildConfiguration section */
/* Begin XCConfigurationList section */
		000000000000000000000020 = {isa = XCConfigurationList; buildConfigurations = (000000000000000000000021, ); defaultConfigurationIsVisible = 0; defaultConfigurationName = Release; };
		000000000000000000000022 = {isa = XCConfigurationList; buildConfigurations = (000000000000000000000023, ); defaultConfigurationIsVisible = 0; defaultConfigurationName = Release; };
		000000000000000000000024 = {isa = XCConfigurationList; buildConfigurations = (000000000000000000000025, ); defaultConfigurationIsVisible = 0; defaultConfigurationName = Release; };
/* End XCConfigurationList section */
	};
	rootObject = CCCCCCCCCCCCCCCCCCCCCCCC;
}
"#,
        )
        .unwrap();
        patch_pbxproj(&path, "Demo", Path::new(".shellsmith/ShellsmithRuntime")).unwrap();
        patch_pbxproj(&path, "Demo", Path::new(".shellsmith/ShellsmithRuntime")).unwrap();
        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(
            content
                .matches("ShellsmithRuntime in Frameworks */ =")
                .count(),
            1
        );
        assert!(content.contains("XCLocalSwiftPackageReference"));
        assert!(content.contains("packageProductDependencies = ("));
        let project_section = section_range(&content, "PBXProject").unwrap();
        assert!(content[project_section.0..project_section.1].contains("packageReferences = ("));
        let frameworks_section = section_range(&content, "PBXFrameworksBuildPhase").unwrap();
        assert!(!content[frameworks_section.0..frameworks_section.1].contains("packageReferences"));
        if cfg!(target_os = "macos") {
            let output = std::process::Command::new("plutil")
                .arg("-lint")
                .arg(&path)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stdout)
            );
        }

        // 本地结构检查始终执行；CI 另外启用完整 Xcode、上游依赖和无签名归档检查。
        if std::env::var_os("SHELLSMITH_TEST_XCODE_ARCHIVE").is_none() {
            return;
        }
        fs::write(
            temp.path().join("main.m"),
            "#import <UIKit/UIKit.h>\n@interface AppDelegate : UIResponder <UIApplicationDelegate>\n@property(strong, nonatomic) UIWindow *window;\n@end\n@implementation AppDelegate\n- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)options { return YES; }\n@end\nint main(int argc, char **argv) { @autoreleasepool { return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class])); } }\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Share.m"),
            "#import <UIKit/UIKit.h>\n@interface ShareViewController : UIViewController\n@end\n@implementation ShareViewController\n@end\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Share-Info.plist"),
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>$(EXECUTABLE_NAME)</string>
<key>CFBundleIdentifier</key><string>$(PRODUCT_BUNDLE_IDENTIFIER)</string>
<key>CFBundlePackageType</key><string>XPC!</string>
<key>CFBundleShortVersionString</key><string>1.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>NSExtension</key><dict>
<key>NSExtensionPointIdentifier</key><string>com.apple.share-services</string>
<key>NSExtensionPrincipalClass</key><string>ShareViewController</string>
</dict></dict></plist>"#,
        )
        .unwrap();
        let schemes = project.join("xcshareddata/xcschemes");
        fs::create_dir_all(&schemes).unwrap();
        fs::write(
            schemes.join("Demo.xcscheme"),
            r#"<?xml version="1.0" encoding="UTF-8"?>
<Scheme LastUpgradeVersion="1600" version="1.3">
<BuildAction parallelizeBuildables="YES" buildImplicitDependencies="YES"><BuildActionEntries>
<BuildActionEntry buildForTesting="YES" buildForRunning="YES" buildForProfiling="YES" buildForArchiving="YES" buildForAnalyzing="YES">
<BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="AAAAAAAAAAAAAAAAAAAAAAAA" BuildableName="Demo.app" BlueprintName="Demo" ReferencedContainer="container:Demo.xcodeproj"/>
</BuildActionEntry></BuildActionEntries></BuildAction>
<ArchiveAction buildConfiguration="Release" revealArchiveInOrganizer="YES"/>
</Scheme>"#,
        )
        .unwrap();
        let workspace = temp.path().join("Demo.xcworkspace");
        fs::create_dir(&workspace).unwrap();
        fs::write(
            workspace.join("contents.xcworkspacedata"),
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Workspace version=\"1.0\"><FileRef location=\"group:Demo.xcodeproj\"/></Workspace>",
        )
        .unwrap();
        let config = ShellsmithIosConfig {
            project: IosProjectConfig {
                path: project.clone(),
                scheme: "Demo".into(),
                configuration: "Release".into(),
                team_id: "ABCDE12345".into(),
                bundle_ids: vec!["com.example.demo".into()],
                entrypoint: None,
            },
            protection: IosProtectionConfig {
                profile: crate::IosProtectionProfile::Strict,
                ..IosProtectionConfig::default()
            },
            confidential: None,
            rasp: None,
        };
        let target = IosTargetInspection {
            name: "Demo".into(),
            product_type: "com.apple.product-type.application".into(),
            bundle_id: None,
            team_id: None,
            deployment_target: None,
            project_file: Some(project.clone()),
            build_library_for_distribution: false,
        };
        integrate_runtime(temp.path(), &project, &target, &config, None).unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let import = std::env::var_os("SHELLSMITH_TEST_FREERASP_ZIP").map(PathBuf::from);
        let sdk =
            crate::prepare_ios_sdk(&temp.path().join("sdk-cache"), import.as_deref(), &cancel)
                .unwrap();
        crate::dependency_cache::install_sdk(&sdk, temp.path(), &cancel).unwrap();
        for input in [&project, &workspace] {
            crate::xcodebuild::resolve_packages(input, "Demo", None, &cancel).unwrap();
            crate::dependency_cache::verify_installed_sdk(temp.path()).unwrap();
            let archive = temp.path().join(format!(
                "{}.xcarchive",
                input.extension().unwrap().to_string_lossy()
            ));
            crate::xcodebuild::archive(input, &config.project, &archive, None, false, &cancel)
                .unwrap();
            let app = archive.join("Products/Applications/Demo.app");
            assert!(app.join("Demo").is_file());
            assert!(app.join("PlugIns/Share.appex/Share").is_file());
            assert!(app
                .join("Frameworks/TalsecRuntime.framework/TalsecRuntime")
                .is_file());
        }
    }
}
