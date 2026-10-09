//! 软件内问题反馈：组装公开 issue 正文、生成预览、提交到统计服务并回退到预填页面。
//!
//! 正文由客户端生成，预览、实际提交与回退链接三处使用同一份内容，
//! 避免服务端与客户端各写一套模板后逐渐不一致。
//! 提交前会把用户文本中的本机主目录替换为 `~`，其余内容原样发送。

use crate::build_info::{get_app_info, get_diagnostic_info};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const FEEDBACK_URL: &str =
    "https://mocika-shield-stats-api.xuechao-suo.workers.dev/reports/feedback";
const ISSUE_NEW_URL: &str = "https://github.com/kairowan/Shellsmith/issues/new";
const SCHEMA_VERSION: u32 = 1;
const MAX_TITLE: usize = 120;
const MAX_FIELD: usize = 8000;
const MAX_BODY: usize = 24000;
/// 统计服务的请求体上限，客户端先按序列化后的字节数拦截，避免收到 400 才报错。
const MAX_PAYLOAD_BYTES: usize = 32768;
/// 预填链接过长时浏览器或服务端可能截断，回退正文限制在这个长度内并明确标注。
const MAX_FALLBACK_BODY: usize = 7000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FeedbackKind {
    Bug,
    Feature,
}

impl FeedbackKind {
    fn issue_prefix(self) -> &'static str {
        match self {
            Self::Bug => "[Bug] ",
            Self::Feature => "[功能建议] ",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FeedbackModule {
    Android,
    Ios,
    Sign,
    Certificates,
    Java,
    Update,
    Gui,
    Build,
    Docs,
    Other,
}

impl FeedbackModule {
    fn label(self) -> &'static str {
        match self {
            Self::Android => "加固（Android）",
            Self::Ios => "加固（iOS）",
            Self::Sign => "签名",
            Self::Certificates => "证书管理",
            Self::Java => "Java 环境检测",
            Self::Update => "更新检查",
            Self::Gui => "界面交互",
            Self::Build => "构建 / CI",
            Self::Docs => "文档与诊断",
            Self::Other => "其他",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FeedbackImpact {
    Blocking,
    Slower,
    NiceToHave,
}

impl FeedbackImpact {
    fn label(self) -> &'static str {
        match self {
            Self::Blocking => "阻塞使用，目前无法完成目标",
            Self::Slower => "明显影响效率，需要频繁绕行",
            Self::NiceToHave => "改善体验，有替代方案",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FeedbackPlatform {
    Windows,
    Macos,
    Linux,
    AndroidRuntime,
    Ios,
    Agnostic,
}

impl FeedbackPlatform {
    fn label(self) -> &'static str {
        match self {
            Self::Windows => "Windows",
            Self::Macos => "macOS",
            Self::Linux => "Linux",
            Self::AndroidRuntime => "Android 运行期",
            Self::Ios => "iOS",
            Self::Agnostic => "与平台无关",
        }
    }
}

/// 前端填写的反馈表单。文本字段长度与提交校验保持一致，避免先填后报错。
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FeedbackRequest {
    kind: FeedbackKind,
    module: FeedbackModule,
    title: String,
    /// bug 为复现步骤，feature 为使用场景。
    primary: String,
    /// bug 为期望结果，feature 为期望方案。
    expected: String,
    /// bug 为实际结果，feature 为当前问题。
    observed: String,
    #[serde(default)]
    impact: Option<FeedbackImpact>,
    #[serde(default)]
    platforms: Vec<FeedbackPlatform>,
    #[serde(default)]
    alternatives: String,
    #[serde(default)]
    extra: String,
    #[serde(default)]
    logs: String,
    #[serde(default = "default_true")]
    include_environment: bool,
}

fn default_true() -> bool {
    true
}

/// 提交给统计服务的固定字段集合，预览与提交使用同一个对象。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct FeedbackPayload {
    schema_version: u32,
    kind: FeedbackKind,
    title: String,
    body: String,
    app_version: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct FeedbackDraft {
    /// 与提交内容完全一致的标题（含服务端会加的前缀）。
    pub issue_title: String,
    /// 与提交内容完全一致的 Markdown 正文。
    pub body: String,
    pub payload: FeedbackPayload,
    /// 服务端不可用时在浏览器打开的预填页面。
    pub fallback_url: String,
    /// 预填链接因过长被截断时为真，界面需要提示用户手动补全。
    pub fallback_truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct FeedbackReceipt {
    pub number: u64,
    pub url: String,
}

#[tauri::command]
pub(crate) fn prepare_feedback(
    app: tauri::AppHandle,
    request: FeedbackRequest,
) -> Result<FeedbackDraft, String> {
    let app_info = get_app_info();
    let home = home_directory();
    // 诊断信息要探测 Java 与工具链，代价不低；只有 Bug 反馈的模板需要它。
    let environment = (request.include_environment && request.kind == FeedbackKind::Bug)
        .then(|| get_diagnostic_info(app));
    let body = build_body(&request, &app_info, environment.as_deref(), home.as_deref())?;
    let title = redact_home_paths(&request.title, home.as_deref())
        .trim()
        .to_string();
    validate_title(&title)?;
    let payload = FeedbackPayload {
        schema_version: SCHEMA_VERSION,
        kind: request.kind,
        title: title.clone(),
        body: body.clone(),
        app_version: app_info.version.clone(),
    };
    let serialized = serialize_payload(&payload)?;
    if serialized.len() > MAX_PAYLOAD_BYTES {
        return Err(format!(
            "反馈内容约 {} KB，超过 {} KB 上限，请精简后重试",
            serialized.len().div_ceil(1024),
            MAX_PAYLOAD_BYTES / 1024
        ));
    }
    let issue_title = format!("{}{}", request.kind.issue_prefix(), title);
    let (fallback_url, fallback_truncated) = fallback_url(&issue_title, &payload.kind, &body)?;
    Ok(FeedbackDraft {
        issue_title,
        body,
        payload,
        fallback_url,
        fallback_truncated,
    })
}

#[tauri::command]
pub(crate) async fn submit_feedback(payload: FeedbackPayload) -> Result<FeedbackReceipt, String> {
    validate_payload(&payload)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| "无法初始化反馈连接".to_string())?;
    let response = client
        .post(FEEDBACK_URL)
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await
        .map_err(|_| "反馈提交失败或超时，可改用浏览器提交".to_string())?;
    let status = response.status().as_u16();
    match status {
        200 | 201 => {
            let mut response = response;
            let mut bytes = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| "无法读取反馈回执".to_string())?
            {
                if bytes.len() + chunk.len() > 4096 {
                    return Err("反馈回执格式不符合约定".into());
                }
                bytes.extend_from_slice(&chunk);
            }
            let receipt: FeedbackReceipt =
                serde_json::from_slice(&bytes).map_err(|_| "反馈回执格式不符合约定".to_string())?;
            if receipt.url.is_empty() || !receipt.url.starts_with("https://github.com/") {
                return Err("反馈回执格式不符合约定".into());
            }
            Ok(receipt)
        }
        429 => Err("提交过于频繁，请稍后再试，或改用浏览器提交".into()),
        400 => Err("反馈内容未通过服务端校验，请检查必填项后重试".into()),
        503 => Err("反馈服务暂时不可用，可改用浏览器提交".into()),
        _ => Err("反馈未被接收，可改用浏览器提交".into()),
    }
}

fn serialize_payload(payload: &FeedbackPayload) -> Result<Vec<u8>, String> {
    serde_json::to_vec(payload).map_err(|_| "无法序列化反馈内容".to_string())
}

fn validate_payload(payload: &FeedbackPayload) -> Result<(), String> {
    if payload.schema_version != SCHEMA_VERSION {
        return Err("反馈协议版本不匹配，请更新软件后重试".into());
    }
    validate_title(&payload.title)?;
    if payload.body.trim().is_empty() {
        return Err("反馈正文为空".into());
    }
    if payload.body.chars().count() > MAX_BODY {
        return Err(format!("反馈正文超过 {MAX_BODY} 字"));
    }
    if payload.app_version.is_empty() || payload.app_version.chars().count() > 64 {
        return Err("软件版本号无效".into());
    }
    Ok(())
}

fn validate_title(title: &str) -> Result<(), String> {
    let title = title.trim();
    let length = title.chars().count();
    if length == 0 {
        return Err("请填写一句话标题".into());
    }
    if length > MAX_TITLE {
        return Err(format!("标题超过 {MAX_TITLE} 字"));
    }
    Ok(())
}

fn validate_field(label: &str, value: &str, required: bool) -> Result<(), String> {
    let length = value.chars().count();
    if required && value.trim().is_empty() {
        return Err(format!("请填写{label}"));
    }
    if length > MAX_FIELD {
        return Err(format!("{label}超过 {MAX_FIELD} 字"));
    }
    Ok(())
}

fn build_body(
    request: &FeedbackRequest,
    app_info: &crate::build_info::AppInfo,
    environment: Option<&str>,
    home: Option<&str>,
) -> Result<String, String> {
    validate_title(request.title.trim())?;
    validate_field("复现步骤 / 使用场景", &request.primary, true)?;
    validate_field("期望结果 / 期望方案", &request.expected, true)?;
    validate_field("实际结果 / 当前问题", &request.observed, true)?;
    validate_field("已尝试的替代方案", &request.alternatives, false)?;
    validate_field("补充信息", &request.extra, false)?;
    validate_field("日志或截图", &request.logs, false)?;
    match request.kind {
        FeedbackKind::Feature if request.impact.is_none() => {
            return Err("请选择影响程度".into());
        }
        FeedbackKind::Bug if !request.platforms.is_empty() => {
            return Err("Bug 反馈不接受相关平台选择".into());
        }
        _ => {}
    }

    let redact = |value: &str| redact_home_paths(value.trim(), home);
    let source = format!(
        "软件内反馈 · Shellsmith {}（构建 {}）· {} {}",
        app_info.version,
        app_info.build_date,
        platform_label(),
        std::env::consts::ARCH
    );

    let mut sections: Vec<String> = vec![
        "<!-- shellsmith-feedback:v1 -->".to_string(),
        "### 反馈来源".to_string(),
        String::new(),
        source,
    ];
    match request.kind {
        FeedbackKind::Bug => {
            sections.extend([
                String::new(),
                "### 问题模块".to_string(),
                String::new(),
                request.module.label().to_string(),
                String::new(),
                "### 复现步骤".to_string(),
                String::new(),
                redact(&request.primary),
                String::new(),
                "### 期望结果".to_string(),
                String::new(),
                redact(&request.expected),
                String::new(),
                "### 实际结果".to_string(),
                String::new(),
                redact(&request.observed),
            ]);
            if let Some(environment) = environment {
                sections.extend([
                    String::new(),
                    "### 环境与诊断".to_string(),
                    String::new(),
                    "```text".to_string(),
                    redact(environment),
                    "```".to_string(),
                ]);
            }
            if !request.logs.trim().is_empty() {
                sections.extend([
                    String::new(),
                    "### 日志或截图".to_string(),
                    String::new(),
                    redact(&request.logs),
                ]);
            }
        }
        FeedbackKind::Feature => {
            sections.extend([
                String::new(),
                "### 功能分类".to_string(),
                String::new(),
                request.module.label().to_string(),
                String::new(),
                "### 使用场景".to_string(),
                String::new(),
                redact(&request.primary),
                String::new(),
                "### 当前问题".to_string(),
                String::new(),
                redact(&request.observed),
                String::new(),
                "### 期望方案".to_string(),
                String::new(),
                redact(&request.expected),
            ]);
            if let Some(impact) = request.impact {
                sections.extend([
                    String::new(),
                    "### 影响程度".to_string(),
                    String::new(),
                    impact.label().to_string(),
                ]);
            }
            if !request.platforms.is_empty() {
                sections.extend([
                    String::new(),
                    "### 相关平台".to_string(),
                    String::new(),
                    request
                        .platforms
                        .iter()
                        .map(|platform| format!("- {}", platform.label()))
                        .collect::<Vec<_>>()
                        .join("\n"),
                ]);
            }
            for (title, value) in [
                ("已尝试的替代方案", &request.alternatives),
                ("补充信息", &request.extra),
            ] {
                if !value.trim().is_empty() {
                    sections.extend([
                        String::new(),
                        format!("### {title}"),
                        String::new(),
                        redact(value),
                    ]);
                }
            }
        }
    }
    sections.extend([
        String::new(),
        "---".to_string(),
        "<sub>由 Shellsmith 软件内反馈提交</sub>".to_string(),
    ]);

    let body = sections.join("\n");
    if body.chars().count() > MAX_BODY {
        return Err(format!("反馈正文超过 {MAX_BODY} 字，请精简后重试"));
    }
    Ok(body)
}

/// 预填 GitHub 新建 issue 页面；正文过长时截断并标注，界面会提示用户补全。
fn fallback_url(
    issue_title: &str,
    kind: &FeedbackKind,
    body: &str,
) -> Result<(String, bool), String> {
    let mut url = reqwest::Url::parse(ISSUE_NEW_URL).map_err(|_| "无法生成反馈链接".to_string())?;
    let mut truncated = false;
    let fallback_body = if body.chars().count() > MAX_FALLBACK_BODY {
        truncated = true;
        let head: String = body.chars().take(MAX_FALLBACK_BODY).collect();
        format!("{head}\n\n（正文过长，已截断；请把软件中预览的剩余内容补充到此处。）")
    } else {
        body.to_string()
    };
    let labels = match kind {
        FeedbackKind::Bug => "bug",
        FeedbackKind::Feature => "enhancement",
    };
    url.query_pairs_mut()
        .append_pair("title", issue_title)
        .append_pair("body", &fallback_body)
        .append_pair("labels", labels);
    Ok((url.into(), truncated))
}

fn platform_label() -> &'static str {
    match std::env::consts::OS {
        "macos" => "macOS",
        "windows" => "Windows",
        "linux" => "Linux",
        other => other,
    }
}

fn home_directory() -> Option<String> {
    #[cfg(windows)]
    let key = "USERPROFILE";
    #[cfg(not(windows))]
    let key = "HOME";
    std::env::var(key)
        .ok()
        .map(|value| value.trim().trim_end_matches(['/', '\\']).to_string())
        .filter(|value| value.chars().count() > 1)
}

/// 用户在反馈里粘贴路径很常见，提交前把本机主目录替换为 `~`。
pub(crate) fn redact_home_paths(text: &str, home: Option<&str>) -> String {
    let Some(home) = home.filter(|value| !value.is_empty()) else {
        return text.to_string();
    };
    let mut result = text.replace(home, "~");
    // Windows 下同一目录可能以 / 或 \ 出现，统一再替换一次斜杠变体。
    let alternate = home.replace('\\', "/");
    if alternate != home {
        result = result.replace(&alternate, "~");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_info::AppInfo;

    fn app_info() -> AppInfo {
        AppInfo {
            version: "1.6.0".into(),
            git_hash: "abc1234".into(),
            build_date: "2026-10-09".into(),
        }
    }

    fn bug_request() -> FeedbackRequest {
        FeedbackRequest {
            kind: FeedbackKind::Bug,
            module: FeedbackModule::Ios,
            title: "导出 IPA 缺少描述文件".into(),
            primary: "1. 打开 iOS 加固 2. 选择 app-store-connect 3. 开始".into(),
            expected: "导出成功".into(),
            observed: "提示 No profiles were found".into(),
            impact: None,
            platforms: vec![],
            alternatives: String::new(),
            extra: String::new(),
            logs: String::new(),
            include_environment: true,
        }
    }

    fn feature_request() -> FeedbackRequest {
        FeedbackRequest {
            kind: FeedbackKind::Feature,
            module: FeedbackModule::Gui,
            title: "希望支持批量加固".into(),
            primary: "在 CI 中一次处理多个 APK".into(),
            expected: "给出非交互的批量入口".into(),
            observed: "目前只能逐个选择".into(),
            impact: Some(FeedbackImpact::Slower),
            platforms: vec![FeedbackPlatform::Macos, FeedbackPlatform::AndroidRuntime],
            alternatives: "手写脚本".into(),
            extra: String::new(),
            logs: String::new(),
            include_environment: false,
        }
    }

    #[test]
    fn bug_反馈生成模板要求的章节与隐藏标记() {
        let body = build_body(&bug_request(), &app_info(), Some("版本: 1.6.0"), None).unwrap();
        assert!(body.starts_with("<!-- shellsmith-feedback:v1 -->"));
        assert!(body.contains("### 反馈来源"));
        assert!(body.contains("Shellsmith 1.6.0（构建 2026-10-09）"));
        assert!(body.contains("### 问题模块"));
        assert!(body.contains("加固（iOS）"));
        assert!(body.contains("### 复现步骤"));
        assert!(body.contains("### 期望结果"));
        assert!(body.contains("### 实际结果"));
        assert!(body.contains("### 环境与诊断"));
        assert!(body.contains("```text\n版本: 1.6.0\n```"));
        assert!(body.contains("由 Shellsmith 软件内反馈提交"));
        assert!(!body.contains("### 影响程度"));
    }

    #[test]
    fn bug_反馈不带环境信息时省略诊断章节() {
        let mut request = bug_request();
        request.include_environment = false;
        let body = build_body(&request, &app_info(), None, None).unwrap();
        assert!(!body.contains("### 环境与诊断"));
    }

    #[test]
    fn feature_反馈生成需求表单要求的章节() {
        let body = build_body(&feature_request(), &app_info(), None, None).unwrap();
        assert!(body.contains("### 功能分类"));
        assert!(body.contains("### 使用场景"));
        assert!(body.contains("### 当前问题"));
        assert!(body.contains("### 期望方案"));
        assert!(body.contains("### 影响程度"));
        assert!(body.contains("明显影响效率"));
        assert!(body.contains("### 相关平台"));
        assert!(body.contains("- macOS"));
        assert!(body.contains("- Android 运行期"));
        assert!(body.contains("### 已尝试的替代方案"));
        assert!(!body.contains("### 复现步骤"));
    }

    #[test]
    fn 必填项为空或超长时拒绝生成正文() {
        let mut empty = bug_request();
        empty.primary = "   ".into();
        assert!(build_body(&empty, &app_info(), None, None).is_err());

        let mut long = bug_request();
        long.observed = "字".repeat(MAX_FIELD + 1);
        assert!(build_body(&long, &app_info(), None, None).is_err());
    }

    #[test]
    fn 需求类型必须选择影响程度而_bug_不接受平台选择() {
        let mut missing_impact = feature_request();
        missing_impact.impact = None;
        assert!(build_body(&missing_impact, &app_info(), None, None).is_err());

        let mut bug_with_platforms = bug_request();
        bug_with_platforms.platforms = vec![FeedbackPlatform::Linux];
        assert!(build_body(&bug_with_platforms, &app_info(), None, None).is_err());
    }

    #[test]
    fn 主目录替换同时覆盖反斜杠与正斜杠写法() {
        let redacted = redact_home_paths(
            "见 /Users/rocky/a 与 C:/Users/rocky/b",
            Some("C:\\Users\\rocky"),
        );
        assert_eq!(redacted, "见 /Users/rocky/a 与 ~/b");
    }

    #[test]
    fn 主目录在完整正文中被替换() {
        let mut request = bug_request();
        request.observed = "崩溃在 /Users/rocky/Desktop/Mova/app.apk".into();
        let body = build_body(&request, &app_info(), None, Some("/Users/rocky")).unwrap();
        assert!(body.contains("~/Desktop/Mova/app.apk"));
        assert!(!body.contains("/Users/rocky"));
    }

    #[test]
    fn 没有主目录信息时原样保留文本() {
        assert_eq!(redact_home_paths("/tmp/a.apk", None), "/tmp/a.apk");
        assert_eq!(redact_home_paths("/tmp/a.apk", Some("")), "/tmp/a.apk");
    }

    #[test]
    fn 标题校验拒绝空值与超长() {
        assert!(validate_title("  ").is_err());
        assert!(validate_title(&"字".repeat(MAX_TITLE + 1)).is_err());
        assert!(validate_title("正常标题").is_ok());
    }

    #[test]
    fn 正文超过上限时拒绝() {
        let mut request = bug_request();
        request.logs = "日".repeat(MAX_BODY);
        assert!(build_body(&request, &app_info(), None, None).is_err());
    }

    #[test]
    fn 预填链接带标题标签且正文未截断时保持一致() {
        let (url, truncated) = fallback_url("[Bug] 标题", &FeedbackKind::Bug, "正文内容").unwrap();
        assert!(!truncated);
        let parsed = reqwest::Url::parse(&url).unwrap();
        let pairs: std::collections::HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        assert_eq!(pairs.get("title").map(String::as_str), Some("[Bug] 标题"));
        assert_eq!(pairs.get("body").map(String::as_str), Some("正文内容"));
        assert_eq!(pairs.get("labels").map(String::as_str), Some("bug"));
    }

    #[test]
    fn 预填链接过长时截断并标注() {
        let body = "正".repeat(MAX_FALLBACK_BODY + 10);
        let (url, truncated) =
            fallback_url("[功能建议] 标题", &FeedbackKind::Feature, &body).expect("应生成链接");
        assert!(truncated);
        let parsed = reqwest::Url::parse(&url).unwrap();
        let pairs: std::collections::HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        let carried = pairs.get("body").expect("应携带正文");
        assert!(carried.contains("已截断"));
        // 截断后保留原文开头，其余部分由用户在浏览器中补全。
        let head: String = body.chars().take(MAX_FALLBACK_BODY).collect();
        assert!(carried.starts_with(&head));
        assert_eq!(pairs.get("labels").map(String::as_str), Some("enhancement"));
    }

    #[test]
    fn 提交前校验拒绝空正文与错误协议版本() {
        let mut payload = FeedbackPayload {
            schema_version: SCHEMA_VERSION,
            kind: FeedbackKind::Bug,
            title: "标题".into(),
            body: String::new(),
            app_version: "1.6.0".into(),
        };
        assert!(validate_payload(&payload).is_err());
        payload.body = "正文".into();
        assert!(validate_payload(&payload).is_ok());
        payload.schema_version = 2;
        assert!(validate_payload(&payload).is_err());
    }

    #[test]
    fn 回执必须指向本仓库的_https_地址() {
        let good: FeedbackReceipt = serde_json::from_str(
            r#"{"number":12,"url":"https://github.com/kairowan/Shellsmith/issues/12"}"#,
        )
        .unwrap();
        assert_eq!(good.number, 12);
        assert!(good.url.starts_with("https://github.com/"));
        assert!(serde_json::from_str::<FeedbackReceipt>(r#"{"number":12}"#).is_err());
    }

    #[test]
    fn 序列化后的字节数是提交上限的依据() {
        // 中日韩字符按字节算远大于按字符算，客户端必须按字节拦截，
        // 否则统计服务会以 400 拒绝，用户只能看到一句笼统的校验失败。
        let mut payload = FeedbackPayload {
            schema_version: SCHEMA_VERSION,
            kind: FeedbackKind::Bug,
            title: "标题".into(),
            body: "问".repeat(MAX_PAYLOAD_BYTES / 3 + 1),
            app_version: "1.6.0".into(),
        };
        let bytes = serialize_payload(&payload).expect("应能序列化");
        assert!(bytes.len() > MAX_PAYLOAD_BYTES);

        payload.body = "短正文".into();
        let bytes = serialize_payload(&payload).expect("应能序列化");
        assert!(bytes.len() <= MAX_PAYLOAD_BYTES);
    }
}
