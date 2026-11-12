use crate::jobs::{CommandPlan, JobPlan, Server};
use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Clone, Debug, serde::Serialize)]
struct TextContent {
    #[serde(rename = "type")]
    kind: &'static str,
    text: String,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ToolResult {
    content: Vec<TextContent>,
    #[serde(rename = "structuredContent", skip_serializing_if = "Option::is_none")]
    structured: Option<Value>,
    #[serde(rename = "isError")]
    is_error: bool,
}

impl ToolResult {
    fn ok(value: Value) -> Self {
        let structured = value.is_object().then(|| value.clone());
        Self {
            content: vec![TextContent {
                kind: "text",
                text: serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string()),
            }],
            structured,
            is_error: false,
        }
    }

    fn error(message: impl Into<String>) -> Self {
        Self {
            content: vec![TextContent {
                kind: "text",
                text: message.into(),
            }],
            structured: None,
            is_error: true,
        }
    }
}

pub fn tool_definitions() -> Vec<Value> {
    vec![
        tool(
            "shellsmith_version",
            "Return the installed Shellsmith CLI version and MCP bridge version.",
            object(json!({}), &[]),
            read_only(),
        ),
        tool(
            "shellsmith_check_apk",
            "Inspect an APK: protection marker, signature state, certificate fingerprint and native ABIs.",
            object(json!({"path": string("APK path")}), &["path"]),
            read_only(),
        ),
        tool(
            "shellsmith_check_aab",
            "Inspect an AAB module structure, optionally validate/build APKS with bundletool.",
            object(
                json!({
                    "path": string("AAB path"),
                    "bundletool": string("Optional bundletool JAR"),
                    "apks_output": string("Optional APKS output path"),
                    "device_spec": string("Optional bundletool device spec JSON"),
                    "apks_mode": string("universal or default"),
                    "keystore": string("Optional keystore for APKS signing"),
                    "key_alias": string("Optional key alias"),
                    "password_env": string("Environment variable containing keystore password (default MOCIKA_SHIELD_KS_PASS)")
                }),
                &["path"],
            ),
            write_operation(),
        ),
        tool(
            "shellsmith_check_ios",
            "Inspect an Xcode project, scheme and signing configuration without modifying it.",
            object(json!({"project": string("Xcode project/workspace path"), "scheme": string("Optional scheme")}), &["project"]),
            read_only(),
        ),
        tool(
            "shellsmith_check_keystore",
            "Read the SHA-256 certificate fingerprint for a keystore alias.",
            object(json!({"keystore": string("Keystore path"), "key_alias": string("Key alias"), "password_env": string("Environment variable containing keystore password (default MOCIKA_SHIELD_KS_PASS)")}), &["keystore", "key_alias"]),
            read_only(),
        ),
        tool(
            "shellsmith_protect_apk",
            "Protect an APK. Optionally sign it with a keystore in the same job; signing passwords are read from environment variables, never tool arguments.",
            object(
                json!({
                    "input": string("Input APK"),
                    "output": string("Final output APK"),
                    "profile": string("compat, balanced or strict"),
                    "ai_resistance": string("off, balanced or high"),
                    "environment_policy": string("compatible or strict"),
                    "runtime_cert_sha256": string("Optional expected runtime certificate SHA-256"),
                    "exclude_abis": array("ABIs to exclude"),
                    "apktool": string("Optional apktool JAR"),
                    "resources": string("Optional runtime resource ZIP"),
                    "apksigner": string("Optional apksigner JAR"),
                    "xop_pvm2_packer": string("Optional XOP PVM2 transform-only packer JAR"),
                    "xop_true_vmp_prefixes": array("DEX type prefixes for PVM2"),
                    "pvm2_required_methods": string("Optional required methods TSV"),
                    "native_vmp_evidence": string("Optional native VMP evidence TSV"),
                    "protect_route_assets": boolean("Encrypt router index assets"),
                    "byos_endpoint": string("Optional BYOS endpoint"),
                    "byos_auth": string("device_approval or play_integrity"),
                    "byos_api_key_env": string("Environment variable containing BYOS API key"),
                    "runtime_ui": runtime_ui_schema(),
                    "sign": sign_options_schema(),
                    "allow_in_place": boolean("Allow output to equal input"),
                    "confirm": boolean("Set to true to confirm this destructive operation")
                }),
                &["input", "output", "confirm"],
            ),
            destructive(),
        ),
        tool(
            "shellsmith_protect_aab",
            "Protect an AAB and rebuild/sign the final bundle. Supports Mocika or XOP engines and APKS validation.",
            object(aab_schema(), &["input", "output", "bundletool", "aapt2", "keystore", "key_alias", "confirm"]),
            destructive(),
        ),
        tool(
            "shellsmith_protect_xop",
            "Protect an APK with the XOP single-shell packer, optionally signing the result.",
            object(xop_schema(), &["input", "output", "packer", "shell_dir", "confirm"]),
            destructive(),
        ),
        tool(
            "shellsmith_protect_ios",
            "Integrate iOS runtime protection in a work copy, archive/export/sign the IPA.",
            object(
                json!({
                    "ios_config": string("Shellsmith iOS TOML config"),
                    "output": string("Output directory"),
                    "freerasp_zip": string("Optional freeRASP source ZIP"),
                    "ios_cache_dir": string("Optional iOS SDK cache directory"),
                    "export_options": string("Optional Xcode ExportOptions.plist"),
                    "export_method": string("Xcode export method"),
                    "allow_provisioning_updates": boolean("Allow Xcode to update provisioning profiles"),
                    "dry_run": boolean("Only inspect, do not copy or modify the project"),
                    "confirm": boolean("Required unless dry_run is true")
                }),
                &["ios_config", "output"],
            ),
            destructive(),
        ),
        tool(
            "shellsmith_sign_apk",
            "Sign an APK with APK Signature Scheme v1/v2/v3/v4. Uses password environment variables, not plaintext arguments.",
            object(sign_schema(), &["input", "keystore", "key_alias", "confirm"]),
            destructive(),
        ),
        tool(
            "shellsmith_install_apks",
            "Install a generated APKS with bundletool to a connected test device.",
            object(json!({"apks": string("APKS path"), "bundletool": string("bundletool JAR"), "device_id": string("Optional adb device id"), "confirm": boolean("Set to true to confirm this destructive operation")}), &["apks", "bundletool", "confirm"]),
            destructive(),
        ),
        tool(
            "shellsmith_read_report",
            "Read a Shellsmith protection report (summary or full JSON).",
            object(json!({"path": string("Protection report path"), "mode": string("summary or full")}), &["path"]),
            read_only(),
        ),
        tool(
            "shellsmith_job_status",
            "Return status, progress, recent logs and result of an asynchronous job.",
            object(json!({"job_id": string("Job id")}), &["job_id"]),
            read_only(),
        ),
        tool(
            "shellsmith_job_result",
            "Return the terminal result of an asynchronous job, or an error if it is still running.",
            object(json!({"job_id": string("Job id")}), &["job_id"]),
            read_only(),
        ),
        tool(
            "shellsmith_job_cancel",
            "Request cancellation of an asynchronous job and terminate its CLI subprocess.",
            object(json!({"job_id": string("Job id")}), &["job_id"]),
            destructive(),
        ),
        tool(
            "shellsmith_job_list",
            "List all jobs known to this MCP server process.",
            object(json!({}), &[]),
            read_only(),
        ),
    ]
}

fn tool(name: &str, description: &str, input_schema: Value, annotations: Value) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": input_schema,
        "annotations": annotations,
    })
}

fn object(properties: Value, required: &[&str]) -> Value {
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": false,
    })
}

fn string(description: &str) -> Value {
    json!({"type": "string", "description": description})
}
fn boolean(description: &str) -> Value {
    json!({"type": "boolean", "description": description})
}
fn integer(description: &str) -> Value {
    json!({"type": "integer", "description": description})
}
fn array(description: &str) -> Value {
    json!({"type": "array", "items": {"type": "string"}, "description": description})
}
fn read_only() -> Value {
    json!({"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false})
}

fn write_operation() -> Value {
    json!({"readOnlyHint": false, "destructiveHint": false, "idempotentHint": false, "openWorldHint": false})
}
fn destructive() -> Value {
    json!({"readOnlyHint": false, "destructiveHint": true, "idempotentHint": false, "openWorldHint": false})
}

fn runtime_ui_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "secure_screen": boolean("Prevent screenshots of protected windows"),
            "screen_exempt_activities": array("Activities exempt from screenshot protection"),
            "adb_policy": string("off, report or block"),
            "runtime_recheck": boolean("Recheck anti-debug/Root while in foreground"),
            "obfuscate_resource_names": boolean("Obfuscate safe resource names"),
            "resource_name_keep": array("Resource names to keep"),
            "ui_packer": string("Optional UI/resource transformer JAR")
        },
        "additionalProperties": false
    })
}

fn sign_options_properties() -> serde_json::Map<String, Value> {
    match json!({
        "keystore": string("Keystore path"),
        "key_alias": string("Key alias"),
        "keystore_type": string("JKS or PKCS12"),
        "v1": boolean("Enable v1 signing"),
        "v2": boolean("Enable v2 signing"),
        "v3": boolean("Enable v3 signing"),
        "v4": boolean("Enable v4 signing"),
        "apksigner": string("Optional apksigner JAR"),
        "password_env": string("Environment variable containing keystore password"),
        "key_password_env": string("Environment variable containing key password")
    }) {
        Value::Object(map) => map,
        _ => unreachable!("sign options schema must be an object"),
    }
}

fn sign_options_schema() -> Value {
    json!({
        "type": "object",
        "properties": sign_options_properties(),
        "additionalProperties": false
    })
}

fn sign_schema() -> Value {
    let mut properties = sign_options_properties();
    properties.insert("input".into(), string("APK to sign"));
    properties.insert(
        "output".into(),
        string("Optional signed output; omit only when allow_in_place is true"),
    );
    properties.insert(
        "allow_in_place".into(),
        boolean("Allow output to equal input"),
    );
    properties.insert(
        "confirm".into(),
        boolean("Set to true to confirm this destructive operation"),
    );
    json!({
        "type": "object",
        "properties": properties,
        "additionalProperties": false
    })
}

fn aab_schema() -> Value {
    json!({
        "input": string("Input AAB"),
        "output": string("Final output AAB"),
        "bundletool": string("bundletool JAR"),
        "aapt2": string("aapt2 executable"),
        "keystore": string("Upload keystore"),
        "key_alias": string("Key alias"),
        "password_env": string("Environment variable containing keystore password"),
        "key_password_env": string("Environment variable containing key password"),
        "keystore_type": string("JKS or PKCS12"),
        "apktool": string("Optional apktool JAR"),
        "resources": string("Optional runtime resource ZIP"),
        "apksigner": string("Optional apksigner JAR"),
        "profile": string("compat, balanced or strict"),
        "ai_resistance": string("off, balanced or high"),
        "environment_policy": string("compatible or strict"),
        "runtime_cert_sha256": string("Expected runtime certificate SHA-256"),
        "allow_upload_cert_binding": boolean("Allow runtime binding to upload key"),
        "play_delivery_adapter": boolean("Declare Play delivery adapter integration"),
        "engine": string("mocika or xop"),
        "xop_packer": string("XOP packer for engine=xop"),
        "xop_shell_dir": string("XOP shell-files directory for engine=xop"),
        "xop_profile": string("balanced, industry, aggressive, perf or max"),
        "xop_no_protect_so": boolean("Do not protect SO in XOP engine"),
        "xop_encrypt_assets": boolean("Encrypt assets in XOP engine"),
        "xop_enable_res_protect": boolean("Enable resource protection in XOP engine"),
        "xop_detect_proxy": boolean("Enable proxy detection in XOP engine"),
        "xop_rasp_action": integer("0=alert, 1=degrade, 2=block"),
        "xop_pvm2_packer": string("Optional XOP PVM2 transform-only packer"),
        "xop_true_vmp_prefixes": array("DEX type prefixes for PVM2"),
        "pvm2_required_methods": string("Optional required methods TSV"),
        "native_vmp_evidence": string("Optional native VMP evidence TSV"),
        "protect_route_assets": boolean("Encrypt router index assets"),
        "exclude_abis": array("ABIs to exclude"),
        "apks_output": string("Optional APKS output"),
        "install_apks": boolean("Install generated APKS"),
        "device_spec": string("Optional bundletool device spec"),
        "device_id": string("Optional adb device id"),
        "smoke_package": string("Optional package for post-install smoke test"),
        "runtime_ui": runtime_ui_schema(),
        "confirm": boolean("Set to true to confirm this destructive operation")
    })
}

fn xop_schema() -> Value {
    json!({
        "input": string("Input APK"),
        "output": string("Output APK"),
        "packer": string("XOP packer JAR"),
        "shell_dir": string("XOP shell-files directory"),
        "keystore": string("Optional signing keystore"),
        "key_alias": string("Optional key alias"),
        "password_env": string("Environment variable containing keystore password"),
        "key_password_env": string("Environment variable containing key password"),
        "keystore_type": string("JKS or PKCS12"),
        "apksigner": string("Optional apksigner JAR"),
        "allow_unsigned": boolean("Allow unsigned intermediate APK"),
        "profile": string("balanced, industry, aggressive, perf or max"),
        "ai_resistance": string("off, balanced or high"),
        "hollow_prefixes": array("Hollow method prefixes"),
        "vmp_prefixes": array("VMP method prefixes"),
        "true_vmp_prefixes": array("True VMP method prefixes"),
        "no_protect_so": boolean("Do not protect SO"),
        "encrypt_assets": boolean("Encrypt assets"),
        "enable_res_protect": boolean("Enable resource protection"),
        "detect_proxy": boolean("Enable proxy detection"),
        "rasp_action": integer("0=alert, 1=degrade, 2=block"),
        "confirm": boolean("Set to true to confirm this destructive operation")
    })
}

#[derive(Debug, Deserialize, Default)]
struct RuntimeUiInput {
    secure_screen: Option<bool>,
    screen_exempt_activities: Option<Vec<String>>,
    adb_policy: Option<String>,
    runtime_recheck: Option<bool>,
    obfuscate_resource_names: Option<bool>,
    resource_name_keep: Option<Vec<String>>,
    ui_packer: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct SignInput {
    input: Option<String>,
    output: Option<String>,
    keystore: Option<String>,
    key_alias: Option<String>,
    keystore_type: Option<String>,
    v1: Option<bool>,
    v2: Option<bool>,
    v3: Option<bool>,
    v4: Option<bool>,
    apksigner: Option<String>,
    password_env: Option<String>,
    key_password_env: Option<String>,
    allow_in_place: Option<bool>,
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Deserialize)]
struct ProtectApkInput {
    input: String,
    output: String,
    profile: Option<String>,
    ai_resistance: Option<String>,
    environment_policy: Option<String>,
    runtime_cert_sha256: Option<String>,
    #[serde(default)]
    exclude_abis: Vec<String>,
    apktool: Option<String>,
    resources: Option<String>,
    apksigner: Option<String>,
    xop_pvm2_packer: Option<String>,
    #[serde(default)]
    xop_true_vmp_prefixes: Vec<String>,
    pvm2_required_methods: Option<String>,
    native_vmp_evidence: Option<String>,
    #[serde(default)]
    protect_route_assets: bool,
    byos_endpoint: Option<String>,
    byos_auth: Option<String>,
    byos_api_key_env: Option<String>,
    runtime_ui: Option<RuntimeUiInput>,
    sign: Option<SignInput>,
    #[serde(default)]
    allow_in_place: bool,
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Deserialize)]
struct ProtectAabInput {
    input: String,
    output: String,
    bundletool: String,
    aapt2: String,
    keystore: String,
    key_alias: String,
    password_env: Option<String>,
    key_password_env: Option<String>,
    keystore_type: Option<String>,
    apktool: Option<String>,
    resources: Option<String>,
    apksigner: Option<String>,
    profile: Option<String>,
    ai_resistance: Option<String>,
    environment_policy: Option<String>,
    runtime_cert_sha256: Option<String>,
    #[serde(default)]
    allow_upload_cert_binding: bool,
    #[serde(default)]
    play_delivery_adapter: bool,
    engine: Option<String>,
    xop_packer: Option<String>,
    xop_shell_dir: Option<String>,
    xop_profile: Option<String>,
    #[serde(default)]
    xop_no_protect_so: bool,
    #[serde(default)]
    xop_encrypt_assets: bool,
    #[serde(default)]
    xop_enable_res_protect: bool,
    #[serde(default)]
    xop_detect_proxy: bool,
    xop_rasp_action: Option<u8>,
    xop_pvm2_packer: Option<String>,
    #[serde(default)]
    xop_true_vmp_prefixes: Vec<String>,
    pvm2_required_methods: Option<String>,
    native_vmp_evidence: Option<String>,
    #[serde(default)]
    protect_route_assets: bool,
    #[serde(default)]
    exclude_abis: Vec<String>,
    apks_output: Option<String>,
    #[serde(default)]
    install_apks: bool,
    device_spec: Option<String>,
    device_id: Option<String>,
    smoke_package: Option<String>,
    runtime_ui: Option<RuntimeUiInput>,
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Deserialize)]
struct ProtectXopInput {
    input: String,
    output: String,
    packer: String,
    shell_dir: String,
    keystore: Option<String>,
    key_alias: Option<String>,
    password_env: Option<String>,
    key_password_env: Option<String>,
    keystore_type: Option<String>,
    apksigner: Option<String>,
    #[serde(default)]
    allow_unsigned: bool,
    profile: Option<String>,
    ai_resistance: Option<String>,
    #[serde(default)]
    hollow_prefixes: Vec<String>,
    #[serde(default)]
    vmp_prefixes: Vec<String>,
    #[serde(default)]
    true_vmp_prefixes: Vec<String>,
    #[serde(default)]
    no_protect_so: bool,
    #[serde(default)]
    encrypt_assets: bool,
    #[serde(default)]
    enable_res_protect: bool,
    #[serde(default)]
    detect_proxy: bool,
    rasp_action: Option<u8>,
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Deserialize)]
struct ProtectIosInput {
    ios_config: String,
    output: String,
    freerasp_zip: Option<String>,
    ios_cache_dir: Option<String>,
    export_options: Option<String>,
    export_method: Option<String>,
    #[serde(default)]
    allow_provisioning_updates: bool,
    #[serde(default)]
    dry_run: bool,
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Deserialize)]
struct CheckAabInput {
    path: String,
    bundletool: Option<String>,
    apks_output: Option<String>,
    device_spec: Option<String>,
    apks_mode: Option<String>,
    keystore: Option<String>,
    key_alias: Option<String>,
    password_env: Option<String>,
}

pub fn call(
    server: &Arc<Server>,
    name: &str,
    args: Value,
    progress_token: Option<Value>,
) -> ToolResult {
    match dispatch(server, name, args, progress_token) {
        Ok(result) => result,
        Err(error) => ToolResult::error(format!("{error:#}")),
    }
}

fn dispatch(
    server: &Arc<Server>,
    name: &str,
    args: Value,
    progress_token: Option<Value>,
) -> Result<ToolResult> {
    match name {
        "shellsmith_version" => {
            let output = server.run_sync(&["--version".to_string()], &[])?;
            Ok(ToolResult::ok(json!({
                "cli": server.cli,
                "cli_version": output,
                "mcp_version": env!("CARGO_PKG_VERSION"),
            })))
        }
        "shellsmith_check_apk" => {
            let input: CheckPathInput = parse(args)?;
            let path = server.resolve_input(&input.path, "APK")?;
            let value =
                server.run_sync(&["check-apk".to_string(), path.display().to_string()], &[])?;
            Ok(ToolResult::ok(value))
        }
        "shellsmith_check_aab" => check_aab(server, args),
        "shellsmith_check_ios" => {
            let input: CheckIosInput = parse(args)?;
            let project = server.resolve_input(&input.project, "Xcode 工程")?;
            let mut cli_args = vec!["check-ios".to_string(), project.display().to_string()];
            if let Some(scheme) = input.scheme {
                cli_args.push("--scheme".into());
                cli_args.push(scheme);
            }
            Ok(ToolResult::ok(server.run_sync(&cli_args, &[])?))
        }
        "shellsmith_check_keystore" => check_keystore(server, args),
        "shellsmith_protect_apk" => protect_apk(server, args, progress_token),
        "shellsmith_protect_aab" => protect_aab(server, args, progress_token),
        "shellsmith_protect_xop" => protect_xop(server, args, progress_token),
        "shellsmith_protect_ios" => protect_ios(server, args, progress_token),
        "shellsmith_sign_apk" => sign_apk(server, args, progress_token),
        "shellsmith_install_apks" => install_apks(server, args, progress_token),
        "shellsmith_read_report" => read_report(server, args),
        "shellsmith_job_status" => job_status(server, args),
        "shellsmith_job_result" => job_result(server, args),
        "shellsmith_job_cancel" => job_cancel(server, args),
        "shellsmith_job_list" => Ok(ToolResult::ok(json!({"jobs": server.job_list()}))),
        _ => anyhow::bail!("未知工具: {name}"),
    }
}

#[derive(Debug, Deserialize)]
struct CheckPathInput {
    path: String,
}
#[derive(Debug, Deserialize)]
struct CheckIosInput {
    project: String,
    scheme: Option<String>,
}
#[derive(Debug, Deserialize)]
struct KeystoreInput {
    keystore: String,
    key_alias: String,
    password_env: Option<String>,
}
#[derive(Debug, Deserialize)]
struct JobInput {
    job_id: String,
}
#[derive(Debug, Deserialize)]
struct ReportInput {
    path: String,
    mode: Option<String>,
}
#[derive(Debug, Deserialize)]
struct InstallApksInput {
    apks: String,
    bundletool: String,
    device_id: Option<String>,
    #[serde(default)]
    confirm: bool,
}

fn parse<T: for<'de> Deserialize<'de>>(args: Value) -> Result<T> {
    serde_json::from_value(args).context("工具参数无效")
}

fn require_confirm(confirm: bool) -> Result<()> {
    if !confirm {
        anyhow::bail!("这是破坏性操作；请先向用户确认，并在参数中设置 confirm=true 后重试");
    }
    Ok(())
}

fn check_aab(server: &Arc<Server>, args: Value) -> Result<ToolResult> {
    let input: CheckAabInput = parse(args)?;
    if input.apks_output.is_some() && input.bundletool.is_none() {
        anyhow::bail!("apks_output 必须与 bundletool 一起使用");
    }
    if input.keystore.is_some() && input.apks_output.is_none() {
        anyhow::bail!("提供 keystore 时必须同时提供 apks_output");
    }
    let path = server.resolve_input(&input.path, "AAB")?;
    let mut cli_args = vec!["check-aab".to_string(), path.display().to_string()];
    if let Some(value) = input.bundletool {
        cli_args.push("--bundletool".into());
        cli_args.push(
            server
                .resolve_input(&value, "bundletool")?
                .display()
                .to_string(),
        );
    }
    if let Some(value) = input.apks_output {
        cli_args.push("--apks-output".into());
        cli_args.push(
            server
                .resolve_output(&value, "APKS 输出")?
                .display()
                .to_string(),
        );
    }
    if let Some(value) = input.device_spec {
        cli_args.push("--device-spec".into());
        cli_args.push(
            server
                .resolve_input(&value, "设备规格")?
                .display()
                .to_string(),
        );
    }
    if let Some(value) = input.apks_mode {
        cli_args.push("--apks-mode".into());
        cli_args.push(value);
    }
    let keystore = input
        .keystore
        .as_deref()
        .map(|value| server.resolve_input(value, "keystore"))
        .transpose()?;
    let env = keystore_env(
        input.password_env.as_deref(),
        keystore.as_deref(),
        input.key_alias.as_deref(),
        &mut cli_args,
    )?;
    Ok(ToolResult::ok(server.run_sync(&cli_args, &env)?))
}

fn check_keystore(server: &Arc<Server>, args: Value) -> Result<ToolResult> {
    let input: KeystoreInput = parse(args)?;
    let keystore = server.resolve_input(&input.keystore, "keystore")?;
    let env_name = input
        .password_env
        .unwrap_or_else(|| "MOCIKA_SHIELD_KS_PASS".to_string());
    let password =
        std::env::var(&env_name).with_context(|| format!("缺少密码环境变量 {env_name}"))?;
    let cli_args = vec![
        "check-keystore".to_string(),
        "--ks".into(),
        keystore.display().to_string(),
        "--alias".into(),
        input.key_alias,
    ];
    let env = vec![("MOCIKA_SHIELD_KS_PASS".to_string(), password)];
    Ok(ToolResult::ok(server.run_sync(&cli_args, &env)?))
}

fn protect_apk(
    server: &Arc<Server>,
    args: Value,
    progress_token: Option<Value>,
) -> Result<ToolResult> {
    let input: ProtectApkInput = parse(args)?;
    require_confirm(input.confirm)?;
    let source = server.resolve_input(&input.input, "输入 APK")?;
    let final_output = server.resolve_output(&input.output, "输出 APK")?;
    if source == final_output {
        if !input.allow_in_place {
            anyhow::bail!("输出不能等于输入；如确需原地重签，请显式设置 allow_in_place=true");
        }
        if input.sign.is_none() {
            anyhow::bail!("原地加固必须同时提供 sign 配置：先加固到临时文件，再签名覆盖原文件");
        }
    }
    let runtime_cert_sha256 = if let Some(sign) = input.sign.as_ref() {
        Some(ensure_sign_certificate_binding(
            server,
            &source,
            sign,
            input.runtime_cert_sha256.as_deref(),
        )?)
    } else {
        input.runtime_cert_sha256.clone()
    };
    let parent = final_output.parent().unwrap_or(Path::new("."));
    let mut keep = Vec::new();
    let stage = tempfile::Builder::new()
        .prefix("shellsmith-mcp-stage-")
        .tempdir_in(parent)
        .context("创建 MCP 任务暂存目录失败")?;
    let stage_root = stage.path().to_path_buf();
    keep.push(stage);
    let stage_env = vec![(
        "SHELLSMITH_STAGE_ROOT".to_string(),
        stage_root.display().to_string(),
    )];
    let (protect_output, sign_output) = if input.sign.is_some() {
        (stage_root.join("unsigned.apk"), Some(final_output.clone()))
    } else {
        (final_output.clone(), None)
    };

    let mut protect_args = vec![
        "protect".to_string(),
        "-i".into(),
        source.display().to_string(),
        "-o".into(),
        protect_output.display().to_string(),
        "--json".into(),
    ];
    push_opt(&mut protect_args, "--profile", input.profile.as_deref());
    push_opt(
        &mut protect_args,
        "--ai-resistance",
        input.ai_resistance.as_deref(),
    );
    push_opt(
        &mut protect_args,
        "--environment-policy",
        input.environment_policy.as_deref(),
    );
    push_opt(
        &mut protect_args,
        "--runtime-cert-sha256",
        runtime_cert_sha256.as_deref(),
    );
    push_path_opt(
        server,
        &mut protect_args,
        "--apktool",
        input.apktool.as_deref(),
        "apktool",
    )?;
    push_path_opt(
        server,
        &mut protect_args,
        "--resources",
        input.resources.as_deref(),
        "运行时资源包",
    )?;
    push_path_opt(
        server,
        &mut protect_args,
        "--apksigner",
        input.apksigner.as_deref(),
        "apksigner",
    )?;
    push_path_opt(
        server,
        &mut protect_args,
        "--xop-pvm2-packer",
        input.xop_pvm2_packer.as_deref(),
        "XOP PVM2 packer",
    )?;
    push_repeated(
        &mut protect_args,
        "--xop-true-vmp-prefix",
        &input.xop_true_vmp_prefixes,
    );
    push_path_opt(
        server,
        &mut protect_args,
        "--pvm2-required-methods",
        input.pvm2_required_methods.as_deref(),
        "PVM2 关键方法清单",
    )?;
    push_path_opt(
        server,
        &mut protect_args,
        "--native-vmp-evidence",
        input.native_vmp_evidence.as_deref(),
        "Native VMP 证据清单",
    )?;
    if input.protect_route_assets {
        protect_args.push("--protect-route-assets".into());
    }
    if !input.exclude_abis.is_empty() {
        protect_args.push("--exclude-abis".into());
        protect_args.push(input.exclude_abis.join(","));
    }
    push_runtime_ui(server, &mut protect_args, input.runtime_ui.as_ref())?;
    let mut env = stage_env.clone();
    if let Some(endpoint) = input.byos_endpoint.as_deref() {
        protect_args.push("--byos-endpoint".into());
        protect_args.push(endpoint.to_string());
        let auth = input
            .byos_auth
            .as_deref()
            .context("BYOS endpoint 需要 byos_auth")?;
        protect_args.push("--byos-auth".into());
        protect_args.push(auth.to_string());
        let env_name = input
            .byos_api_key_env
            .as_deref()
            .unwrap_or("SHELLSMITH_BYOS_API_KEY");
        let value = std::env::var(env_name)
            .with_context(|| format!("缺少 BYOS API key 环境变量 {env_name}"))?;
        env.push(("SHELLSMITH_BYOS_API_KEY".into(), value));
    }

    let mut commands = vec![CommandPlan {
        args: protect_args,
        env: env.clone(),
        label: "加固 APK".into(),
    }];
    if let Some(sign) = input.sign {
        let sign_args = sign_command_args(
            server,
            &sign,
            protect_output.display().to_string(),
            sign_output
                .as_ref()
                .map(|p| p.display().to_string())
                .as_deref(),
            input.allow_in_place,
        )?;
        let mut sign_env = sign_env(&sign)?;
        sign_env.extend(stage_env);
        commands.push(CommandPlan {
            args: sign_args,
            env: sign_env,
            label: "签名 APK".into(),
        });
    }
    let job_id = server.start_job(
        "shellsmith_protect_apk",
        JobPlan {
            commands,
            result: json!({
                "output": final_output,
                "report": report_path(&final_output),
                "signed": sign_output.is_some()
            }),
            keep,
        },
        progress_token,
    )?;
    Ok(ToolResult::ok(
        json!({"job_id": job_id, "status": "running"}),
    ))
}

fn protect_aab(
    server: &Arc<Server>,
    args: Value,
    progress_token: Option<Value>,
) -> Result<ToolResult> {
    let input: ProtectAabInput = parse(args)?;
    require_confirm(input.confirm)?;
    let source = server.resolve_input(&input.input, "输入 AAB")?;
    let output = server.resolve_output(&input.output, "输出 AAB")?;
    let bundletool = server.resolve_input(&input.bundletool, "bundletool")?;
    let aapt2 = server.resolve_input(&input.aapt2, "aapt2")?;
    let keystore = server.resolve_input(&input.keystore, "keystore")?;
    if source == output {
        anyhow::bail!("AAB 输出不能等于输入");
    }
    let mut keep = Vec::new();
    let stage = tempfile::Builder::new()
        .prefix("shellsmith-mcp-stage-")
        .tempdir_in(output.parent().unwrap_or(Path::new(".")))
        .context("创建 MCP 任务暂存目录失败")?;
    let stage_env = vec![(
        "SHELLSMITH_STAGE_ROOT".to_string(),
        stage.path().display().to_string(),
    )];
    keep.push(stage);
    let mut cli_args = vec![
        "protect-aab".to_string(),
        "-i".into(),
        source.display().to_string(),
        "-o".into(),
        output.display().to_string(),
        "--bundletool".into(),
        bundletool.display().to_string(),
        "--aapt2".into(),
        aapt2.display().to_string(),
        "--ks".into(),
        keystore.display().to_string(),
        "--key-alias".into(),
        input.key_alias,
        "--json".into(),
    ];
    push_keystore_type(&mut cli_args, input.keystore_type.as_deref());
    push_path_opt(
        server,
        &mut cli_args,
        "--apktool",
        input.apktool.as_deref(),
        "apktool",
    )?;
    push_path_opt(
        server,
        &mut cli_args,
        "--resources",
        input.resources.as_deref(),
        "运行时资源包",
    )?;
    push_path_opt(
        server,
        &mut cli_args,
        "--apksigner",
        input.apksigner.as_deref(),
        "apksigner",
    )?;
    push_opt(&mut cli_args, "--profile", input.profile.as_deref());
    push_opt(
        &mut cli_args,
        "--ai-resistance",
        input.ai_resistance.as_deref(),
    );
    push_opt(
        &mut cli_args,
        "--environment-policy",
        input.environment_policy.as_deref(),
    );
    push_opt(
        &mut cli_args,
        "--runtime-cert-sha256",
        input.runtime_cert_sha256.as_deref(),
    );
    if input.allow_upload_cert_binding {
        cli_args.push("--allow-upload-cert-binding".into());
    }
    if input.play_delivery_adapter {
        cli_args.push("--play-delivery-adapter".into());
    }
    push_opt(&mut cli_args, "--engine", input.engine.as_deref());
    push_path_opt(
        server,
        &mut cli_args,
        "--xop-packer",
        input.xop_packer.as_deref(),
        "XOP packer",
    )?;
    push_path_opt(
        server,
        &mut cli_args,
        "--xop-shell-dir",
        input.xop_shell_dir.as_deref(),
        "XOP shell 目录",
    )?;
    push_opt(&mut cli_args, "--xop-profile", input.xop_profile.as_deref());
    if input.xop_no_protect_so {
        cli_args.push("--xop-no-protect-so".into());
    }
    if input.xop_encrypt_assets {
        cli_args.push("--xop-encrypt-assets".into());
    }
    if input.xop_enable_res_protect {
        cli_args.push("--xop-enable-res-protect".into());
    }
    if input.xop_detect_proxy {
        cli_args.push("--xop-detect-proxy".into());
    }
    if let Some(action) = input.xop_rasp_action {
        cli_args.push("--xop-rasp-action".into());
        cli_args.push(action.to_string());
    }
    push_path_opt(
        server,
        &mut cli_args,
        "--xop-pvm2-packer",
        input.xop_pvm2_packer.as_deref(),
        "XOP PVM2 packer",
    )?;
    push_repeated(
        &mut cli_args,
        "--xop-true-vmp-prefix",
        &input.xop_true_vmp_prefixes,
    );
    push_path_opt(
        server,
        &mut cli_args,
        "--pvm2-required-methods",
        input.pvm2_required_methods.as_deref(),
        "PVM2 关键方法清单",
    )?;
    push_path_opt(
        server,
        &mut cli_args,
        "--native-vmp-evidence",
        input.native_vmp_evidence.as_deref(),
        "Native VMP 证据清单",
    )?;
    if input.protect_route_assets {
        cli_args.push("--protect-route-assets".into());
    }
    if !input.exclude_abis.is_empty() {
        cli_args.push("--exclude-abis".into());
        cli_args.push(input.exclude_abis.join(","));
    }
    if let Some(value) = input.apks_output {
        cli_args.push("--apks-output".into());
        cli_args.push(
            server
                .resolve_output(&value, "APKS 输出")?
                .display()
                .to_string(),
        );
    }
    if input.install_apks {
        cli_args.push("--install-apks".into());
    }
    push_path_opt(
        server,
        &mut cli_args,
        "--device-spec",
        input.device_spec.as_deref(),
        "设备规格",
    )?;
    push_opt(&mut cli_args, "--device-id", input.device_id.as_deref());
    push_opt(
        &mut cli_args,
        "--smoke-package",
        input.smoke_package.as_deref(),
    );
    push_runtime_ui(server, &mut cli_args, input.runtime_ui.as_ref())?;
    let mut env = password_envs(
        input.password_env.as_deref(),
        input.key_password_env.as_deref(),
    )?;
    env.extend(stage_env);
    let job_id = server.start_job(
        "shellsmith_protect_aab",
        JobPlan {
            commands: vec![CommandPlan {
                args: cli_args,
                env,
                label: "加固 AAB".into(),
            }],
            result: json!({"output": output, "report": report_path(&output)}),
            keep,
        },
        progress_token,
    )?;
    Ok(ToolResult::ok(
        json!({"job_id": job_id, "status": "running"}),
    ))
}

fn protect_xop(
    server: &Arc<Server>,
    args: Value,
    progress_token: Option<Value>,
) -> Result<ToolResult> {
    let input: ProtectXopInput = parse(args)?;
    require_confirm(input.confirm)?;
    let source = server.resolve_input(&input.input, "输入 APK")?;
    let output = server.resolve_output(&input.output, "输出 APK")?;
    let packer = server.resolve_input(&input.packer, "XOP packer")?;
    let shell_dir = server.resolve_input(&input.shell_dir, "XOP shell 目录")?;
    if source == output {
        anyhow::bail!("输出不能等于输入；XOP 加固不支持原地覆盖");
    }
    let mut keep = Vec::new();
    let stage = tempfile::Builder::new()
        .prefix("shellsmith-mcp-stage-")
        .tempdir_in(output.parent().unwrap_or(Path::new(".")))
        .context("创建 MCP 任务暂存目录失败")?;
    let stage_env = vec![(
        "SHELLSMITH_STAGE_ROOT".to_string(),
        stage.path().display().to_string(),
    )];
    keep.push(stage);
    let mut cli_args = vec![
        "protect-xop".to_string(),
        "-i".into(),
        source.display().to_string(),
        "-o".into(),
        output.display().to_string(),
        "--packer".into(),
        packer.display().to_string(),
        "--shell-dir".into(),
        shell_dir.display().to_string(),
        "--json".into(),
    ];
    if let Some(keystore) = input.keystore.as_deref() {
        cli_args.push("--ks".into());
        cli_args.push(
            server
                .resolve_input(keystore, "keystore")?
                .display()
                .to_string(),
        );
    }
    push_opt(&mut cli_args, "--key-alias", input.key_alias.as_deref());
    push_keystore_type(&mut cli_args, input.keystore_type.as_deref());
    push_path_opt(
        server,
        &mut cli_args,
        "--apksigner",
        input.apksigner.as_deref(),
        "apksigner",
    )?;
    if input.allow_unsigned {
        cli_args.push("--allow-unsigned".into());
    }
    push_opt(&mut cli_args, "--profile", input.profile.as_deref());
    push_opt(
        &mut cli_args,
        "--ai-resistance",
        input.ai_resistance.as_deref(),
    );
    push_repeated(&mut cli_args, "--hollow-prefix", &input.hollow_prefixes);
    push_repeated(&mut cli_args, "--vmp-prefix", &input.vmp_prefixes);
    push_repeated(&mut cli_args, "--true-vmp-prefix", &input.true_vmp_prefixes);
    for (flag, value) in [
        ("--no-protect-so", input.no_protect_so),
        ("--encrypt-assets", input.encrypt_assets),
        ("--enable-res-protect", input.enable_res_protect),
        ("--detect-proxy", input.detect_proxy),
    ] {
        if value {
            cli_args.push(flag.into());
        }
    }
    if let Some(action) = input.rasp_action {
        cli_args.push("--rasp-action".into());
        cli_args.push(action.to_string());
    }
    let mut env = if input.keystore.is_some() {
        if input.key_alias.as_deref().unwrap_or_default().is_empty() {
            anyhow::bail!("提供 keystore 时必须提供 key_alias");
        }
        password_envs(
            input.password_env.as_deref(),
            input.key_password_env.as_deref(),
        )?
    } else {
        if !input.allow_unsigned {
            anyhow::bail!("未提供 keystore 时必须设置 allow_unsigned=true");
        }
        Vec::new()
    };
    env.extend(stage_env);
    let job_id = server.start_job(
        "shellsmith_protect_xop",
        JobPlan {
            commands: vec![CommandPlan {
                args: cli_args,
                env,
                label: "XOP 单壳加固".into(),
            }],
            result: json!({"output": output}),
            keep,
        },
        progress_token,
    )?;
    Ok(ToolResult::ok(
        json!({"job_id": job_id, "status": "running"}),
    ))
}

fn protect_ios(
    server: &Arc<Server>,
    args: Value,
    progress_token: Option<Value>,
) -> Result<ToolResult> {
    let input: ProtectIosInput = parse(args)?;
    if !input.dry_run {
        require_confirm(input.confirm)?;
    }
    let config = server.resolve_input(&input.ios_config, "iOS 配置")?;
    let output = server.resolve_output(&input.output, "iOS 输出目录")?;
    let mut cli_args = vec![
        "protect-ios".to_string(),
        "--ios-config".into(),
        config.display().to_string(),
        "--output".into(),
        output.display().to_string(),
        "--json".into(),
    ];
    push_path_opt(
        server,
        &mut cli_args,
        "--freerasp-zip",
        input.freerasp_zip.as_deref(),
        "freeRASP ZIP",
    )?;
    if let Some(value) = input.ios_cache_dir.as_deref() {
        let path = server.resolve_output(value, "iOS SDK 缓存目录")?;
        cli_args.push("--ios-cache-dir".into());
        cli_args.push(path.display().to_string());
    }
    push_path_opt(
        server,
        &mut cli_args,
        "--export-options",
        input.export_options.as_deref(),
        "ExportOptions.plist",
    )?;
    push_opt(
        &mut cli_args,
        "--export-method",
        input.export_method.as_deref(),
    );
    if input.allow_provisioning_updates {
        cli_args.push("--allow-provisioning-updates".into());
    }
    if input.dry_run {
        cli_args.push("--dry-run".into());
    }
    let job_id = server.start_job(
        "shellsmith_protect_ios",
        JobPlan {
            commands: vec![CommandPlan {
                args: cli_args,
                env: Vec::new(),
                label: "iOS 保护".into(),
            }],
            result: json!({"output": output}),
            keep: Vec::new(),
        },
        progress_token,
    )?;
    Ok(ToolResult::ok(
        json!({"job_id": job_id, "status": "running"}),
    ))
}

fn sign_apk(
    server: &Arc<Server>,
    args: Value,
    progress_token: Option<Value>,
) -> Result<ToolResult> {
    let input: SignInput = parse(args)?;
    require_confirm(input.confirm)?;
    if input.input.is_none() || input.keystore.is_none() || input.key_alias.is_none() {
        anyhow::bail!("签名需要 input、keystore 和 key_alias");
    }
    let source = server.resolve_input(input.input.as_deref().unwrap(), "输入 APK")?;
    let output = match input.output.as_deref() {
        Some(value) => Some(server.resolve_output(value, "输出 APK")?),
        None => None,
    };
    if output.as_ref().is_some_and(|output| output == &source)
        && !input.allow_in_place.unwrap_or(false)
    {
        anyhow::bail!("输出等于输入；如确需原地签名，请设置 allow_in_place=true");
    }
    if output.is_none() && !input.allow_in_place.unwrap_or(false) {
        anyhow::bail!("签名需要 output；如确需原地签名，请设置 allow_in_place=true");
    }
    let final_output = output.clone().unwrap_or_else(|| source.clone());
    let final_output_string = final_output.display().to_string();
    let mut keep = Vec::new();
    let stage = tempfile::Builder::new()
        .prefix("shellsmith-mcp-stage-")
        .tempdir_in(final_output.parent().unwrap_or(Path::new(".")))
        .context("创建 MCP 任务暂存目录失败")?;
    let stage_env = vec![(
        "SHELLSMITH_STAGE_ROOT".to_string(),
        stage.path().display().to_string(),
    )];
    keep.push(stage);
    let cli_args = sign_command_args(
        server,
        &input,
        source.display().to_string(),
        Some(&final_output_string),
        input.allow_in_place.unwrap_or(false),
    )?;
    let mut env = sign_env(&input)?;
    env.extend(stage_env);
    let job_id = server.start_job(
        "shellsmith_sign_apk",
        JobPlan {
            commands: vec![CommandPlan {
                args: cli_args,
                env,
                label: "签名 APK".into(),
            }],
            result: json!({"output": final_output, "report": report_path(&final_output)}),
            keep,
        },
        progress_token,
    )?;
    Ok(ToolResult::ok(
        json!({"job_id": job_id, "status": "running"}),
    ))
}

fn install_apks(
    server: &Arc<Server>,
    args: Value,
    progress_token: Option<Value>,
) -> Result<ToolResult> {
    let input: InstallApksInput = parse(args)?;
    require_confirm(input.confirm)?;
    let apks = server.resolve_input(&input.apks, "APKS")?;
    let bundletool = server.resolve_input(&input.bundletool, "bundletool")?;
    let mut cli_args = vec![
        "install-apks".to_string(),
        apks.display().to_string(),
        "--bundletool".into(),
        bundletool.display().to_string(),
    ];
    push_opt(&mut cli_args, "--device-id", input.device_id.as_deref());
    let job_id = server.start_job(
        "shellsmith_install_apks",
        JobPlan {
            commands: vec![CommandPlan {
                args: cli_args,
                env: Vec::new(),
                label: "安装 APKS".into(),
            }],
            result: json!({"apks": apks}),
            keep: Vec::new(),
        },
        progress_token,
    )?;
    Ok(ToolResult::ok(
        json!({"job_id": job_id, "status": "running"}),
    ))
}

fn read_report(server: &Arc<Server>, args: Value) -> Result<ToolResult> {
    let input: ReportInput = parse(args)?;
    let path = server.resolve_input(&input.path, "保护报告")?;
    if path.extension().and_then(|value| value.to_str()) != Some("json") {
        anyhow::bail!("保护报告必须是 JSON 文件");
    }
    let metadata = fs::metadata(&path)?;
    if metadata.len() > 64 * 1024 * 1024 {
        anyhow::bail!("保护报告超过 64 MiB");
    }
    let value: Value = serde_json::from_slice(&fs::read(&path)?)?;
    let output = match input.mode.as_deref() {
        None | Some("summary") => json!({
            "path": path,
            "schema_version": value.get("schema_version"),
            "image_version": value.get("image_version"),
            "build": value.get("build"),
            "output_sha256": value.get("output_sha256"),
            "methods": value.get("methods").and_then(Value::as_array).map(|rows| rows.len()),
            "dexes": value.get("dexes"),
            "native_vmp": value.get("native_vmp"),
        }),
        Some("full") => value,
        Some(other) => anyhow::bail!("mode 仅支持 summary 或 full，收到 {other}"),
    };
    Ok(ToolResult::ok(output))
}

fn job_status(server: &Arc<Server>, args: Value) -> Result<ToolResult> {
    let input: JobInput = parse(args)?;
    let job = server.job_status(&input.job_id).context("未找到 job_id")?;
    Ok(ToolResult::ok(serde_json::to_value(job)?))
}

fn job_result(server: &Arc<Server>, args: Value) -> Result<ToolResult> {
    let input: JobInput = parse(args)?;
    let job = server.job_status(&input.job_id).context("未找到 job_id")?;
    if job.status == crate::jobs::JobStatus::Running {
        anyhow::bail!("任务仍在运行，请稍后查询");
    }
    Ok(ToolResult::ok(serde_json::to_value(job)?))
}

fn job_cancel(server: &Arc<Server>, args: Value) -> Result<ToolResult> {
    let input: JobInput = parse(args)?;
    let job = server.cancel_job(&input.job_id).context("未找到 job_id")?;
    Ok(ToolResult::ok(serde_json::to_value(job)?))
}

fn normalize_fingerprint(value: &str) -> String {
    value.trim().to_uppercase().replace([':', ' ', '-'], "")
}

fn cert_fingerprint(value: &Value) -> Option<String> {
    value
        .get("cert_fingerprint")
        .and_then(Value::as_str)
        .map(normalize_fingerprint)
        .filter(|value| !value.is_empty())
}

fn resolve_sign_keystore(server: &Arc<Server>, input: &SignInput) -> Result<PathBuf> {
    let keystore = input.keystore.as_deref().context("签名缺少 keystore")?;
    server.resolve_input(keystore, "keystore")
}

/// 校验运行时绑定证书与最终签名证书一致。
///
/// - 未显式提供 `runtime_cert_sha256` 时，CLI 会默认绑定输入 APK 证书；因此输入证书必须等于最终签名证书。
/// - 显式提供时，绑定证书必须等于最终签名证书；这允许用户有意把运行时绑定到新证书。
fn ensure_sign_certificate_binding(
    server: &Arc<Server>,
    input_apk: &Path,
    sign: &SignInput,
    requested: Option<&str>,
) -> Result<String> {
    let keystore = resolve_sign_keystore(server, sign)?;
    let alias = sign.key_alias.as_deref().context("签名缺少 key_alias")?;
    let env = sign_env(sign)?;
    let keystore_info = server.run_sync(
        &[
            "check-keystore".to_string(),
            "--ks".into(),
            keystore.display().to_string(),
            "--alias".into(),
            alias.to_string(),
        ],
        &env,
    )?;
    let sign_cert = cert_fingerprint(&keystore_info).context("无法从 keystore 读取签名证书指纹")?;

    let apk_info = server.run_sync(
        &["check-apk".to_string(), input_apk.display().to_string()],
        &[],
    )?;
    let input_cert = cert_fingerprint(&apk_info);

    if let Some(requested) = requested {
        let requested = normalize_fingerprint(requested);
        if requested != sign_cert {
            anyhow::bail!(
                "runtime_cert_sha256 与最终签名证书不一致：绑定 {requested}，最终签名 {sign_cert}"
            );
        }
    } else if input_cert.as_deref() != Some(sign_cert.as_str()) {
        if input_cert.is_none() {
            anyhow::bail!(
                "输入 APK 未签名或无法读取证书；请显式设置 runtime_cert_sha256={sign_cert} 以绑定最终签名证书"
            );
        }
        anyhow::bail!(
            "输入 APK 证书与最终签名证书不一致；请使用同一证书，或显式设置 runtime_cert_sha256={sign_cert} 确认重绑定"
        );
    }
    Ok(sign_cert)
}

fn sign_command_args(
    server: &Arc<Server>,
    input: &SignInput,
    input_path: String,
    output_path: Option<&str>,
    allow_in_place: bool,
) -> Result<Vec<String>> {
    let keystore = resolve_sign_keystore(server, input)?;
    if output_path.is_none() && !allow_in_place {
        anyhow::bail!("签名需要 output");
    }
    if output_path.is_some_and(|output| output == input_path) && !allow_in_place {
        anyhow::bail!("输出等于输入；如确需原地签名，请设置 allow_in_place=true");
    }
    let mut args = vec![
        "sign".to_string(),
        "-i".into(),
        input_path,
        "--ks".into(),
        keystore.display().to_string(),
        "--key-alias".into(),
        input.key_alias.clone().context("签名缺少 key_alias")?,
        "--json".into(),
    ];
    if let Some(output) = output_path {
        args.push("-o".into());
        args.push(output.to_string());
    }
    push_keystore_type(&mut args, input.keystore_type.as_deref());
    push_path_opt(
        server,
        &mut args,
        "--apksigner",
        input.apksigner.as_deref(),
        "apksigner",
    )?;
    for (flag, value) in [
        ("--v1", input.v1),
        ("--v2", input.v2),
        ("--v3", input.v3),
        ("--v4", input.v4),
    ] {
        if let Some(value) = value {
            args.push(flag.into());
            args.push(value.to_string());
        }
    }
    Ok(args)
}

fn sign_env(input: &SignInput) -> Result<Vec<(String, String)>> {
    password_envs(
        input.password_env.as_deref(),
        input.key_password_env.as_deref(),
    )
}

fn password_envs(store_env: Option<&str>, key_env: Option<&str>) -> Result<Vec<(String, String)>> {
    let store_name = store_env.unwrap_or("MOCIKA_SHIELD_KS_PASS");
    let store = std::env::var(store_name)
        .with_context(|| format!("缺少 keystore 密码环境变量 {store_name}"))?;
    let mut env = vec![("MOCIKA_SHIELD_KS_PASS".to_string(), store.clone())];
    let key_name = key_env.unwrap_or("MOCIKA_SHIELD_KEY_PASS");
    if let Some(key) = std::env::var_os(key_name) {
        env.push((
            "MOCIKA_SHIELD_KEY_PASS".to_string(),
            key.to_string_lossy().into_owned(),
        ));
    } else {
        env.push(("MOCIKA_SHIELD_KEY_PASS".to_string(), store));
    }
    Ok(env)
}

fn keystore_env(
    password_env: Option<&str>,
    keystore: Option<&Path>,
    key_alias: Option<&str>,
    args: &mut Vec<String>,
) -> Result<Vec<(String, String)>> {
    let Some(keystore) = keystore else {
        return Ok(Vec::new());
    };
    let Some(alias) = key_alias else {
        anyhow::bail!("提供 keystore 时必须提供 key_alias");
    };
    args.push("--ks".into());
    args.push(keystore.display().to_string());
    args.push("--ks-alias".into());
    args.push(alias.to_string());
    let env_name = password_env.unwrap_or("MOCIKA_SHIELD_KS_PASS");
    let password =
        std::env::var(env_name).with_context(|| format!("缺少密码环境变量 {env_name}"))?;
    Ok(vec![("MOCIKA_SHIELD_KS_PASS".to_string(), password)])
}

fn push_runtime_ui(
    server: &Arc<Server>,
    args: &mut Vec<String>,
    input: Option<&RuntimeUiInput>,
) -> Result<()> {
    let Some(input) = input else {
        return Ok(());
    };
    for (flag, value) in [
        ("--secure-screen", input.secure_screen),
        ("--runtime-recheck", input.runtime_recheck),
        ("--obfuscate-resource-names", input.obfuscate_resource_names),
    ] {
        if let Some(value) = value {
            args.push(flag.into());
            args.push(value.to_string());
        }
    }
    if let Some(value) = &input.adb_policy {
        args.push("--adb-policy".into());
        args.push(value.clone());
    }
    if let Some(values) = &input.screen_exempt_activities {
        if !values.is_empty() {
            args.push("--screen-exempt-activities".into());
            args.push(values.join(","));
        }
    }
    if let Some(values) = &input.resource_name_keep {
        if !values.is_empty() {
            args.push("--resource-name-keep".into());
            args.push(values.join(","));
        }
    }
    push_path_opt(
        server,
        args,
        "--ui-packer",
        input.ui_packer.as_deref(),
        "界面/资源变换器",
    )
}

fn push_path_opt(
    server: &Arc<Server>,
    args: &mut Vec<String>,
    flag: &str,
    value: Option<&str>,
    label: &str,
) -> Result<()> {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    let path = server.resolve_input(value, label)?;
    args.push(flag.to_string());
    args.push(path.display().to_string());
    Ok(())
}

fn push_opt(args: &mut Vec<String>, flag: &str, value: Option<&str>) {
    if let Some(value) = value {
        if !value.is_empty() {
            args.push(flag.to_string());
            args.push(value.to_string());
        }
    }
}

fn push_repeated(args: &mut Vec<String>, flag: &str, values: &[String]) {
    for value in values {
        args.push(flag.to_string());
        args.push(value.clone());
    }
}

fn push_keystore_type(args: &mut Vec<String>, value: Option<&str>) {
    if let Some(value) = value {
        args.push("--ks-type".into());
        args.push(value.to_ascii_lowercase());
    }
}

fn report_path(output: &Path) -> String {
    format!("{}.protection.json", output.display())
}
