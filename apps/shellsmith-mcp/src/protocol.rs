use crate::jobs::Server;
use crate::tools;
use anyhow::Result;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::sync::Arc;
use std::thread;

const LATEST_PROTOCOL_VERSION: &str = "2025-06-18";
const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2024-11-05", "2025-03-26", "2025-06-18"];

const INSTRUCTIONS: &str = "\
Shellsmith MCP exposes the local Shellsmith CLI. All artifact processing stays on this machine. \
Inspect first with shellsmith_check_apk / shellsmith_check_aab / shellsmith_check_ios / \
shellsmith_check_keystore, read reports with shellsmith_read_report, then start long-running \
protect/sign/install work with the corresponding tool. Long-running tools return a job_id \
immediately; poll shellsmith_job_status, fetch the terminal payload with shellsmith_job_result, \
and use shellsmith_job_cancel to stop the CLI subprocess. Keystore and BYOS secrets are never \
accepted as tool arguments; export them in the MCP server environment and pass only the \
environment variable name (password_env / key_password_env / byos_api_key_env).";

pub fn serve(server: Arc<Server>) -> Result<()> {
    let stdin = std::io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let mut line = String::new();
    loop {
        line.clear();
        let read = match reader.read_line(&mut line) {
            Ok(read) => read,
            Err(error) => {
                server.shutdown();
                return Err(error.into());
            }
        };
        if read == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let message: Value = match serde_json::from_str(trimmed) {
            Ok(value) => value,
            Err(error) => {
                server.write_json(&error_response(
                    Value::Null,
                    -32700,
                    format!("JSON 解析失败: {error}"),
                ));
                continue;
            }
        };
        if let Some(messages) = message.as_array() {
            for message in messages {
                handle_message(&server, message);
            }
        } else {
            handle_message(&server, &message);
        }
    }
    server.shutdown();
    Ok(())
}

fn handle_message(server: &Arc<Server>, message: &Value) {
    let method = message.get("method").and_then(Value::as_str);
    let id = message.get("id").cloned();
    let params = message.get("params").cloned().unwrap_or(Value::Null);

    let Some(method) = method else {
        if let Some(id) = id {
            server.write_json(&error_response(id, -32600, "缺少 method"));
        }
        return;
    };

    let Some(id) = id else {
        handle_notification(server, method, params);
        return;
    };

    let response = match method {
        "initialize" => {
            let requested = params
                .get("protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or(LATEST_PROTOCOL_VERSION);
            let protocol_version = if SUPPORTED_PROTOCOL_VERSIONS.contains(&requested) {
                requested
            } else {
                LATEST_PROTOCOL_VERSION
            };
            Ok(json!({
                "protocolVersion": protocol_version,
                "capabilities": {
                    "tools": { "listChanged": false }
                },
                "serverInfo": {
                    "name": "shellsmith-mcp",
                    "title": "Shellsmith",
                    "version": env!("CARGO_PKG_VERSION")
                },
                "instructions": INSTRUCTIONS
            }))
        }
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tools::tool_definitions() })),
        "tools/call" => {
            let Some(name) = params.get("name").and_then(Value::as_str) else {
                server.write_json(&error_response(id, -32602, "tools/call 缺少 name"));
                return;
            };
            let arguments = match params.get("arguments") {
                None | Some(Value::Null) => json!({}),
                Some(value) => value.clone(),
            };
            if !arguments.is_object() {
                server.write_json(&error_response(id, -32602, "arguments 必须是对象"));
                return;
            }
            let progress_token = params
                .get("_meta")
                .and_then(|meta| meta.get("progressToken"))
                .cloned();
            let server = Arc::clone(server);
            let name = name.to_string();
            thread::spawn(move || {
                let result = tools::call(&server, &name, arguments, progress_token);
                match serde_json::to_value(result) {
                    Ok(value) => server.write_json(&success_response(id, value)),
                    Err(error) => server.write_json(&error_response(
                        id,
                        -32603,
                        format!("序列化工具结果失败: {error}"),
                    )),
                }
            });
            return;
        }
        "shutdown" => {
            server.shutdown();
            Ok(Value::Null)
        }
        _ => Err(anyhow::anyhow!("未支持的方法: {method}")),
    };

    match response {
        Ok(result) => server.write_json(&success_response(id, result)),
        Err(error) => {
            let code = if method.starts_with("notifications/") {
                -32600
            } else {
                -32601
            };
            server.write_json(&error_response(id, code, format!("{error:#}")));
        }
    }
}

fn handle_notification(server: &Arc<Server>, method: &str, _params: Value) {
    match method {
        "notifications/initialized"
        | "notifications/cancelled"
        | "notifications/roots/list_changed" => {}
        "exit" => {
            server.shutdown();
            let _ = std::io::stdout().flush();
            std::process::exit(0);
        }
        _ => {
            let _ = server;
        }
    }
}

fn success_response(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn error_response(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message.into() }
    })
}
