use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

const SECRET: &str = "test-secret";

struct McpClient {
    child: Child,
    stdin: Option<ChildStdin>,
    rx: Receiver<String>,
    inbox: Vec<Value>,
    next_id: i64,
}

impl McpClient {
    fn start(cli: &Path, allow_roots: &[&Path], envs: &[(&str, &str)]) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_shellsmith-mcp"));
        command.arg("--cli").arg(cli);
        for root in allow_roots {
            command.arg("--allow-root").arg(root);
        }
        for (key, value) in envs {
            command.env(key, value);
        }
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut child = command.spawn().expect("启动 shellsmith-mcp 失败");
        let stdin = child.stdin.take().expect("stdin");
        let stdout = child.stdout.take().expect("stdout");
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                match line {
                    Ok(line) if !line.trim().is_empty() => {
                        if tx.send(line).is_err() {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        });
        Self {
            child,
            stdin: Some(stdin),
            rx,
            inbox: Vec::new(),
            next_id: 1,
        }
    }

    fn send(&mut self, value: Value) {
        let text = serde_json::to_string(&value).expect("序列化请求");
        let stdin = self.stdin.as_mut().expect("stdin 已关闭");
        writeln!(stdin, "{text}").expect("写入 stdin");
        stdin.flush().expect("刷新 stdin");
    }

    fn notify(&mut self, method: &str, params: Value) {
        self.send(json!({"jsonrpc": "2.0", "method": method, "params": params}));
    }

    fn read_message(&mut self, timeout: Duration) -> Value {
        let line = self
            .rx
            .recv_timeout(timeout)
            .unwrap_or_else(|_| panic!("等待 MCP 消息超时"));
        serde_json::from_str(&line).unwrap_or_else(|error| panic!("无效 JSON: {error}: {line}"))
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.send_request(method, params);
        self.response_for(&id)
    }

    fn send_request(&mut self, method: &str, params: Value) -> Value {
        let id = json!(self.next_id);
        self.next_id += 1;
        self.send(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params
        }));
        id
    }

    fn response_for(&mut self, id: &Value) -> Value {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(index) = self
                .inbox
                .iter()
                .position(|message| message.get("id") == Some(id))
            {
                return self.inbox.remove(index);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            let message = self.read_message(remaining);
            if message.get("id") == Some(id) {
                return message;
            }
            self.inbox.push(message);
        }
    }

    fn call(&mut self, name: &str, arguments: Value) -> Value {
        self.call_with_meta(name, arguments, Value::Null)
    }

    fn call_with_meta(&mut self, name: &str, arguments: Value, meta: Value) -> Value {
        let mut params = json!({"name": name, "arguments": arguments});
        if !meta.is_null() {
            params["_meta"] = meta;
        }
        let response = self.request("tools/call", params);
        assert!(
            response.get("error").is_none(),
            "tools/call 协议错误: {response}"
        );
        response["result"].clone()
    }

    fn wait_for_notification(&mut self, method: &str) -> Value {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(index) = self
                .inbox
                .iter()
                .position(|message| message.get("method").and_then(Value::as_str) == Some(method))
            {
                return self.inbox.remove(index);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            let message = self.read_message(remaining);
            if message.get("method").and_then(Value::as_str) == Some(method) {
                return message;
            }
            self.inbox.push(message);
        }
    }

    fn wait_job(&mut self, job_id: &str) -> Value {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let job = self.call("shellsmith_job_status", json!({"job_id": job_id}));
            assert!(job.get("isError").is_none() || job["isError"] == false);
            let status = job["structuredContent"]["status"]
                .as_str()
                .unwrap_or_else(|| panic!("任务状态缺失: {job}"));
            if status != "running" {
                return job;
            }
            assert!(
                Instant::now() < deadline,
                "任务 {job_id} 在超时前未结束: {job}"
            );
            thread::sleep(Duration::from_millis(50));
        }
    }

    fn close_stdin(&mut self) {
        self.stdin.take();
    }

    fn wait_exit(&mut self, timeout: Duration) -> Option<std::process::ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.child.try_wait().expect("等待 MCP 退出失败") {
                Some(status) => return Some(status),
                None if Instant::now() >= deadline => return None,
                None => thread::sleep(Duration::from_millis(50)),
            }
        }
    }
}

impl Drop for McpClient {
    fn drop(&mut self) {
        if let Some(stdin) = self.stdin.as_mut() {
            let _ = stdin.flush();
        }
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn write_fake_cli(dir: &Path) -> PathBuf {
    let path = dir.join("fake-shield.sh");
    let script = r#"#!/bin/sh
log="${FAKE_SHIELD_LOG:-/dev/null}"
printf '%s\n' "$*" >> "$log"
cmd="$1"
shift || true
case "$cmd" in
  --version)
    echo "shield 1.10.1"
    ;;
  check-apk)
    printf '{"already_protected":false,"is_signed":true,"cert_fingerprint":"%s","error":null}\n' "${FAKE_APK_CERT:-AA:BB:CC}"
    ;;
  check-aab)
    sleep "${FAKE_CHECK_SLEEP:-0}"
    echo '{"has_base":true,"modules":[]}'
    ;;
  check-keystore)
    if [ "$MOCIKA_SHIELD_KS_PASS" != "test-secret" ]; then
      echo '{"type":"error","message":"bad keystore password"}'
      exit 1
    fi
    printf '{"cert_fingerprint":"%s","error":null}\n' "${FAKE_KS_CERT:-CC:DD:EE}"
    ;;
  protect|protect-xop|protect-aab|protect-ios|sign|install-apks)
    if [ "${FAKE_REJECT_BYOS:-0}" = "1" ] && [ -n "${SHELLSMITH_BYOS_API_KEY:-}" ]; then
      echo '{"type":"error","message":"byos key leaked"}'
      exit 1
    fi
    echo '{"type":"progress","step":"Fake","message":"working"}'
    if [ -n "${FAKE_TEMP_LOG:-}" ]; then
      printf 'TMPDIR=%s\nSTAGE=%s\n' "${TMPDIR:-}" "${SHELLSMITH_STAGE_ROOT:-}" > "$FAKE_TEMP_LOG"
    fi
    if [ "${FAKE_SHELLSMITH_LEAVE_TEMP:-0}" = "1" ]; then
      mkdir -p "${TMPDIR:-/tmp}/fake-pass"
      echo secret > "${TMPDIR:-/tmp}/fake-pass/ks.pass"
      mkdir -p "${SHELLSMITH_STAGE_ROOT:-.}/shield-signed-fake"
      echo staged > "${SHELLSMITH_STAGE_ROOT:-.}/shield-signed-fake/staged.apk"
    fi
    if [ "${FAKE_SHELLSMITH_CLOSE_STDOUT:-0}" = "1" ]; then
      exec 1>&-
    fi
    sleep "${FAKE_SHIELD_SLEEP:-0.05}"
    if [ "${FAKE_SHIELD_FAIL:-0}" = "1" ]; then
      echo '{"type":"error","message":"fake protection failed"}'
      exit 1
    fi
    out=""
    prev=""
    for arg in "$@"; do
      case "$prev" in
        -o|--output) out="$arg" ;;
      esac
      prev="$arg"
    done
    if [ -n "$out" ]; then
      case "$out" in
        *.apk|*.aab|*.apks) : > "$out" ;;
        *) mkdir -p "$out" ;;
      esac
    fi
    echo '{"type":"done"}'
    exit 0
    ;;
  *)
    echo '{"type":"error","message":"unknown command"}'
    exit 2
    ;;
esac
"#;
    fs::write(&path, script).expect("写入 fake CLI");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions).unwrap();
    }
    path
}

fn text(result: &Value) -> String {
    result["content"]
        .as_array()
        .and_then(|items| items.first())
        .and_then(|item| item.get("text"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

#[test]
fn initializes_and_lists_every_shellsmith_tool() {
    let temp = tempfile::tempdir().unwrap();
    let cli = write_fake_cli(temp.path());
    let mut client = McpClient::start(&cli, &[], &[]);

    let init = client.request(
        "initialize",
        json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1"}
        }),
    );
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(init["result"]["serverInfo"]["name"], "shellsmith-mcp");
    assert!(init["result"]["capabilities"]["tools"].is_object());
    client.notify("notifications/initialized", json!({}));

    let list = client.request("tools/list", json!({}));
    let tools = list["result"]["tools"].as_array().expect("tools 数组");
    let names: Vec<&str> = tools
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    for expected in [
        "shellsmith_version",
        "shellsmith_check_apk",
        "shellsmith_check_aab",
        "shellsmith_check_ios",
        "shellsmith_check_keystore",
        "shellsmith_protect_apk",
        "shellsmith_protect_aab",
        "shellsmith_protect_xop",
        "shellsmith_protect_ios",
        "shellsmith_sign_apk",
        "shellsmith_install_apks",
        "shellsmith_read_report",
        "shellsmith_job_status",
        "shellsmith_job_result",
        "shellsmith_job_cancel",
        "shellsmith_job_list",
    ] {
        assert!(names.contains(&expected), "缺少工具 {expected}: {names:?}");
    }
    assert_eq!(tools.len(), 16);

    for tool in tools {
        let schema = &tool["inputSchema"];
        let properties = schema["properties"].as_object().expect("properties");
        assert!(
            !properties.contains_key("ks_pass")
                && !properties.contains_key("password")
                && !properties.contains_key("key_password"),
            "{} 暴露了明文密码字段",
            tool["name"]
        );
    }

    let ping = client.request("ping", json!({}));
    assert_eq!(ping["result"], json!({}));

    let jobs = client.request(
        "tools/call",
        json!({"name": "shellsmith_job_list", "arguments": null}),
    );
    assert_eq!(jobs["result"]["isError"], false, "{jobs}");
    assert!(jobs["result"]["structuredContent"]["jobs"].is_array());
}

#[test]
fn runs_checks_and_enforces_secret_environment() {
    let temp = tempfile::tempdir().unwrap();
    let cli = write_fake_cli(temp.path());
    let apk = temp.path().join("app.apk");
    let keystore = temp.path().join("release.jks");
    fs::write(&apk, b"apk").unwrap();
    fs::write(&keystore, b"ks").unwrap();

    let mut client = McpClient::start(
        &cli,
        &[temp.path()],
        &[("TEST_KS_PASS", SECRET), ("WRONG_KS_PASS", "wrong")],
    );

    let check = client.call(
        "shellsmith_check_apk",
        json!({"path": apk.display().to_string()}),
    );
    assert_eq!(check["isError"], false, "{check}");
    assert_eq!(check["structuredContent"]["is_signed"], true);

    let keystore_check = client.call(
        "shellsmith_check_keystore",
        json!({
            "keystore": keystore.display().to_string(),
            "key_alias": "release",
            "password_env": "TEST_KS_PASS"
        }),
    );
    assert_eq!(keystore_check["isError"], false, "{keystore_check}");
    assert_eq!(
        keystore_check["structuredContent"]["cert_fingerprint"],
        "CC:DD:EE"
    );

    let missing = client.call(
        "shellsmith_check_keystore",
        json!({
            "keystore": keystore.display().to_string(),
            "key_alias": "release",
            "password_env": "MISSING_KS_PASS"
        }),
    );
    assert_eq!(missing["isError"], true, "{missing}");
    assert!(text(&missing).contains("MISSING_KS_PASS"));

    let wrong = client.call(
        "shellsmith_check_keystore",
        json!({
            "keystore": keystore.display().to_string(),
            "key_alias": "release",
            "password_env": "WRONG_KS_PASS"
        }),
    );
    assert_eq!(wrong["isError"], true, "{wrong}");
    assert!(text(&wrong).contains("bad keystore password"));
}

#[test]
fn enforces_allowed_roots() {
    let allowed = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let cli = write_fake_cli(allowed.path());
    let outside_apk = outside.path().join("outside.apk");
    fs::write(&outside_apk, b"apk").unwrap();

    let mut client = McpClient::start(&cli, &[allowed.path()], &[]);
    let result = client.call(
        "shellsmith_check_apk",
        json!({"path": outside_apk.display().to_string()}),
    );
    assert_eq!(result["isError"], true, "{result}");
    assert!(text(&result).contains("不在允许的目录内"));
}

#[cfg(unix)]
#[test]
fn rejects_output_symlink_escape() {
    use std::os::unix::fs::symlink;

    let allowed = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let cli = write_fake_cli(allowed.path());
    let apk = allowed.path().join("app.apk");
    let outside_file = outside.path().join("outside.apk");
    let link = allowed.path().join("escaped.apk");
    fs::write(&apk, b"apk").unwrap();
    fs::write(&outside_file, b"outside").unwrap();
    symlink(&outside_file, &link).unwrap();

    let mut client = McpClient::start(&cli, &[allowed.path()], &[]);
    let result = client.call(
        "shellsmith_protect_xop",
        json!({
            "input": apk.display().to_string(),
            "output": link.display().to_string(),
            "packer": cli.display().to_string(),
            "shell_dir": allowed.path().display().to_string(),
            "allow_unsigned": true,
            "confirm": true
        }),
    );
    assert_eq!(result["isError"], true, "{result}");
    assert!(text(&result).contains("不在允许的目录内"));
    assert_eq!(fs::read(&outside_file).unwrap(), b"outside");
}

#[test]
fn protects_apk_asynchronously_with_progress_and_auto_sign() {
    let temp = tempfile::tempdir().unwrap();
    let cli = write_fake_cli(temp.path());
    let log = temp.path().join("calls.log");
    let apk = temp.path().join("app.apk");
    let output = temp.path().join("app-protected.apk");
    let keystore = temp.path().join("release.jks");
    fs::write(&apk, b"apk").unwrap();
    fs::write(&keystore, b"ks").unwrap();

    let mut client = McpClient::start(
        &cli,
        &[temp.path()],
        &[
            ("TEST_KS_PASS", SECRET),
            ("TEST_KEY_PASS", SECRET),
            ("FAKE_SHIELD_LOG", log.to_str().unwrap()),
            ("FAKE_APK_CERT", "CC:DD:EE"),
            ("FAKE_KS_CERT", "CC:DD:EE"),
        ],
    );

    let start = client.call_with_meta(
        "shellsmith_protect_apk",
        json!({
            "input": apk.display().to_string(),
            "output": output.display().to_string(),
            "profile": "balanced",
            "confirm": true,
            "sign": {
                "keystore": keystore.display().to_string(),
                "key_alias": "release",
                "password_env": "TEST_KS_PASS",
                "key_password_env": "TEST_KEY_PASS",
                "v2": true
            }
        }),
        json!({"progressToken": "protect-1"}),
    );
    assert_eq!(start["isError"], false, "{start}");
    let job_id = start["structuredContent"]["job_id"]
        .as_str()
        .expect("job_id")
        .to_string();
    assert_eq!(start["structuredContent"]["status"], "running");

    let progress = client.wait_for_notification("notifications/progress");
    assert_eq!(progress["params"]["progressToken"], "protect-1");

    let job = client.wait_job(&job_id);
    assert_eq!(job["structuredContent"]["status"], "succeeded", "{job}");
    let expected_output = output
        .parent()
        .unwrap()
        .canonicalize()
        .unwrap()
        .join(output.file_name().unwrap());
    assert_eq!(
        job["structuredContent"]["result"]["output"],
        expected_output.display().to_string()
    );
    assert_eq!(job["structuredContent"]["result"]["signed"], true);

    let logs = fs::read_to_string(&log).unwrap();
    assert!(logs.contains("protect"), "{logs}");
    assert!(logs.contains("sign"), "{logs}");
    assert!(
        logs.contains("--runtime-cert-sha256 CCDDEE"),
        "自动签名必须把绑定证书固定为最终签名证书: {logs}"
    );
    assert!(output.exists(), "自动签名最终产物应存在");
    assert!(!logs.contains(SECRET), "日志不应包含密码: {logs}");
}

#[test]
fn rejects_mismatched_signing_certificate_and_allows_explicit_rebind() {
    let temp = tempfile::tempdir().unwrap();
    let cli = write_fake_cli(temp.path());
    let log = temp.path().join("calls.log");
    let apk = temp.path().join("app.apk");
    let output = temp.path().join("app-protected.apk");
    let keystore = temp.path().join("release.jks");
    fs::write(&apk, b"apk").unwrap();
    fs::write(&keystore, b"ks").unwrap();

    let mut client = McpClient::start(
        &cli,
        &[temp.path()],
        &[
            ("TEST_KS_PASS", SECRET),
            ("TEST_KEY_PASS", SECRET),
            ("FAKE_SHIELD_LOG", log.to_str().unwrap()),
            ("FAKE_APK_CERT", "AA:BB:CC"),
            ("FAKE_KS_CERT", "CC:DD:EE"),
        ],
    );

    let arguments = |runtime_cert: Option<&str>| {
        let mut value = json!({
            "input": apk.display().to_string(),
            "output": output.display().to_string(),
            "confirm": true,
            "sign": {
                "keystore": keystore.display().to_string(),
                "key_alias": "release",
                "password_env": "TEST_KS_PASS",
                "key_password_env": "TEST_KEY_PASS",
                "v2": true
            }
        });
        if let Some(runtime_cert) = runtime_cert {
            value["runtime_cert_sha256"] = json!(runtime_cert);
        }
        value
    };

    let rejected = client.call("shellsmith_protect_apk", arguments(None));
    assert_eq!(rejected["isError"], true, "{rejected}");
    assert!(text(&rejected).contains("不一致"), "{rejected}");
    assert!(!output.exists());

    let conflict = client.call("shellsmith_protect_apk", arguments(Some("AA:BB:CC")));
    assert_eq!(conflict["isError"], true, "{conflict}");
    assert!(text(&conflict).contains("不一致"), "{conflict}");
    assert!(!output.exists());

    let rebound = client.call("shellsmith_protect_apk", arguments(Some("CC:DD:EE")));
    assert_eq!(rebound["isError"], false, "{rebound}");
    let job_id = rebound["structuredContent"]["job_id"].as_str().unwrap();
    let job = client.wait_job(job_id);
    assert_eq!(job["structuredContent"]["status"], "succeeded", "{job}");
    assert!(output.exists());

    let logs = fs::read_to_string(&log).unwrap();
    assert!(
        logs.contains("--runtime-cert-sha256 CCDDEE"),
        "显式重绑定必须固定到最终签名证书: {logs}"
    );
}

#[test]
fn sync_check_does_not_block_job_cancel() {
    let temp = tempfile::tempdir().unwrap();
    let cli = write_fake_cli(temp.path());
    let apk = temp.path().join("app.apk");
    let aab = temp.path().join("app.aab");
    let output = temp.path().join("protected.apk");
    fs::write(&apk, b"apk").unwrap();
    fs::write(&aab, b"aab").unwrap();

    let mut client = McpClient::start(
        &cli,
        &[temp.path()],
        &[("FAKE_SHIELD_SLEEP", "5"), ("FAKE_CHECK_SLEEP", "2")],
    );
    let start = client.call(
        "shellsmith_protect_xop",
        json!({
            "input": apk.display().to_string(),
            "output": output.display().to_string(),
            "packer": cli.display().to_string(),
            "shell_dir": temp.path().display().to_string(),
            "allow_unsigned": true,
            "confirm": true
        }),
    );
    assert_eq!(start["isError"], false, "{start}");
    let job_id = start["structuredContent"]["job_id"].as_str().unwrap();

    let check_id = client.send_request(
        "tools/call",
        json!({
            "name": "shellsmith_check_aab",
            "arguments": {"path": aab.display().to_string()}
        }),
    );
    thread::sleep(Duration::from_millis(150));

    let started = Instant::now();
    let cancelled = client.call("shellsmith_job_cancel", json!({"job_id": job_id}));
    let elapsed = started.elapsed();
    assert_eq!(cancelled["isError"], false, "{cancelled}");
    assert!(
        elapsed < Duration::from_secs(1),
        "同步检查阻塞了取消请求: {elapsed:?}"
    );

    let check = client.response_for(&check_id);
    assert_eq!(check["result"]["isError"], false, "{check}");
    let job = client.wait_job(job_id);
    assert_eq!(job["structuredContent"]["status"], "cancelled", "{job}");
}

#[test]
fn cancellation_works_after_cli_closes_stdout_early() {
    let temp = tempfile::tempdir().unwrap();
    let cli = write_fake_cli(temp.path());
    let apk = temp.path().join("app.apk");
    let output = temp.path().join("closed-stdout.apk");
    fs::write(&apk, b"apk").unwrap();

    let mut client = McpClient::start(
        &cli,
        &[temp.path()],
        &[
            ("FAKE_SHELLSMITH_CLOSE_STDOUT", "1"),
            ("FAKE_SHIELD_SLEEP", "2"),
        ],
    );
    let start = client.call(
        "shellsmith_protect_xop",
        json!({
            "input": apk.display().to_string(),
            "output": output.display().to_string(),
            "packer": cli.display().to_string(),
            "shell_dir": temp.path().display().to_string(),
            "allow_unsigned": true,
            "confirm": true
        }),
    );
    assert_eq!(start["isError"], false, "{start}");
    let job_id = start["structuredContent"]["job_id"].as_str().unwrap();
    thread::sleep(Duration::from_millis(300));

    let started = Instant::now();
    let cancelled = client.call("shellsmith_job_cancel", json!({"job_id": job_id}));
    let elapsed = started.elapsed();
    assert_eq!(cancelled["isError"], false, "{cancelled}");
    assert!(
        elapsed < Duration::from_secs(1),
        "CLI 提前关闭 stdout 后取消被阻塞: {elapsed:?}"
    );
    let job = client.wait_job(job_id);
    assert_eq!(job["structuredContent"]["status"], "cancelled", "{job}");
}

#[test]
fn closing_stdin_cancels_running_jobs() {
    let temp = tempfile::tempdir().unwrap();
    let cli = write_fake_cli(temp.path());
    let apk = temp.path().join("app.apk");
    let output = temp.path().join("late-output.apk");
    fs::write(&apk, b"apk").unwrap();

    let mut client = McpClient::start(&cli, &[temp.path()], &[("FAKE_SHIELD_SLEEP", "2")]);
    let start = client.call(
        "shellsmith_protect_xop",
        json!({
            "input": apk.display().to_string(),
            "output": output.display().to_string(),
            "packer": cli.display().to_string(),
            "shell_dir": temp.path().display().to_string(),
            "allow_unsigned": true,
            "confirm": true
        }),
    );
    assert_eq!(start["isError"], false, "{start}");
    thread::sleep(Duration::from_millis(200));

    client.close_stdin();
    let status = client.wait_exit(Duration::from_secs(5));
    assert!(status.is_some(), "MCP 未在关闭 stdin 后退出");
    thread::sleep(Duration::from_millis(2500));
    assert!(
        !output.exists(),
        "MCP 退出后后台 CLI 仍继续生成输出: {}",
        output.display()
    );
}

#[test]
fn sync_check_times_out_and_kills_cli() {
    let temp = tempfile::tempdir().unwrap();
    let cli = write_fake_cli(temp.path());
    let aab = temp.path().join("app.aab");
    fs::write(&aab, b"aab").unwrap();

    let mut client = McpClient::start(
        &cli,
        &[temp.path()],
        &[
            ("FAKE_CHECK_SLEEP", "3"),
            ("SHELLSMITH_MCP_SYNC_TIMEOUT_SECS", "1"),
        ],
    );
    let started = Instant::now();
    let result = client.call(
        "shellsmith_check_aab",
        json!({"path": aab.display().to_string()}),
    );
    let elapsed = started.elapsed();
    assert_eq!(result["isError"], true, "{result}");
    assert!(text(&result).contains("超时"), "{result}");
    assert!(
        elapsed >= Duration::from_secs(1) && elapsed < Duration::from_secs(3),
        "同步检查超时时间不符合预期: {elapsed:?}"
    );
}

#[test]
fn offline_protect_does_not_inherit_byos_key() {
    let temp = tempfile::tempdir().unwrap();
    let cli = write_fake_cli(temp.path());
    let apk = temp.path().join("app.apk");
    let output = temp.path().join("offline.apk");
    fs::write(&apk, b"apk").unwrap();

    let mut client = McpClient::start(
        &cli,
        &[temp.path()],
        &[
            ("SHELLSMITH_BYOS_API_KEY", "must-not-leak"),
            ("FAKE_REJECT_BYOS", "1"),
        ],
    );
    let start = client.call(
        "shellsmith_protect_apk",
        json!({
            "input": apk.display().to_string(),
            "output": output.display().to_string(),
            "confirm": true
        }),
    );
    assert_eq!(start["isError"], false, "{start}");
    let job_id = start["structuredContent"]["job_id"].as_str().unwrap();
    let job = client.wait_job(job_id);
    assert_eq!(job["structuredContent"]["status"], "succeeded", "{job}");
    assert!(output.exists());
}

#[test]
fn cancels_sign_and_cleans_temporary_directories() {
    let temp = tempfile::tempdir().unwrap();
    let cli = write_fake_cli(temp.path());
    let temp_log = temp.path().join("temp-paths.log");
    let apk = temp.path().join("app.apk");
    let output = temp.path().join("signed.apk");
    let keystore = temp.path().join("release.jks");
    fs::write(&apk, b"apk").unwrap();
    fs::write(&keystore, b"ks").unwrap();

    let mut client = McpClient::start(
        &cli,
        &[temp.path()],
        &[
            ("TEST_KS_PASS", SECRET),
            ("TEST_KEY_PASS", SECRET),
            ("FAKE_TEMP_LOG", temp_log.to_str().unwrap()),
            ("FAKE_SHELLSMITH_LEAVE_TEMP", "1"),
            ("FAKE_SHIELD_SLEEP", "5"),
        ],
    );
    let start = client.call(
        "shellsmith_sign_apk",
        json!({
            "input": apk.display().to_string(),
            "output": output.display().to_string(),
            "keystore": keystore.display().to_string(),
            "key_alias": "release",
            "password_env": "TEST_KS_PASS",
            "key_password_env": "TEST_KEY_PASS",
            "confirm": true
        }),
    );
    assert_eq!(start["isError"], false, "{start}");
    let job_id = start["structuredContent"]["job_id"].as_str().unwrap();

    let deadline = Instant::now() + Duration::from_secs(3);
    while !temp_log.exists() {
        assert!(Instant::now() < deadline, "fake CLI 未创建临时路径记录");
        thread::sleep(Duration::from_millis(20));
    }
    let paths = fs::read_to_string(&temp_log).unwrap();
    let temp_root = paths
        .lines()
        .find_map(|line| line.strip_prefix("TMPDIR="))
        .expect("TMPDIR");
    let stage_root = paths
        .lines()
        .find_map(|line| line.strip_prefix("STAGE="))
        .expect("STAGE");
    assert!(Path::new(temp_root).exists(), "{paths}");
    assert!(Path::new(stage_root).exists(), "{paths}");

    let cancelled = client.call("shellsmith_job_cancel", json!({"job_id": job_id}));
    assert_eq!(cancelled["isError"], false, "{cancelled}");
    let job = client.wait_job(job_id);
    assert_eq!(job["structuredContent"]["status"], "cancelled", "{job}");

    let deadline = Instant::now() + Duration::from_secs(3);
    while Path::new(temp_root).exists() || Path::new(stage_root).exists() {
        assert!(
            Instant::now() < deadline,
            "取消后临时目录未清理: TMPDIR={temp_root} STAGE={stage_root}"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn cancels_running_job_and_kills_cli_subprocess() {
    let temp = tempfile::tempdir().unwrap();
    let cli = write_fake_cli(temp.path());
    let apk = temp.path().join("app.apk");
    let output = temp.path().join("slow.apk");
    fs::write(&apk, b"apk").unwrap();

    let mut client = McpClient::start(&cli, &[temp.path()], &[("FAKE_SHIELD_SLEEP", "5")]);
    let start = client.call(
        "shellsmith_protect_xop",
        json!({
            "input": apk.display().to_string(),
            "output": output.display().to_string(),
            "packer": cli.display().to_string(),
            "shell_dir": temp.path().display().to_string(),
            "allow_unsigned": true,
            "confirm": true
        }),
    );
    assert_eq!(start["isError"], false, "{start}");
    let job_id = start["structuredContent"]["job_id"].as_str().unwrap();

    thread::sleep(Duration::from_millis(200));
    let cancelled = client.call("shellsmith_job_cancel", json!({"job_id": job_id}));
    assert_eq!(cancelled["isError"], false, "{cancelled}");
    assert!(
        ["running", "cancelled"]
            .contains(&cancelled["structuredContent"]["status"].as_str().unwrap()),
        "{cancelled}"
    );

    let job = client.wait_job(job_id);
    assert_eq!(job["structuredContent"]["status"], "cancelled", "{job}");
}

#[test]
fn signs_in_place_only_with_explicit_allow_in_place() {
    let temp = tempfile::tempdir().unwrap();
    let cli = write_fake_cli(temp.path());
    let log = temp.path().join("sign.log");
    let apk = temp.path().join("app.apk");
    let keystore = temp.path().join("release.jks");
    fs::write(&apk, b"apk").unwrap();
    fs::write(&keystore, b"ks").unwrap();

    let mut client = McpClient::start(
        &cli,
        &[temp.path()],
        &[
            ("TEST_KS_PASS", SECRET),
            ("FAKE_SHIELD_LOG", log.to_str().unwrap()),
        ],
    );

    let rejected = client.call(
        "shellsmith_sign_apk",
        json!({
            "input": apk.display().to_string(),
            "keystore": keystore.display().to_string(),
            "key_alias": "release",
            "password_env": "TEST_KS_PASS",
            "confirm": true
        }),
    );
    assert_eq!(rejected["isError"], true, "{rejected}");
    assert!(text(&rejected).contains("allow_in_place"), "{rejected}");

    let start = client.call(
        "shellsmith_sign_apk",
        json!({
            "input": apk.display().to_string(),
            "keystore": keystore.display().to_string(),
            "key_alias": "release",
            "password_env": "TEST_KS_PASS",
            "allow_in_place": true,
            "confirm": true
        }),
    );
    assert_eq!(start["isError"], false, "{start}");
    let job_id = start["structuredContent"]["job_id"].as_str().unwrap();
    let job = client.wait_job(job_id);
    assert_eq!(job["structuredContent"]["status"], "succeeded", "{job}");

    let canonical_apk = apk
        .parent()
        .unwrap()
        .canonicalize()
        .unwrap()
        .join("app.apk");
    assert_eq!(
        job["structuredContent"]["result"]["output"],
        canonical_apk.display().to_string()
    );
    let calls = fs::read_to_string(&log).unwrap();
    assert!(
        calls.contains(&format!("-o {}", canonical_apk.display())),
        "原地签名必须把输入路径同时作为输出传给 CLI: {calls}"
    );
}

#[test]
fn reports_failed_jobs_and_hides_result_until_terminal() {
    let temp = tempfile::tempdir().unwrap();
    let cli = write_fake_cli(temp.path());
    let apk = temp.path().join("app.apk");
    let output = temp.path().join("failed.apk");
    fs::write(&apk, b"apk").unwrap();

    let mut client = McpClient::start(
        &cli,
        &[temp.path()],
        &[("FAKE_SHIELD_FAIL", "1"), ("FAKE_SHIELD_SLEEP", "0.3")],
    );
    let start = client.call(
        "shellsmith_protect_xop",
        json!({
            "input": apk.display().to_string(),
            "output": output.display().to_string(),
            "packer": cli.display().to_string(),
            "shell_dir": temp.path().display().to_string(),
            "allow_unsigned": true,
            "confirm": true
        }),
    );
    assert_eq!(start["isError"], false, "{start}");
    let job_id = start["structuredContent"]["job_id"].as_str().unwrap();

    let running = client.call("shellsmith_job_result", json!({"job_id": job_id}));
    assert_eq!(running["isError"], true, "{running}");
    assert!(text(&running).contains("仍在运行"));

    let job = client.wait_job(job_id);
    assert_eq!(job["structuredContent"]["status"], "failed", "{job}");
    assert!(
        job["structuredContent"]["error"]
            .as_str()
            .unwrap_or_default()
            .contains("fake protection failed"),
        "{job}"
    );
    assert!(!output.exists());
}

#[test]
fn rejects_destructive_calls_without_confirmation() {
    let temp = tempfile::tempdir().unwrap();
    let cli = write_fake_cli(temp.path());
    let apk = temp.path().join("app.apk");
    let output = temp.path().join("out.apk");
    fs::write(&apk, b"apk").unwrap();

    let mut client = McpClient::start(&cli, &[temp.path()], &[]);
    let result = client.call(
        "shellsmith_protect_apk",
        json!({
            "input": apk.display().to_string(),
            "output": output.display().to_string()
        }),
    );
    assert_eq!(result["isError"], true, "{result}");
    assert!(text(&result).contains("confirm=true"), "{result}");
    assert!(!output.exists());
}

#[test]
fn reads_reports_and_rejects_non_json() {
    let temp = tempfile::tempdir().unwrap();
    let cli = write_fake_cli(temp.path());
    let report = temp.path().join("app.apk.protection.json");
    fs::write(
        &report,
        serde_json::to_vec(&json!({
            "schema_version": 2,
            "image_version": "1.10.1",
            "build": {"id": "test"},
            "output_sha256": "abc",
            "methods": [1, 2, 3],
            "dexes": [{"name": "classes.dex"}],
            "native_vmp": null
        }))
        .unwrap(),
    )
    .unwrap();

    let mut client = McpClient::start(&cli, &[temp.path()], &[]);
    let summary = client.call(
        "shellsmith_read_report",
        json!({"path": report.display().to_string()}),
    );
    assert_eq!(summary["isError"], false, "{summary}");
    assert_eq!(summary["structuredContent"]["methods"], 3);
    assert_eq!(summary["structuredContent"]["schema_version"], 2);

    let full = client.call(
        "shellsmith_read_report",
        json!({"path": report.display().to_string(), "mode": "full"}),
    );
    assert_eq!(full["structuredContent"]["output_sha256"], "abc");

    let invalid = client.call(
        "shellsmith_read_report",
        json!({"path": report.display().to_string(), "mode": "raw"}),
    );
    assert_eq!(invalid["isError"], true, "{invalid}");
}
