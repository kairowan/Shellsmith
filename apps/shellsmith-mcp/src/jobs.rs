use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, VecDeque};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tempfile::TempDir;

const MAX_JOB_LOGS: usize = 200;
const MAX_JOBS: usize = 200;
const DEFAULT_SYNC_TIMEOUT_SECS: u64 = 600;
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
const SENSITIVE_ENV: &[&str] = &[
    "SHELLSMITH_BYOS_API_KEY",
    "MOCIKA_SHIELD_KS_PASS",
    "MOCIKA_SHIELD_KEY_PASS",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

#[derive(Clone, Serialize)]
pub struct JobSnapshot {
    pub job_id: String,
    pub tool: String,
    pub status: JobStatus,
    pub message: String,
    pub progress: u64,
    pub logs: Vec<String>,
    pub result: Option<Value>,
    pub error: Option<String>,
    pub started_at_ms: u64,
    pub finished_at_ms: Option<u64>,
}

pub struct Job {
    id: String,
    tool: String,
    status: JobStatus,
    message: String,
    progress: u64,
    logs: VecDeque<String>,
    result: Option<Value>,
    error: Option<String>,
    started_at_ms: u64,
    finished_at_ms: Option<u64>,
    cancel: Arc<AtomicBool>,
    child: Option<Child>,
    progress_token: Option<Value>,
    done: Arc<AtomicBool>,
}

impl Job {
    fn snapshot(&self) -> JobSnapshot {
        JobSnapshot {
            job_id: self.id.clone(),
            tool: self.tool.clone(),
            status: self.status,
            message: self.message.clone(),
            progress: self.progress,
            logs: self.logs.iter().cloned().collect(),
            result: self.result.clone(),
            error: self.error.clone(),
            started_at_ms: self.started_at_ms,
            finished_at_ms: self.finished_at_ms,
        }
    }

    fn push_log(&mut self, line: impl Into<String>) {
        self.logs.push_back(line.into());
        while self.logs.len() > MAX_JOB_LOGS {
            self.logs.pop_front();
        }
    }

    fn finish(&mut self, status: JobStatus, message: String) {
        self.status = status;
        self.message = message;
        self.finished_at_ms = Some(now_ms());
        self.child = None;
    }
}

pub struct CommandPlan {
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub label: String,
}

pub struct JobPlan {
    pub commands: Vec<CommandPlan>,
    pub result: Value,
    /// 自动签名等流程的临时目录，必须活到任务结束。
    pub keep: Vec<TempDir>,
}

pub struct Server {
    pub cli: PathBuf,
    pub allowed_roots: Vec<PathBuf>,
    pub out: Arc<Mutex<BufWriter<std::io::Stdout>>>,
    jobs: Mutex<BTreeMap<String, Arc<Mutex<Job>>>>,
    next_id: AtomicU64,
    shutting_down: AtomicBool,
    sync_active: AtomicUsize,
}

impl Server {
    pub fn new(cli: PathBuf, allowed_roots: Vec<PathBuf>) -> Self {
        Self {
            cli,
            allowed_roots,
            out: Arc::new(Mutex::new(BufWriter::new(std::io::stdout()))),
            jobs: Mutex::new(BTreeMap::new()),
            next_id: AtomicU64::new(1),
            shutting_down: AtomicBool::new(false),
            sync_active: AtomicUsize::new(0),
        }
    }

    pub fn write_json(&self, value: &Value) {
        let Ok(mut out) = self.out.lock() else {
            return;
        };
        if serde_json::to_writer(&mut *out, value).is_ok() {
            let _ = out.write_all(b"\n");
            let _ = out.flush();
        }
    }

    pub fn start_job(
        self: &Arc<Self>,
        tool: impl Into<String>,
        plan: JobPlan,
        progress_token: Option<Value>,
    ) -> Result<String> {
        if self.shutting_down.load(Ordering::SeqCst) {
            anyhow::bail!("MCP 服务正在关闭，无法创建新任务");
        }
        let id = format!(
            "job-{}-{}",
            now_ms(),
            self.next_id.fetch_add(1, Ordering::Relaxed)
        );
        let done = Arc::new(AtomicBool::new(false));
        let job = Arc::new(Mutex::new(Job {
            id: id.clone(),
            tool: tool.into(),
            status: JobStatus::Running,
            message: "任务已创建".to_string(),
            progress: 0,
            logs: VecDeque::new(),
            result: None,
            error: None,
            started_at_ms: now_ms(),
            finished_at_ms: None,
            cancel: Arc::new(AtomicBool::new(false)),
            child: None,
            progress_token,
            done: Arc::clone(&done),
        }));
        let mut jobs = self
            .jobs
            .lock()
            .map_err(|_| anyhow::anyhow!("任务表锁不可用"))?;
        if self.shutting_down.load(Ordering::SeqCst) {
            anyhow::bail!("MCP 服务正在关闭，无法创建新任务");
        }
        if jobs.len() >= MAX_JOBS {
            let finished = jobs
                .iter()
                .find(|(_, job)| {
                    job.lock()
                        .map(|job| job.status != JobStatus::Running)
                        .unwrap_or(true)
                })
                .map(|(id, _)| id.clone());
            if let Some(id) = finished {
                jobs.remove(&id);
            }
        }
        jobs.insert(id.clone(), Arc::clone(&job));
        drop(jobs);
        let server = Arc::clone(self);
        thread::spawn(move || run_job(server, job, plan, done));
        Ok(id)
    }

    pub fn job_status(&self, id: &str) -> Option<JobSnapshot> {
        self.jobs
            .lock()
            .ok()
            .and_then(|jobs| jobs.get(id).cloned())
            .and_then(|job| job.lock().ok().map(|job| job.snapshot()))
    }

    pub fn job_list(&self) -> Vec<JobSnapshot> {
        let jobs = self
            .jobs
            .lock()
            .map(|jobs| jobs.values().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        jobs.into_iter()
            .filter_map(|job| job.lock().ok().map(|job| job.snapshot()))
            .collect()
    }

    pub fn cancel_job(&self, id: &str) -> Option<JobSnapshot> {
        let job = self
            .jobs
            .lock()
            .ok()
            .and_then(|jobs| jobs.get(id).cloned())?;
        let mut job = job.lock().ok()?;
        if job.status != JobStatus::Running {
            return Some(job.snapshot());
        }
        job.cancel.store(true, Ordering::SeqCst);
        job.message = "取消请求已发送".to_string();
        if let Some(child) = job.child.as_mut() {
            kill_tree(child);
        }
        Some(job.snapshot())
    }

    /// 停止接收新任务，取消并回收所有活动任务与同步检查。
    pub fn shutdown(&self) {
        self.shutting_down.store(true, Ordering::SeqCst);
        let jobs = self
            .jobs
            .lock()
            .map(|jobs| jobs.values().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        for job in &jobs {
            if let Ok(mut job) = job.lock() {
                if job.status == JobStatus::Running {
                    job.cancel.store(true, Ordering::SeqCst);
                    job.message = "MCP 服务关闭，取消任务".to_string();
                    if let Some(child) = job.child.as_mut() {
                        kill_tree(child);
                    }
                }
            }
        }
        let deadline = Instant::now() + SHUTDOWN_TIMEOUT;
        loop {
            let jobs_done = jobs.iter().all(|job| {
                job.lock()
                    .map(|job| job.done.load(Ordering::SeqCst))
                    .unwrap_or(true)
            });
            if jobs_done && self.sync_active.load(Ordering::SeqCst) == 0 {
                break;
            }
            if Instant::now() >= deadline {
                for job in &jobs {
                    if let Ok(mut job) = job.lock() {
                        if let Some(child) = job.child.as_mut() {
                            kill_tree(child);
                        }
                    }
                }
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    pub fn run_sync(&self, args: &[String], env: &[(String, String)]) -> Result<Value> {
        if self.shutting_down.load(Ordering::SeqCst) {
            anyhow::bail!("MCP 服务正在关闭");
        }
        let _active = SyncActiveGuard::new(&self.sync_active);
        let sync_temp = tempfile::Builder::new()
            .prefix("shellsmith-mcp-sync-")
            .tempdir()
            .context("创建 MCP 同步检查临时目录失败")?;
        let mut process = Command::new(&self.cli);
        process
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        set_cli_working_dir(&mut process, &self.cli);
        apply_sanitized_env(&mut process, env);
        add_temp_env(&mut process, sync_temp.path());
        let mut child = process
            .spawn()
            .with_context(|| format!("启动 Shellsmith CLI 失败: {}", self.cli.display()))?;
        let stdout = child
            .stdout
            .take()
            .context("Shellsmith CLI stdout 不可用")?;
        let stderr = child
            .stderr
            .take()
            .context("Shellsmith CLI stderr 不可用")?;
        let stdout_text = Arc::new(Mutex::new(String::new()));
        let stderr_text = Arc::new(Mutex::new(String::new()));
        let stdout_done = Arc::new(AtomicBool::new(false));
        let stderr_done = Arc::new(AtomicBool::new(false));
        let stdout_buffer = Arc::clone(&stdout_text);
        let stdout_flag = Arc::clone(&stdout_done);
        thread::spawn(move || {
            let mut text = String::new();
            let mut reader = BufReader::new(stdout);
            let _ = reader.read_to_string(&mut text);
            if let Ok(mut buffer) = stdout_buffer.lock() {
                *buffer = text;
            }
            stdout_flag.store(true, Ordering::SeqCst);
        });
        let stderr_buffer = Arc::clone(&stderr_text);
        let stderr_flag = Arc::clone(&stderr_done);
        thread::spawn(move || {
            let mut text = String::new();
            let mut reader = BufReader::new(stderr);
            let _ = reader.read_to_string(&mut text);
            if let Ok(mut buffer) = stderr_buffer.lock() {
                *buffer = text;
            }
            stderr_flag.store(true, Ordering::SeqCst);
        });
        let timeout = sync_timeout();
        let deadline = Instant::now() + timeout;
        let status = loop {
            if self.shutting_down.load(Ordering::SeqCst) {
                kill_tree(&mut child);
                let _ = child.wait();
                anyhow::bail!("MCP 服务正在关闭，已终止 Shellsmith CLI");
            }
            match child.try_wait().context("等待 Shellsmith CLI 失败")? {
                Some(status) => break status,
                None => {
                    if Instant::now() >= deadline {
                        kill_tree(&mut child);
                        let _ = child.wait();
                        anyhow::bail!("Shellsmith CLI 检查超时（{} 秒）", timeout.as_secs());
                    }
                    thread::sleep(Duration::from_millis(50));
                }
            }
        };
        let drain_deadline = Instant::now() + Duration::from_millis(500);
        while (!stdout_done.load(Ordering::SeqCst) || !stderr_done.load(Ordering::SeqCst))
            && Instant::now() < drain_deadline
        {
            thread::sleep(Duration::from_millis(10));
        }
        let stdout = stdout_text
            .lock()
            .map(|text| text.clone())
            .unwrap_or_default();
        let stderr = stderr_text
            .lock()
            .map(|text| text.clone())
            .unwrap_or_default();
        if !status.success() {
            anyhow::bail!(
                "Shellsmith CLI 退出码 {}：{}",
                status.code().unwrap_or(-1),
                if stderr.trim().is_empty() {
                    stdout.trim()
                } else {
                    stderr.trim()
                }
            );
        }
        parse_json_output(stdout.as_bytes())
    }

    pub fn resolve_input(&self, value: &str, label: &str) -> Result<PathBuf> {
        let path = absolute_path(value)?;
        let canonical = path
            .canonicalize()
            .with_context(|| format!("{label}不存在或无法访问: {}", path.display()))?;
        self.ensure_allowed(&canonical, label)?;
        Ok(canonical)
    }

    pub fn resolve_output(&self, value: &str, label: &str) -> Result<PathBuf> {
        let path = absolute_path(value)?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent = parent
            .canonicalize()
            .with_context(|| format!("{label}的父目录不存在或不可访问: {}", parent.display()))?;
        let name = path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("{label}缺少文件名: {}", path.display()))?;
        let output = parent.join(name);
        self.ensure_allowed(&output, label)?;
        if output.exists() {
            let canonical = output
                .canonicalize()
                .with_context(|| format!("{label}无法解析: {}", output.display()))?;
            self.ensure_allowed(&canonical, label)?;
        }
        Ok(output)
    }

    pub fn ensure_allowed(&self, path: &Path, label: &str) -> Result<()> {
        if self.allowed_roots.is_empty() {
            return Ok(());
        }
        for root in &self.allowed_roots {
            let root = root.canonicalize().unwrap_or_else(|_| root.clone());
            if path.starts_with(&root) {
                return Ok(());
            }
        }
        anyhow::bail!(
            "{label}不在允许的目录内: {}；请通过 --allow-root 或 SHELLSMITH_MCP_ALLOWED_ROOTS 配置",
            path.display()
        )
    }
}

fn run_job(server: Arc<Server>, job: Arc<Mutex<Job>>, plan: JobPlan, done: Arc<AtomicBool>) {
    let _done = DoneGuard(done);
    let _keep = plan.keep;
    // MCP 持有任务私有 TMPDIR；取消时即使用 SIGKILL，也能在回收后删除 CLI 的口令临时目录。
    let job_temp = match tempfile::Builder::new()
        .prefix("shellsmith-mcp-job-")
        .tempdir()
    {
        Ok(temp) => temp,
        Err(error) => {
            finish_job(
                &job,
                JobStatus::Failed,
                format!("创建 MCP 任务临时目录失败: {error}"),
                None,
                Some(error.to_string()),
            );
            return;
        }
    };
    for command in plan.commands {
        if job
            .lock()
            .map(|job| job.cancel.load(Ordering::SeqCst))
            .unwrap_or(true)
        {
            finish_job(
                &job,
                JobStatus::Cancelled,
                "任务已取消".to_string(),
                None,
                None,
            );
            return;
        }
        update_job(&job, |job| {
            job.message = command.label.clone();
            job.push_log(format!("▶ {}", command.label));
        });

        let mut process = Command::new(&server.cli);
        process
            .args(&command.args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        set_cli_working_dir(&mut process, &server.cli);
        apply_sanitized_env(&mut process, &command.env);
        add_temp_env(&mut process, job_temp.path());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            process.process_group(0);
        }
        let mut child = match process.spawn() {
            Ok(child) => child,
            Err(error) => {
                finish_job(
                    &job,
                    JobStatus::Failed,
                    format!("启动 Shellsmith CLI 失败: {error}"),
                    None,
                    Some(error.to_string()),
                );
                return;
            }
        };
        let Some(stdout) = child.stdout.take() else {
            finish_job(
                &job,
                JobStatus::Failed,
                "Shellsmith CLI stdout 不可用".to_string(),
                None,
                Some("stdout unavailable".to_string()),
            );
            return;
        };
        let stderr = child.stderr.take();
        {
            if let Ok(mut job) = job.lock() {
                job.child = Some(child);
            }
        }
        let stderr_output = Arc::new(Mutex::new(String::new()));
        let stderr_buffer = Arc::clone(&stderr_output);
        let _stderr_thread = stderr.map(move |mut stderr| {
            thread::spawn(move || {
                let mut text = String::new();
                let _ = stderr.read_to_string(&mut text);
                if let Ok(mut buffer) = stderr_buffer.lock() {
                    *buffer = text;
                }
            })
        });
        let (line_tx, line_rx) = mpsc::channel::<String>();
        thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                match line {
                    Ok(line) => {
                        if line_tx.send(line).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
        let mut last_error = None;
        let mut exited_status = None;
        loop {
            match line_rx.recv_timeout(Duration::from_millis(200)) {
                Ok(line) => record_output_line(&server, &job, &line, &mut last_error),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    let cancelled = job
                        .lock()
                        .map(|job| job.cancel.load(Ordering::SeqCst))
                        .unwrap_or(true);
                    if cancelled {
                        break;
                    }
                    let exited = {
                        let Ok(mut guard) = job.lock() else {
                            break;
                        };
                        match guard.child.as_mut() {
                            Some(child) => match child.try_wait() {
                                Ok(Some(status)) => {
                                    guard.child.take();
                                    Some(status)
                                }
                                Ok(None) => None,
                                Err(_) => None,
                            },
                            None => None,
                        }
                    };
                    if let Some(status) = exited {
                        exited_status = Some(status);
                        // 孙子进程可能仍持有 stdout；给已退出 CLI 的尾部输出留出短暂排空窗口。
                        while let Ok(line) = line_rx.recv_timeout(Duration::from_millis(50)) {
                            record_output_line(&server, &job, &line, &mut last_error);
                        }
                        break;
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        thread::sleep(Duration::from_millis(50));
        let stderr_text = stderr_output
            .lock()
            .map(|text| text.clone())
            .unwrap_or_default();
        if !stderr_text.trim().is_empty() {
            update_job(&job, |job| job.push_log(stderr_text.trim().to_string()));
        }
        let status = if let Some(status) = exited_status {
            status
        } else {
            match wait_for_child(&job) {
                Ok(ChildOutcome::Exited(status)) => status,
                Ok(ChildOutcome::Cancelled) => {
                    cancel_and_reap(&job);
                    finish_job(
                        &job,
                        JobStatus::Cancelled,
                        "任务已取消".to_string(),
                        None,
                        None,
                    );
                    return;
                }
                Err(error) => {
                    cancel_and_reap(&job);
                    finish_job(
                        &job,
                        JobStatus::Failed,
                        format!("等待 Shellsmith CLI 失败: {error}"),
                        None,
                        Some(error.to_string()),
                    );
                    return;
                }
            }
        };
        let cancelled = job
            .lock()
            .map(|job| job.cancel.load(Ordering::SeqCst))
            .unwrap_or(false);
        if !status.success() {
            if cancelled {
                finish_job(
                    &job,
                    JobStatus::Cancelled,
                    "任务已取消".to_string(),
                    None,
                    None,
                );
            } else {
                let message = last_error
                    .filter(|message| !message.trim().is_empty())
                    .unwrap_or_else(|| {
                        if stderr_text.trim().is_empty() {
                            format!("Shellsmith CLI 退出码 {}", status.code().unwrap_or(-1))
                        } else {
                            stderr_text.trim().to_string()
                        }
                    });
                finish_job(
                    &job,
                    JobStatus::Failed,
                    message.clone(),
                    None,
                    Some(message),
                );
            }
            return;
        }
        if cancelled {
            finish_job(
                &job,
                JobStatus::Cancelled,
                "任务已取消".to_string(),
                None,
                None,
            );
            return;
        }
    }

    finish_job(
        &job,
        JobStatus::Succeeded,
        "任务完成".to_string(),
        Some(plan.result),
        None,
    );
}

struct DoneGuard(Arc<AtomicBool>);

impl Drop for DoneGuard {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

struct SyncActiveGuard<'a>(&'a AtomicUsize);

impl<'a> SyncActiveGuard<'a> {
    fn new(counter: &'a AtomicUsize) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        Self(counter)
    }
}

impl Drop for SyncActiveGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

enum ChildOutcome {
    Exited(ExitStatus),
    Cancelled,
}

fn wait_for_child(job: &Arc<Mutex<Job>>) -> Result<ChildOutcome> {
    loop {
        let status = {
            let mut guard = job
                .lock()
                .map_err(|_| anyhow::anyhow!("任务状态锁不可用"))?;
            if guard.cancel.load(Ordering::SeqCst) {
                return Ok(ChildOutcome::Cancelled);
            }
            match guard.child.as_mut() {
                Some(child) => match child.try_wait().context("等待 Shellsmith CLI 失败")? {
                    Some(status) => {
                        guard.child.take();
                        Some(status)
                    }
                    None => None,
                },
                None => anyhow::bail!("Shellsmith CLI 子进程状态丢失"),
            }
        };
        if let Some(status) = status {
            return Ok(ChildOutcome::Exited(status));
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn cancel_and_reap(job: &Arc<Mutex<Job>>) {
    let child = job.lock().ok().and_then(|mut job| job.child.take());
    if let Some(mut child) = child {
        kill_tree(&mut child);
        let _ = child.wait();
    }
}

fn apply_sanitized_env(process: &mut Command, env: &[(String, String)]) {
    for key in SENSITIVE_ENV {
        process.env_remove(key);
    }
    process.envs(env.iter().cloned());
}

fn set_cli_working_dir(process: &mut Command, cli: &Path) {
    if let Some(parent) = cli.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        process.current_dir(parent);
    }
}

fn add_temp_env(process: &mut Command, root: &Path) {
    let root = root.to_string_lossy().into_owned();
    process
        .env("TMPDIR", &root)
        .env("TMP", &root)
        .env("TEMP", &root);
}

fn sync_timeout() -> Duration {
    std::env::var("SHELLSMITH_MCP_SYNC_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|seconds| *seconds > 0)
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(DEFAULT_SYNC_TIMEOUT_SECS))
}

fn kill_tree(child: &mut Child) {
    #[cfg(unix)]
    {
        let pid = child.id() as i32;
        if pid > 0 {
            // 子进程以独立进程组启动；负 pid 终止整个 CLI → java/apktool/apksigner 树。
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let pid = child.id().to_string();
        let _ = Command::new("taskkill")
            .args(["/PID", pid.as_str(), "/T", "/F"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .status();
    }
    let _ = child.kill();
}

fn record_output_line(
    server: &Server,
    job: &Arc<Mutex<Job>>,
    line: &str,
    last_error: &mut Option<String>,
) {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return;
    }
    update_job(job, |job| {
        job.progress += 1;
        job.push_log(trimmed.to_string());
        if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
            if value.get("type").and_then(Value::as_str) == Some("progress") {
                if let Some(message) = value.get("message").and_then(Value::as_str) {
                    job.message = message.to_string();
                }
            }
            if value.get("type").and_then(Value::as_str) == Some("error") {
                *last_error = value
                    .get("message")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
            }
        }
    });
    notify_progress(server, job);
}

fn update_job(job: &Arc<Mutex<Job>>, update: impl FnOnce(&mut Job)) {
    if let Ok(mut job) = job.lock() {
        update(&mut job);
    }
}

fn finish_job(
    job: &Arc<Mutex<Job>>,
    status: JobStatus,
    message: String,
    result: Option<Value>,
    error: Option<String>,
) {
    if let Ok(mut job) = job.lock() {
        job.result = result;
        job.error = error;
        job.finish(status, message);
    }
}

fn notify_progress(server: &Server, job: &Arc<Mutex<Job>>) {
    let Ok(job) = job.lock() else {
        return;
    };
    let Some(token) = &job.progress_token else {
        return;
    };
    let payload = json!({
        "jsonrpc": "2.0",
        "method": "notifications/progress",
        "params": {
            "progressToken": token,
            "progress": job.progress,
            "message": job.message,
        }
    });
    drop(job);
    server.write_json(&payload);
}

fn parse_json_output(bytes: &[u8]) -> Result<Value> {
    let text = String::from_utf8_lossy(bytes);
    for line in text.lines().rev() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<Value>(line) {
            return Ok(value);
        }
    }
    Ok(Value::String(text.trim().to_string()))
}

fn absolute_path(value: &str) -> Result<PathBuf> {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        return Ok(path);
    }
    Ok(std::env::current_dir()?.join(path))
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
