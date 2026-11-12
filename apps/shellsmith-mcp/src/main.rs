mod jobs;
mod protocol;
mod tools;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;

/// Shellsmith 的本地 Model Context Protocol 服务。
///
/// 通过 stdio 提供 JSON-RPC；所有加固、签名、检查与安装动作都委托给本机
/// `shield` CLI 执行，不上传 APK、AAB、证书或报告。
#[derive(Debug, Parser)]
#[command(name = "shellsmith-mcp", version, about)]
struct Args {
    /// shellsmith/shield CLI 可执行文件；默认先找同目录的 shield，再找 PATH。
    #[arg(long, env = "SHELLSMITH_MCP_CLI", value_name = "PATH")]
    cli: Option<PathBuf>,

    /// 允许工具读写的工作目录；可重复。未配置时不限制路径。
    #[arg(long = "allow-root", value_name = "DIR")]
    allow_roots: Vec<PathBuf>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("shellsmith-mcp: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = Args::parse();
    let mut roots = args.allow_roots;
    if let Ok(value) = std::env::var("SHELLSMITH_MCP_ALLOWED_ROOTS") {
        roots.extend(std::env::split_paths(&value));
    }
    let roots = roots
        .into_iter()
        .map(|root| root.canonicalize().unwrap_or(root))
        .collect();
    let server = Arc::new(jobs::Server::new(
        args.cli.unwrap_or_else(default_cli),
        roots,
    ));
    protocol::serve(server)
}

fn default_cli() -> PathBuf {
    let name = if cfg!(windows) {
        "shield.exe"
    } else {
        "shield"
    };
    if let Ok(executable) = std::env::current_exe() {
        if let Some(directory) = executable.parent() {
            let sibling = directory.join(name);
            if sibling.is_file() {
                return sibling;
            }
        }
    }
    PathBuf::from(name)
}
