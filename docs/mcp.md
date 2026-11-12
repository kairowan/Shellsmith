# Shellsmith MCP Server

`apps/shellsmith-mcp` 把本机 `shield` CLI 的全部加固、签名、检查、报告和 APKS 安装能力包装成 [Model Context Protocol](https://modelcontextprotocol.io/) 工具。它不包含自己的 Agent、模型调用或 UI，也不复制加固核心逻辑；每次工具调用都委托给同一台机器上的 `shield` 可执行文件。

- 默认传输：本地 stdio（逐行 JSON-RPC 2.0）
- 默认网络：除 BYOS 和你显式传入的远端服务外，不上传 APK、AAB、证书、密码或报告
- 工具参数：不接受明文密码，只接受环境变量名
- 长任务：立即返回 `job_id`，通过 `shellsmith_job_status` / `shellsmith_job_result` / `shellsmith_job_cancel` 管理
- 破坏性操作：必须显式传 `confirm: true`

## 从 GitHub Releases 安装

发布页的 `Shellsmith-cli-<version>-<platform>` 包同时包含 `shield` 和 `shellsmith-mcp`。Release 发布后由 `CLI and MCP Release Bundles` 工作流自动构建并上传。

1. 下载对应平台的 `.tar.gz`（Linux/macOS）或 `.zip`（Windows）并解压；
2. 直接运行 `bin/shellsmith-mcp --allow-root /path/to/projects`；
3. 不需要额外指定 `--cli`：MCP 会优先查找同目录的 `shield`，找不到时再查 `PATH`。

MCP 客户端配置示例：

```json
{
  "mcpServers": {
    "shellsmith": {
      "command": "/absolute/path/to/bin/shellsmith-mcp",
      "args": ["--allow-root", "/absolute/path/to/projects"]
    }
  }
}
```

发布包中的 `README.md` 也包含同样的配置。密码仍然只从启动环境读取，不要把明文密码写进客户端 JSON。

## 构建与启动

```bash
cargo build --release -p shellsmith-mcp
./target/release/shellsmith-mcp \
  --cli /path/to/shield \
  --allow-root /path/to/your/projects
```

参数：

| 参数 | 环境变量 | 说明 |
|---|---|---|
| `--cli PATH` | `SHELLSMITH_MCP_CLI` | `shield` 可执行文件；默认先找同目录，再查 `PATH` |
| `--allow-root DIR` | `SHELLSMITH_MCP_ALLOWED_ROOTS` | 允许读写的目录，可重复；未配置时不限制路径。环境变量使用平台路径分隔符 |

服务启动后从 stdin 读取 MCP 消息，向 stdout 写响应；诊断信息只写 stderr。

## 客户端配置

以 Claude Desktop / Claude Code 一类支持 stdio MCP 的客户端为例：

```json
{
  "mcpServers": {
    "shellsmith": {
      "command": "/opt/Shellsmith/bin/shellsmith-mcp",
      "args": [
        "--cli", "/opt/Shellsmith/bin/shield",
        "--allow-root", "/Users/me/android-projects"
      ]
    }
  }
}
```

密钥不要写进工具参数。启动 MCP 前通过操作系统环境、keychain、secret manager 或启动包装脚本注入：

```bash
export MOCIKA_SHIELD_KS_PASS="$(security find-generic-password -s shellsmith-ks -w)"
export MOCIKA_SHIELD_KEY_PASS="$(security find-generic-password -s shellsmith-key -w)"
exec /opt/Shellsmith/bin/shellsmith-mcp --allow-root "$HOME/projects"
```

然后把环境变量名传给工具：

```json
{
  "keystore": "/secure/release.jks",
  "key_alias": "release",
  "password_env": "MOCIKA_SHIELD_KS_PASS",
  "key_password_env": "MOCIKA_SHIELD_KEY_PASS"
}
```

支持的环境变量：

| 变量 | 用途 |
|---|---|
| `MOCIKA_SHIELD_KS_PASS` | keystore 密码默认值 |
| `MOCIKA_SHIELD_KEY_PASS` | key 密码；省略时沿用 keystore 密码 |
| `SHELLSMITH_BYOS_API_KEY` | BYOS 构建端 API key |
| `SHELLSMITH_MCP_CLI` | 默认 `shield` 路径 |
| `SHELLSMITH_MCP_ALLOWED_ROOTS` | 默认允许目录列表 |

## 工具清单

同步工具直接返回 CLI 的 JSON 结果；异步工具返回 `{ "job_id": "...", "status": "running" }`。

| 工具 | 类型 | 说明 |
|---|---|---|
| `shellsmith_version` | 同步 | 返回 CLI 版本与 MCP 版本 |
| `shellsmith_check_apk` | 同步 | 检查 APK 是否已加固、签名状态、证书指纹和 ABI |
| `shellsmith_check_aab` | 同步 | 检查 AAB 模块；可用 bundletool 校验并生成 APKS |
| `shellsmith_check_ios` | 同步 | 检查 Xcode 工程、scheme 与签名配置，不修改工程 |
| `shellsmith_check_keystore` | 同步 | 读取 keystore alias 的 SHA-256 证书指纹 |
| `shellsmith_protect_apk` | 异步 | 加固 APK；可在同一任务里自动签名 |
| `shellsmith_protect_aab` | 异步 | 加固并重建/签名 AAB，支持 Mocika 或 XOP 引擎 |
| `shellsmith_protect_xop` | 异步 | 使用 XOP 单壳加固 APK，可签名或输出未签名中间包 |
| `shellsmith_protect_ios` | 异步 | 在独立工作副本中接入 iOS 保护并归档导出 |
| `shellsmith_sign_apk` | 异步 | 按 v1/v2/v3/v4 签名 APK |
| `shellsmith_install_apks` | 异步 | 用 bundletool 把 APKS 安装到连接的测试设备 |
| `shellsmith_read_report` | 同步 | 读取 `*.protection.json`，支持 `summary` / `full` |
| `shellsmith_job_status` | 同步 | 返回状态、进度、最近日志和结果 |
| `shellsmith_job_result` | 同步 | 仅返回已结束任务的结果 |
| `shellsmith_job_cancel` | 同步 | 取消任务并终止 CLI 子进程 |
| `shellsmith_job_list` | 同步 | 列出当前 MCP 进程内的任务 |

所有加固、签名和安装工具都要求 `confirm: true`（iOS `dry_run` 只检查时除外）；`shellsmith_job_cancel` 用于停止任务，不要求确认。`shellsmith_protect_apk` 的 `sign` 子对象复用独立签名参数。

## 常用调用

### 先检查

```json
{
  "name": "shellsmith_check_apk",
  "arguments": {
    "path": "/Users/me/projects/app.apk"
  }
}
```

### 加固并自动签名

```json
{
  "name": "shellsmith_protect_apk",
  "arguments": {
    "input": "/Users/me/projects/app.apk",
    "output": "/Users/me/projects/app-protected.apk",
    "profile": "balanced",
    "ai_resistance": "balanced",
    "runtime_ui": {
      "secure_screen": true,
      "adb_policy": "report",
      "runtime_recheck": true
    },
    "sign": {
      "keystore": "/secure/release.jks",
      "key_alias": "release",
      "password_env": "MOCIKA_SHIELD_KS_PASS",
      "key_password_env": "MOCIKA_SHIELD_KEY_PASS",
      "v2": true,
      "v3": true
    },
    "confirm": true
  }
}
```

返回：

```json
{
  "job_id": "job-1760000000000-1",
  "status": "running"
}
```

### 轮询任务

```json
{"name": "shellsmith_job_status", "arguments": {"job_id": "job-1760000000000-1"}}
```

任务结束后 `structuredContent.result` 包含输出路径和报告路径：

```json
{
  "output": "/Users/me/projects/app-protected.apk",
  "report": "/Users/me/projects/app-protected.apk.protection.json",
  "signed": true
}
```

如果客户端在 `tools/call` 的 `_meta.progressToken` 中提供 token，服务会发送 `notifications/progress`。

### 读取报告

```json
{
  "name": "shellsmith_read_report",
  "arguments": {
    "path": "/Users/me/projects/app-protected.apk.protection.json",
    "mode": "summary"
  }
}
```

`mode` 为 `full` 时返回完整报告；报告上限 64 MiB，且必须是 `.json` 文件。

## 安全边界

- **密码**：只从 MCP 进程环境读取；工具 schema 中没有 `password`、`ks_pass`、`key_password` 字段。错误信息不会回显密码。
- **路径**：输入路径必须存在并会被规范化；输出父目录必须存在；配置 `--allow-root` 后，所有输入和输出都必须位于允许目录内。
- **确认**：加固、签名、安装要求 `confirm: true`；原地覆盖还要求 `allow_in_place: true`。
- **取消**：取消会终止 `shield` 子进程；已写出的临时文件由 CLI 自身清理。
- **不上传**：MCP 不包含遥测、更新检查或远程托管逻辑。只有显式使用 BYOS 时才会访问你配置的 HTTPS 服务。
- **报告**：`shellsmith_read_report` 只读本地 JSON，不执行报告中的任何内容。

## 与 GUI 能力边界

MCP 暴露的是当前 `origin/main` 的 CLI 能力。以下 GUI 专属能力不暴露：

- 证书数据库与 GUI 证书管理
- 应用设置、主题、语言
- 应用内更新与遥测/反馈
- GUI 的批量队列和界面状态

并行开发中的 ELFProtect / ProtectSo 在合并进 `main` 前不纳入 MCP。远程 MCP 托管、OAuth 和多租户也不在当前范围。

## 故障排查

| 现象 | 处理 |
|---|---|
| `启动 Shellsmith CLI 失败` | 用 `--cli` 或 `SHELLSMITH_MCP_CLI` 指向正确的 `shield` |
| `缺少密码环境变量 ...` | 在启动 MCP 的进程环境中导出对应变量，或把 `password_env` 改成实际变量名 |
| `不在允许的目录内` | 调整 `--allow-root` / `SHELLSMITH_MCP_ALLOWED_ROOTS` |
| 任务一直是 `running` | 调用 `shellsmith_job_status` 查看 `logs`；必要时 `shellsmith_job_cancel` |
| `tools/call` 返回 `isError: true` | 这是工具执行错误，内容在 `content[0].text`；协议层错误才使用 JSON-RPC `error` |
