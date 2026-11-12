#!/usr/bin/env bash
# 生成 CLI + MCP 发布包说明。
# 使用带引号的 heredoc，避免说明文字中的反引号或 $ 被 shell 执行。
set -euo pipefail

output="${1:?用法: render-mcp-release-readme.sh OUTPUT VERSION PLATFORM}"
version="${2:?缺少版本号}"
platform="${3:?缺少平台}"

cat > "$output" <<'EOF'
# Shellsmith CLI + MCP @VERSION@

Platform: @PLATFORM@

This bundle contains the `shield` CLI and the `shellsmith-mcp` stdio server.
No artifact, certificate or password is uploaded by this package.

## Verify

```bash
./bin/shield --version
./bin/shellsmith-mcp --version
```

## MCP client configuration

Use an absolute path to the extracted bundle:

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

`shellsmith-mcp` automatically finds the sibling `shield` binary. If you keep
the CLI elsewhere, pass `--cli /path/to/shield` or set
`SHELLSMITH_MCP_CLI=/path/to/shield`.

Keystore passwords are read from the MCP server environment only:

```bash
export MOCIKA_SHIELD_KS_PASS="..."
export MOCIKA_SHIELD_KEY_PASS="..."
```

Do not put a plaintext password in the MCP client JSON or tool arguments.

## Requirements

- Java 17+ with `java` and `keytool` available.
- AAB workflows also need `bundletool.jar` and `aapt2`; pass their paths to the tool.
- Android APK/AAB work stays on this machine; iOS archive requires macOS and Xcode.
- macOS: if Gatekeeper blocks the unsigned CLI, run
  `xattr -rd com.apple.quarantine /path/to/Shellsmith-cli-*`.

See `docs/mcp.md` in the repository for the full tool list and security model.
EOF

sed \
  -e "s/@VERSION@/${version}/g" \
  -e "s/@PLATFORM@/${platform}/g" \
  "$output" > "$output.tmp"
mv "$output.tmp" "$output"
