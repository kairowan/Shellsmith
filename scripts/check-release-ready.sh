#!/usr/bin/env bash
# 发布前轻量检查：不构建产物，只检查仓库状态、版本同步、文档资源和敏感文件。

set -euo pipefail

ROOT="$(cd -- "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

failures=0

info() {
  printf '==> %s\n' "$1"
}

ok() {
  printf '  ✓ %s\n' "$1"
}

fail() {
  printf '  ✗ %s\n' "$1"
  failures=$((failures + 1))
}

warn() {
  printf '  ! %s\n' "$1"
}

read_toml_version() {
  sed -n 's/^version = "\(.*\)"/\1/p' "$1" | head -1
}

read_json_version() {
  sed -n 's/^[[:space:]]*"version": "\(.*\)",\{0,1\}/\1/p' "$1" | head -1
}

expect_file() {
  local path="$1"
  local label="$2"
  if [[ -f "$path" ]]; then
    ok "$label"
  else
    fail "$label 缺失: $path"
  fi
}

# 分发物哈希固定：随包分发的 jar 被替换后必须在此显式更新，避免依赖被静默调包。
# 更新时先核对上游来源，再改这里的期望值。
expect_sha256() {
  local path="$1"
  local expected="$2"
  if [[ ! -f "$path" ]]; then
    return
  fi
  local actual
  actual="$(shasum -a 256 "$path" | awk '{print $1}')"
  if [[ "$actual" == "$expected" ]]; then
    ok "哈希匹配: $path"
  else
    fail "$path 哈希不匹配，期望 $expected，实际 $actual"
  fi
}

info "检查工作区状态"
if [[ -z "$(git status --porcelain)" ]]; then
  ok "工作区干净"
else
  fail "工作区存在未提交变更"
  git status --short
fi

info "检查版本号同步"
version_files=(
  "crates/shield-core/Cargo.toml"
  "apps/shield-cli/Cargo.toml"
  "apps/shellsmith-mcp/Cargo.toml"
  "shield-stub/src/main/rust/Cargo.toml"
  "shield-stub/compat/api19-rust/Cargo.toml"
  "apps/shield-gui/src-tauri/Cargo.toml"
  "apps/shield-gui/src-tauri/tauri.conf.json"
  "apps/shield-gui/package.json"
  "apps/shield-gui/package-lock.json"
)

base_version="$(read_toml_version crates/shield-core/Cargo.toml)"
if [[ -z "$base_version" ]]; then
  fail "无法读取 crates/shield-core/Cargo.toml 版本号"
else
  for file in "${version_files[@]}"; do
    case "$file" in
      *.toml) version="$(read_toml_version "$file")" ;;
      *.json) version="$(read_json_version "$file")" ;;
      *) version="" ;;
    esac
    if [[ "$version" == "$base_version" ]]; then
      ok "$file = $version"
    else
      fail "$file 版本不一致：$version，期望 $base_version"
    fi
  done
fi

info "检查构建必需资源"
expect_file "tools/apktool_3.0.3.jar" "开发工具 apktool 存在"
expect_file "tools/apksigner.jar" "开发工具 apksigner 存在"
expect_file "shield-stub/build/outputs/resources/resources.zip" "resources.zip 已生成"
expect_file "shield-stub/build/outputs/resources/resources-api19.zip" "resources-api19.zip 已生成"

if python3 tests/scripts/check-byos-resources.py; then
  ok "BYOS 分发资源及授权隔离一致"
else
  fail "BYOS 分发资源不完整或模式不匹配"
fi

info "检查分发物版本与哈希"
if [[ -e "tools/apktool_3.0.1.jar" ]]; then
  fail "旧版 apktool_3.0.1.jar 仍存在，必须删除以免混用"
else
  ok "旧版 apktool 已移除"
fi
if [[ -f "tools/apktool_3.0.3.jar" ]]; then
  apktool_version="$(java -jar tools/apktool_3.0.3.jar --version 2>/dev/null | tr -d '\r' || true)"
  if [[ "$apktool_version" == "3.0.3" ]]; then
    ok "apktool 版本 3.0.3"
  else
    fail "apktool 版本不符：$apktool_version，期望 3.0.3"
  fi
fi
expect_sha256 "tools/apktool_3.0.3.jar" "dbf930b076c6b9be08d57c449cacefc3bdd6b71ebd59b3066fc0e1f5b14f9423"
expect_sha256 "tools/apksigner.jar" "2defad215d7ff52968a409cde528cdaef7918b115e276b8e3378ca7a178e4180"
# 打包器由当前源码重建，JDK 版本会写入构建记录；校验源码、类文件和锁定依赖，不能固定整个 JAR 的摘要。
if python3 scripts/build_pvm2_packer.py --check; then
  ok "PVM2 打包器源码、类文件与锁定依赖一致"
else
  fail "PVM2 打包器构建记录校验失败"
fi

info "检查 README 截图引用"
screenshot_refs=()
while IFS= read -r ref; do
  screenshot_refs+=("$ref")
done < <(grep -Eo 'docs/assets/screenshots/[^) ]+\.(png|jpg|jpeg|webp)' README.md | sort -u)
if [[ "${#screenshot_refs[@]}" -eq 0 ]]; then
  fail "README 未找到截图引用"
else
  for ref in "${screenshot_refs[@]}"; do
    expect_file "$ref" "截图存在: $ref"
  done
fi

info "检查开源仓库治理文件"
expect_file "SECURITY.md" "SECURITY.md 存在"
expect_file "docs/process/support.md" "支持与问题反馈文档存在"
expect_file ".github/ISSUE_TEMPLATE/bug_report.yml" "Bug issue 模板存在"
expect_file ".github/ISSUE_TEMPLATE/compatibility.yml" "兼容性 issue 模板存在"
expect_file ".github/ISSUE_TEMPLATE/config.yml" "Issue 模板配置存在"
expect_file ".github/workflows/ci.yml" "CI workflow 存在"
expect_file ".github/workflows/release.yml" "Release workflow 存在"

info "检查已跟踪敏感或本地产物"
tracked_sensitive="$(
  git ls-files \
    | grep -E '(^|/)(shield\.db|config\.toml|tool_config\.json|node_modules/)|\.(apk|aab|jks|p12|keystore|env)$' \
    | grep -Ev '(^|/)\.cargo/config\.toml$' \
    || true
)"
if [[ -z "$tracked_sensitive" ]]; then
  ok "未发现已跟踪的敏感文件或本地产物"
else
  fail "发现已跟踪的敏感文件或本地产物"
  printf '%s\n' "$tracked_sensitive"
fi

info "检查 PVM2 打包器与运行时源码的格式版本一致"
if pvm2_output="$(python3 scripts/verify_pvm2_packager_version.py \
  --jar tools/xop-pvm2-packer.jar --xop-root third_party/xopprotector 2>&1)"; then
  ok "${pvm2_output#✓ }"
else
  fail "PVM2 打包器与运行时源码的镜像格式版本不一致"
  printf '%s\n' "$pvm2_output"
fi

info "检查未跟踪敏感或本地产物"
untracked_sensitive="$(git ls-files --others --exclude-standard | grep -E '(^|/)(shield\.db|config\.toml|tool_config\.json)|\.(apk|aab|jks|p12|keystore|env)$' || true)"
if [[ -z "$untracked_sensitive" ]]; then
  ok "未发现未跟踪的敏感文件或本地产物"
else
  fail "发现未跟踪的敏感文件或本地产物"
  printf '%s\n' "$untracked_sensitive"
fi

if [[ -d apps/shield-gui/node_modules ]]; then
  warn "apps/shield-gui/node_modules 存在但已被 .gitignore 忽略"
fi

if [[ "$failures" -gt 0 ]]; then
  printf '\n发布前检查未通过：%d 项失败\n' "$failures"
  exit 1
fi

printf '\n发布前检查通过。\n'
