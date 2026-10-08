#!/usr/bin/env bash
# macOS 平台发布脚本（必须在 macOS 机器上原生运行）
# 生成：CLI（tar.gz，支持 universal binary）、GUI（.app + .dmg）
#
# 用法:
#   ./scripts/release-macos.sh [VERSION] [universal]
#   VERSION=1.2.3 ./scripts/release-macos.sh 1.2.3 universal
#
# 前置要求:
#   macOS 12+ (Monterey)
#   Xcode Command Line Tools: xcode-select --install
#   Rust: rustup target add aarch64-apple-darwin x86_64-apple-darwin
#   Tauri CLI: cargo install tauri-cli
#   Java 17+（shield-stub 构建需要）
#
# 注意:
#   - 默认 adhoc 签名供本机测试；MACOS_RELEASE_MODE=developer-id 时执行正式签名、公证和装订
#   - universal binary 需在同一台 Mac 上分别为 arm64 和 x86_64 构建后合并

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname "$0")" && pwd)"
ROOT="$SCRIPT_DIR/.."
VERSION="${VERSION:-${1:-1.0.0}}"
BUILD_UNIVERSAL="${2:-}"
DIST_DIR="$ROOT/dist/macos"
SKIP_CLI_RELEASE="${SKIP_CLI_RELEASE:-0}"
SKIP_STUB_BUILD="${SKIP_STUB_BUILD:-0}"
MACOS_RELEASE_MODE="${MACOS_RELEASE_MODE:-adhoc}"
MACOS_SIGN_IDENTITY="${MACOS_SIGN_IDENTITY:-}"
MACOS_NOTARY_PROFILE="${MACOS_NOTARY_PROFILE:-}"
GUI_BUNDLETOOL=""
GUI_AAPT2=""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()    { echo -e "${BLUE}==> $1${NC}"; }
success() { echo -e "${GREEN}✓ $1${NC}"; }
warn()    { echo -e "${YELLOW}⚠ $1${NC}"; }
error()   { echo -e "${RED}✗ $1${NC}" >&2; exit 1; }

APP_NAME="Shellsmith"
BUNDLE_ID="dev.mocika.shield-gui"
GUI_BINARY="shield-gui"

# ========== 检查运行环境 ==========
check_env() {
  info "检查运行环境..."
  [[ -n "${TAURI_SIGNING_PRIVATE_KEY:-}" ]] || error "发布需要设置 TAURI_SIGNING_PRIVATE_KEY"

  if [[ "$OSTYPE" != "darwin"* ]]; then
    error "此脚本仅支持 macOS，当前系统: $OSTYPE"
  fi

  if ! command -v cargo &>/dev/null; then
    error "Rust 未安装，请访问 https://rustup.rs/ 安装"
  fi

  if ! command -v java &>/dev/null; then
    error "未安装 Java，shield-stub 构建需要 Java 17+"
  fi

  if ! command -v npm &>/dev/null; then
    error "未安装 Node.js/npm，Tauri React 前端构建需要 npm"
  fi

  case "$MACOS_RELEASE_MODE" in
    adhoc) ;;
    developer-id)
      [[ -n "$MACOS_SIGN_IDENTITY" ]] || error \
        "developer-id 模式必须设置 MACOS_SIGN_IDENTITY"
      [[ -n "$MACOS_NOTARY_PROFILE" ]] || error \
        "developer-id 模式必须设置 MACOS_NOTARY_PROFILE（先用 notarytool store-credentials 写入钥匙串）"
      security find-identity -v -p codesigning \
        | grep -F "$MACOS_SIGN_IDENTITY" >/dev/null \
        || error "钥匙串中没有可用签名身份: $MACOS_SIGN_IDENTITY"
      xcrun notarytool --version >/dev/null \
        || error "当前 Xcode 不提供 notarytool"
      xcrun stapler --version >/dev/null 2>&1 \
        || error "当前 Xcode 不提供 stapler"
      ;;
    *) error "MACOS_RELEASE_MODE 只能是 adhoc 或 developer-id" ;;
  esac

  if [[ "$BUILD_UNIVERSAL" == "universal" ]]; then
    for target in aarch64-apple-darwin x86_64-apple-darwin; do
      if ! rustup target list --installed | grep -q "$target"; then
        warn "未安装 ${target}，正在安装..."
        rustup target add "$target"
      fi
    done
  fi

  success "环境检查通过"
  echo "  Rust: $(rustc --version)"
  echo "  架构: $(uname -m)$([ "$BUILD_UNIVERSAL" = "universal" ] && echo " → universal" || echo "")"
  echo "  版本: $VERSION"
  echo "  签名: $MACOS_RELEASE_MODE"
}

# ========== 构建 shield-stub（resources.zip）==========
build_stub() {
  info "构建 shield-stub（resources.zip）..."
  cd "$ROOT"
  SHIELD_VERSION="$VERSION" bash scripts/build-stub.sh
  SKIP_STANDARD_STUB_BUILD=1 bash scripts/build-android-api19-resources.sh
  RESOURCES_ZIP="$ROOT/shield-stub/build/outputs/resources/resources.zip"
  if [[ ! -f "$RESOURCES_ZIP" ]]; then
    error "shield-stub 构建失败，resources.zip 未生成"
  fi
  if [[ ! -f "$ROOT/shield-stub/build/outputs/resources/resources-api19.zip" ]]; then
    error "shield-stub 构建失败，resources-api19.zip 未生成"
  fi
  success "shield-stub 构建完成"
}

# ========== 构建 CLI ==========
build_cli() {
  info "构建 CLI..."
  cd "$ROOT"

  if [[ "$BUILD_UNIVERSAL" == "universal" ]]; then
    cargo build --release -p shield-cli --target aarch64-apple-darwin
    cargo build --release -p shield-cli --target x86_64-apple-darwin

    mkdir -p "$ROOT/target/universal/release"
    lipo -create \
      "$ROOT/target/aarch64-apple-darwin/release/shield" \
      "$ROOT/target/x86_64-apple-darwin/release/shield" \
      -output "$ROOT/target/universal/release/shield"
    CLI_BIN="$ROOT/target/universal/release/shield"
    success "CLI universal binary 构建完成"
  else
    cargo build --release -p shield-cli
    CLI_BIN="$ROOT/target/release/shield"
    success "CLI 构建完成（$(uname -m)）"
  fi
  echo "  大小: $(du -h "$CLI_BIN" | cut -f1)"
}

prepare_aab_gui_tools() {
  info "准备 GUI AAB 工具..."
  local bundletool_candidates=(
    "${BUNDLETOOL_JAR:-}"
    "$ROOT/tools/bundletool.jar"
    "$ROOT/target/e2e-tools/bundletool-all-1.18.3.jar"
  )
  local candidate
  for candidate in "${bundletool_candidates[@]}"; do
    if [[ -n "$candidate" && -f "$candidate" ]]; then
      GUI_BUNDLETOOL="$candidate"
      break
    fi
  done
  [[ -n "$GUI_BUNDLETOOL" ]] || error \
    "缺少 bundletool JAR；请设置 BUNDLETOOL_JAR 或放到 target/e2e-tools/bundletool-all-1.18.3.jar"

  if [[ -n "${AAPT2_BIN:-}" && -x "${AAPT2_BIN}" ]]; then
    GUI_AAPT2="$AAPT2_BIN"
  else
    local sdk="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/Library/Android/sdk}}"
    if [[ -d "$sdk/build-tools" ]]; then
      GUI_AAPT2=$(find "$sdk/build-tools" -type f -name aapt2 -perm -111 2>/dev/null | sort -V | tail -n 1)
    fi
  fi
  [[ -n "$GUI_AAPT2" && -x "$GUI_AAPT2" ]] || error \
    "缺少可执行的 aapt2；请设置 AAPT2_BIN 或 ANDROID_SDK_ROOT"
  success "GUI AAB 工具已就绪（bundletool + aapt2）"
}

# ========== 构建 GUI（先生成并签名 .app，再由已验证应用包创建 .dmg）==========
build_gui() {
  info "构建 GUI（cargo tauri build --bundles app）..."
  cd "$ROOT/apps/shield-gui"

  npm ci
  local AAB_TAURI_CONFIG
  AAB_TAURI_CONFIG=$(GUI_BUNDLETOOL="$GUI_BUNDLETOOL" GUI_AAPT2="$GUI_AAPT2" node -e '
    process.stdout.write(JSON.stringify({bundle:{createUpdaterArtifacts:false,resources:{
      [process.env.GUI_BUNDLETOOL]: "tools/bundletool.jar",
      [process.env.GUI_AAPT2]: "tools/aapt2"
    }}}))
  ')
  local BUNDLE_BASE
  if [[ "$BUILD_UNIVERSAL" == "universal" ]]; then
    BUNDLE_BASE="$ROOT/target/universal-apple-darwin/release/bundle"
    rm -rf "$BUNDLE_BASE/macos" "$BUNDLE_BASE/dmg"
    cargo tauri build --bundles app --target universal-apple-darwin \
      --config "$AAB_TAURI_CONFIG"
  else
    BUNDLE_BASE="$ROOT/target/release/bundle"
    rm -rf "$BUNDLE_BASE/macos" "$BUNDLE_BASE/dmg"
    cargo tauri build --bundles app --config "$AAB_TAURI_CONFIG"
  fi

  local APP_DIR
  APP_DIR=$(find "$BUNDLE_BASE/macos" -name "*.app" -maxdepth 1 2>/dev/null | head -n 1)
  local APP_COUNT
  APP_COUNT=$(find "$BUNDLE_BASE/macos" -name "*.app" -maxdepth 1 2>/dev/null | wc -l | tr -d ' ')
  if [[ -z "$APP_DIR" || "$APP_COUNT" != "1" ]]; then
    error "Tauri .app 未生成: $BUNDLE_BASE/macos/"
  fi

  if [[ "$MACOS_RELEASE_MODE" == "developer-id" ]]; then
    info "使用 Developer ID 对完整 .app 签名并启用 hardened runtime..."
    codesign --force --deep --options runtime --timestamp \
      --sign "$MACOS_SIGN_IDENTITY" "$APP_DIR"
  else
    info "对完整 .app 执行 adhoc 签名并校验..."
    codesign --force --deep --sign - "$APP_DIR"
  fi
  codesign --verify --deep --strict --verbose=2 "$APP_DIR"
  success ".app 签名校验通过（${MACOS_RELEASE_MODE}）"

  local ARCH_SUFFIX
  if [[ "$BUILD_UNIVERSAL" == "universal" ]]; then
    ARCH_SUFFIX="universal"
  else
    ARCH_SUFFIX="$(uname -m)"
  fi
  local DMG_DIR="$BUNDLE_BASE/dmg"
  local RELEASE_SUFFIX=""
  if [[ "$MACOS_RELEASE_MODE" == "developer-id" ]]; then
    RELEASE_SUFFIX="_notarized"
  fi
  local DMG="$DMG_DIR/Shellsmith_${VERSION}_${ARCH_SUFFIX}${RELEASE_SUFFIX}.dmg"
  local DMG_STAGE
  DMG_STAGE=$(mktemp -d)
  rm -rf "$DMG_DIR"
  mkdir -p "$DMG_DIR"
  ditto "$APP_DIR" "$DMG_STAGE/Shellsmith.app"
  ln -s /Applications "$DMG_STAGE/Applications"
  hdiutil create -quiet -volname "Shellsmith" -srcfolder "$DMG_STAGE" -ov -format UDZO "$DMG"
  rm -rf "$DMG_STAGE"
  if [[ "$MACOS_RELEASE_MODE" == "developer-id" ]]; then
    info "签名、提交公证并装订 DMG ticket..."
    codesign --force --timestamp --sign "$MACOS_SIGN_IDENTITY" "$DMG"
    xcrun notarytool submit "$DMG" \
      --keychain-profile "$MACOS_NOTARY_PROFILE" --wait
    xcrun stapler staple "$DMG"
    xcrun stapler validate "$DMG"
    codesign --verify --strict --verbose=2 "$DMG"
    spctl --assess --type open --context context:primary-signature --verbose=4 "$DMG"
    success "Developer ID 签名与 Apple 公证验证通过"
  fi
  success "GUI 构建完成，DMG 已从签名后的 .app 创建"
}

# ========== 准备输出目录 ==========
prepare_dirs() {
  info "准备输出目录..."
  rm -rf "$DIST_DIR"
  mkdir -p "$DIST_DIR"/{cli,gui-app,gui-dmg}
  success "目录准备完成: $DIST_DIR"
}

# ========== 打包 CLI tar.gz ==========
package_cli() {
  info "打包 CLI..."

  local ARCH_LABEL
  if [[ "$BUILD_UNIVERSAL" == "universal" ]]; then
    ARCH_LABEL="universal"
  else
    ARCH_LABEL="$(uname -m)"
  fi

  local CLI_PKG_DIR="$DIST_DIR/cli/Shellsmith-cli-${VERSION}-macos-${ARCH_LABEL}"
  mkdir -p "$CLI_PKG_DIR"/{bin,lib,resources,licenses}

  cp "$CLI_BIN" "$CLI_PKG_DIR/bin/shield"
  chmod +x "$CLI_PKG_DIR/bin/shield"

  if [[ -f "$ROOT/tools/apktool_3.0.1.jar" ]]; then
    cp "$ROOT/tools/apktool_3.0.1.jar" "$CLI_PKG_DIR/lib/apktool.jar"
  else
    warn "apktool.jar 未找到，请手动复制到 tools/ 目录"
  fi
  if [[ -f "$ROOT/tools/apksigner.jar" ]]; then
    cp "$ROOT/tools/apksigner.jar" "$CLI_PKG_DIR/lib/apksigner.jar"
  else
    warn "apksigner.jar 未找到，请手动复制到 tools/ 目录"
  fi

  if [[ ! -f "$ROOT/tools/xop-pvm2-packer.jar" ]]; then
    error "xop-pvm2-packer.jar 未找到，无法打包严格模式 CLI"
  fi
  cp "$ROOT/tools/xop-pvm2-packer.jar" "$CLI_PKG_DIR/lib/xop-pvm2-packer.jar"
  cp "$ROOT/tools/licenses/XopProtector-LICENSE.txt" "$CLI_PKG_DIR/licenses/"
  cp "$ROOT/tools/licenses/XopProtector-NOTICE.txt" "$CLI_PKG_DIR/licenses/"

  cp "$ROOT/shield-stub/build/outputs/resources/resources.zip" "$CLI_PKG_DIR/resources/resources.zip"
  cp "$ROOT/shield-stub/build/outputs/resources/resources-api19.zip" "$CLI_PKG_DIR/resources/resources-api19.zip"
  cp "$ROOT/shield-stub/build/outputs/resources/mocika-play-delivery-api.jar" "$CLI_PKG_DIR/resources/mocika-play-delivery-api.jar"

  cat > "$CLI_PKG_DIR/shield.sh" << 'RUNEOF'
#!/usr/bin/env bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$DIR/bin/shield" "$@"
RUNEOF
  chmod +x "$CLI_PKG_DIR/shield.sh"

  cat > "$CLI_PKG_DIR/README.md" << 'READMEEOF'
# Shellsmith CLI

macOS 版本。

## 使用方法

\`\`\`bash
./bin/shield protect -i input.apk -o protected.apk
\`\`\`

## 要求

- macOS 10.13+
- Java 17+（严格模式的内置 Xop PVM2 与 shield-stub 构建需要；`java` / `keytool` 需可用）

## 目录结构

\`\`\`
Shellsmith-cli-${VERSION}-macos-${ARCH_LABEL}/
├── bin/shield          # 可执行文件
├── lib/
│   ├── apktool.jar
│   ├── apksigner.jar
│   └── xop-pvm2-packer.jar
├── resources/
│   ├── resources.zip         # Android 5+ 完整运行时
│   └── resources-api19.zip   # Android 4.4 ARMv7 兼容运行时
├── licenses/                 # XopProtector 许可证与声明
├── shield.sh           # 快捷启动脚本
└── README.md
\`\`\`
READMEEOF

  cd "$DIST_DIR/cli"
  tar -czf "Shellsmith-cli-${VERSION}-macos-${ARCH_LABEL}.tar.gz" \
      "Shellsmith-cli-${VERSION}-macos-${ARCH_LABEL}"
  rm -rf "Shellsmith-cli-${VERSION}-macos-${ARCH_LABEL}"

  success "CLI tar.gz 打包完成"
  ls -lh "$DIST_DIR/cli/"*.tar.gz
}

# ========== 收集 GUI 产物（Tauri 生成的 .app 和 .dmg）==========
collect_gui() {
  info "收集 GUI 产物..."

  local TAURI_TARGET="$ROOT/target"
  local BUNDLE_BASE

  if [[ "$BUILD_UNIVERSAL" == "universal" ]]; then
    BUNDLE_BASE="$TAURI_TARGET/universal-apple-darwin/release/bundle"
  else
    BUNDLE_BASE="$TAURI_TARGET/release/bundle"
  fi

  # .app
  local APP_DIR
  APP_DIR=$(find "$BUNDLE_BASE/macos" -name "*.app" -maxdepth 1 2>/dev/null | head -n 1)
  if [[ -n "$APP_DIR" ]]; then
    ditto "$APP_DIR" "$DIST_DIR/gui-app/Shellsmith.app"
    # 更新包必须取最终签名的应用，不能使用 Tauri 构建阶段的中间包。
    local UPDATE_ARCH
    if [[ "$BUILD_UNIVERSAL" == "universal" ]]; then
      UPDATE_ARCH="universal"
    else
      UPDATE_ARCH="$(uname -m)"
    fi
    local UPDATE_PACKAGE="$DIST_DIR/gui-app/Shellsmith_${VERSION}_macos_${UPDATE_ARCH}.app.tar.gz"
    if [[ "$MACOS_RELEASE_MODE" == "developer-id" ]]; then
      xcrun stapler staple "$DIST_DIR/gui-app/Shellsmith.app"
      xcrun stapler validate "$DIST_DIR/gui-app/Shellsmith.app"
    fi
    COPYFILE_DISABLE=1 tar -czf "$UPDATE_PACKAGE" -C "$DIST_DIR/gui-app" Shellsmith.app
    cargo tauri signer sign --app-version "$VERSION" "$UPDATE_PACKAGE"
    success ".app: Shellsmith.app（应用显示名：$(basename "$APP_DIR" .app)）"
  else
    warn ".app 未找到: $BUNDLE_BASE/macos/"
  fi

  # .dmg（重命名为规范格式）
  local DMG
  DMG=$(find "$BUNDLE_BASE/dmg" -name "*.dmg" 2>/dev/null | head -n 1)
  if [[ -n "$DMG" ]]; then
    local ARCH_SUFFIX
    if [[ "$BUILD_UNIVERSAL" == "universal" ]]; then
      ARCH_SUFFIX="universal"
    else
      ARCH_SUFFIX="$(uname -m)"
    fi
    local RELEASE_SUFFIX=""
    if [[ "$MACOS_RELEASE_MODE" == "developer-id" ]]; then
      RELEASE_SUFFIX="_notarized"
    fi
    local DMG_OUT="Shellsmith_${VERSION}_macos_${ARCH_SUFFIX}${RELEASE_SUFFIX}.dmg"
    cp "$DMG" "$DIST_DIR/gui-dmg/$DMG_OUT"
    success ".dmg → $DMG_OUT"
  else
    warn ".dmg 未找到: $BUNDLE_BASE/dmg/"
  fi
}

# ========== 生成校验和 ==========
generate_checksums() {
  info "生成 SHA256 校验和..."
  cd "$DIST_DIR"
  find . -type f \( -name "*.tar.gz" -o -name "*.dmg" \) \
    -exec shasum -a 256 {} \; | sort > checksums-sha256.txt
  success "校验和已写入 checksums-sha256.txt"
  cat checksums-sha256.txt
}

# ========== 显示结果 ==========
show_results() {
  local ARCH_LABEL
  if [[ "$BUILD_UNIVERSAL" == "universal" ]]; then
    ARCH_LABEL="universal (ARM64 + x86_64)"
  else
    ARCH_LABEL="$(uname -m)"
  fi

  echo ""
  info "macOS 发布构建完成！v${VERSION}  架构: ${ARCH_LABEL}"
  echo ""
  find "$DIST_DIR" -type f | sort | while read -r f; do
    local size
    size=$(du -h "$f" | cut -f1)
    echo "  📄 ${f#"$DIST_DIR"/} ($size)"
  done
  echo ""
  echo "📦 CLI（tar.gz）:"
  ls "$DIST_DIR/cli/"*.tar.gz 2>/dev/null || echo "   (未生成)"
  echo ""
  echo "📦 GUI .app（直接运行）:"
  find "$DIST_DIR/gui-app" -maxdepth 1 -name "*.app" -print 2>/dev/null || echo "   (未生成)"
  echo ""
  echo "📦 GUI .dmg（拖拽安装）:"
  ls "$DIST_DIR/gui-dmg/"*.dmg 2>/dev/null || echo "   (未生成)"
  echo ""
  if [[ "$MACOS_RELEASE_MODE" == "developer-id" ]]; then
    success "Developer ID 签名和 Apple 公证均已完成，可作为外部分发候选"
  else
    warn "注意：当前是 adhoc 本地包；外部分发请设置 MACOS_RELEASE_MODE=developer-id、MACOS_SIGN_IDENTITY 和 MACOS_NOTARY_PROFILE 后重建"
  fi
  success "全部完成！"
}

# ========== 主流程 ==========
main() {
  echo ""
  echo "  Shellsmith — macOS 发布脚本（必须在 macOS 上原生运行）"
  echo "  版本: $VERSION"
  echo ""

  cd "$ROOT"

  check_env
  if [[ "$SKIP_STUB_BUILD" == "1" ]]; then
    info "复用现有 Android 运行时资源（SKIP_STUB_BUILD=1）"
    for resource in resources.zip resources-api19.zip mocika-play-delivery-api.jar; do
      [[ -f "$ROOT/shield-stub/build/outputs/resources/$resource" ]] || error \
        "缺少现有运行时资源: $resource"
    done
  else
    build_stub
  fi
  prepare_dirs
  if [[ "$SKIP_CLI_RELEASE" == "1" ]]; then
    info "跳过 CLI 构建与打包（SKIP_CLI_RELEASE=1）"
  else
    build_cli
  fi
  prepare_aab_gui_tools
  build_gui
  if [[ "$SKIP_CLI_RELEASE" != "1" ]]; then
    package_cli
  fi
  collect_gui
  generate_checksums
  show_results
}

main "$@"
