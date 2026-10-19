use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum EnvironmentPolicyArg {
    #[default]
    Compatible,
    Strict,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum ProtectionProfileArg {
    Compat,
    #[default]
    Balanced,
    Strict,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum AiResistanceArg {
    Off,
    #[default]
    Balanced,
    High,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum KeystoreTypeArg {
    #[default]
    Jks,
    Pkcs12,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum ProtectionEngineArg {
    #[default]
    Mocika,
    Xop,
}

#[derive(Parser)]
#[command(
    name = "shield",
    version,
    author,
    about = "Android 与 iOS 应用加固工具",
    arg_required_else_help = true
)]
pub(crate) struct Cli {
    /// CLI 人工配置文件，建议命名为 shield-cli.toml。
    #[arg(long, global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
// ponytail: clap owns these values once at process start; boxing the largest
// command would complicate every dispatch path without a measurable benefit.
#[allow(clippy::large_enum_variant)]
pub(crate) enum Commands {
    Protect(ProtectArgs),
    /// 加固 base、条件/on-demand dynamic-feature 与各交付模式 Asset Pack，并重新签署 AAB。
    ProtectAab(ProtectAabArgs),
    /// 使用 Xop Packer 的单壳运行时保护 APK；不会再叠加 Shellsmith 壳。
    ProtectXop(ProtectXopArgs),
    Sign(SignArgs),
    CheckApk {
        path: PathBuf,
    },
    CheckAab {
        path: PathBuf,
        /// 可选的 bundletool JAR；提供后会执行 validate，并可生成本地 APKS。
        #[arg(long, value_name = "JAR")]
        bundletool: Option<PathBuf>,
        /// 可选的 APKS 输出路径；必须同时提供 --bundletool。
        #[arg(long, value_name = "APKS")]
        apks_output: Option<PathBuf>,
        /// bundletool 的设备规格 JSON，用于生成 device-specific APKS。
        #[arg(long, value_name = "JSON")]
        device_spec: Option<PathBuf>,
        /// bundletool build-apks 模式：universal 或 default。
        #[arg(long, default_value = "universal")]
        apks_mode: String,
        /// 生成 APKS 所需的签名 keystore。
        #[arg(long, value_name = "KEYSTORE")]
        ks: Option<PathBuf>,
        #[arg(long, value_name = "ALIAS")]
        ks_alias: Option<String>,
        #[arg(long, env = "MOCIKA_SHIELD_KS_PASS", hide_env_values = true)]
        ks_pass: Option<String>,
    },
    /// 检查 Xcode 工程、scheme、签名配置和已知上游兼容问题；不会修改工程。
    CheckIos {
        #[arg(value_name = "XCODE_PROJECT")]
        project: PathBuf,
        #[arg(long)]
        scheme: Option<String>,
    },
    /// 在独立工作副本中接入 iOS 保护、归档、签名并验证 IPA。
    ProtectIos(ProtectIosArgs),
    /// 使用 bundletool 将已生成的 APKS 安装到连接的测试设备；不执行保护变换。
    InstallApks {
        #[arg(value_name = "APKS")]
        path: PathBuf,
        #[arg(long, value_name = "JAR")]
        bundletool: PathBuf,
        #[arg(long)]
        device_id: Option<String>,
    },
    CheckKeystore {
        #[arg(long)]
        ks: PathBuf,
        #[arg(long)]
        alias: String,
        #[arg(long)]
        ks_pass: String,
    },
}

impl Commands {
    pub(crate) fn machine_output(&self) -> bool {
        match self {
            Self::Protect(args) => args.json,
            Self::ProtectAab(args) => args.json,
            Self::ProtectXop(args) => args.json,
            Self::ProtectIos(args) => args.json,
            Self::Sign(args) => args.json,
            Self::CheckApk { .. }
            | Self::CheckAab { .. }
            | Self::CheckIos { .. }
            | Self::CheckKeystore { .. }
            | Self::InstallApks { .. } => true,
        }
    }
}

#[derive(Args)]
pub(crate) struct ProtectIosArgs {
    /// Shellsmith iOS TOML 配置。
    #[arg(long = "ios-config", value_name = "TOML")]
    pub config: PathBuf,
    /// 独立输出目录；必须不存在或为空，不能位于源码目录内。
    #[arg(short, long, value_name = "DIR")]
    pub output: PathBuf,
    /// 导入官方 freeRASP v7.1.4 源码 ZIP；后续可直接复用本机缓存。
    #[arg(long, value_name = "ZIP")]
    pub freerasp_zip: Option<PathBuf>,
    /// 覆盖 iOS SDK 缓存目录（默认与 macOS GUI 共用）。
    #[arg(long, value_name = "DIR")]
    pub ios_cache_dir: Option<PathBuf>,
    /// 可选的 Xcode ExportOptions.plist；未提供时生成自动签名配置。
    #[arg(long, value_name = "PLIST")]
    pub export_options: Option<PathBuf>,
    /// Xcode 导出方式，例如 development、ad-hoc、app-store-connect。
    #[arg(long, default_value = "development")]
    pub export_method: String,
    /// 允许 Xcode 访问开发者账号并更新 Provisioning Profile。
    #[arg(long)]
    pub allow_provisioning_updates: bool,
    /// 只执行检查与已知问题评估，不复制或修改工程。
    #[arg(long)]
    pub dry_run: bool,
    /// 每行输出 JSON 进度事件，并在末尾输出完整报告。
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Default)]
pub struct ProtectAabArgs {
    #[command(flatten)]
    pub runtime_ui: RuntimeUiArgs,
    #[arg(short, long, value_name = "AAB")]
    pub input: PathBuf,
    #[arg(short, long, value_name = "AAB")]
    pub output: PathBuf,
    /// bundletool JAR；用于生成 universal APK、重建 AAB 和最终校验。
    #[arg(long, value_name = "JAR")]
    pub bundletool: PathBuf,
    /// aapt2 可执行文件；用于把加固 APK 转为 protobuf 资源格式。
    #[arg(long, value_name = "BIN")]
    pub aapt2: PathBuf,
    #[arg(long, value_name = "KEYSTORE")]
    pub ks: PathBuf,
    #[arg(long)]
    pub key_alias: String,
    #[arg(long, env = "MOCIKA_SHIELD_KS_PASS", hide_env_values = true)]
    pub ks_pass: String,
    #[arg(long, env = "MOCIKA_SHIELD_KEY_PASS", hide_env_values = true)]
    pub key_pass: Option<String>,
    #[arg(long, value_enum, default_value_t = KeystoreTypeArg::Jks)]
    pub ks_type: KeystoreTypeArg,
    #[arg(long, value_name = "JAR")]
    pub apktool: Option<PathBuf>,
    #[arg(long, value_name = "ZIP")]
    pub resources: Option<PathBuf>,
    #[arg(long, value_name = "JAR")]
    pub apksigner: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = EnvironmentPolicyArg::Compatible)]
    pub environment_policy: EnvironmentPolicyArg,
    #[arg(long, value_enum, default_value_t = ProtectionProfileArg::Balanced)]
    pub profile: ProtectionProfileArg,
    #[arg(long, value_enum, default_value_t = AiResistanceArg::Balanced)]
    pub ai_resistance: AiResistanceArg,
    /// 最终设备 APK 的证书 SHA-256（Play App Signing 证书）。
    #[arg(long, value_name = "SHA256")]
    pub runtime_cert_sha256: Option<String>,
    /// 仅用于本地 bundletool/设备实验；允许把运行时绑定到 upload key。
    #[arg(long)]
    pub allow_upload_cert_binding: bool,
    /// 声明业务已使用稳定的 MocikaPlayDelivery API 读取 fast-follow/on-demand
    /// Asset Pack；未声明时拒绝生成运行时无法透明读取的密文模块。
    #[arg(long)]
    pub play_delivery_adapter: bool,
    /// APK 变换引擎；xop 直接使用 Xop 单壳，不叠加 Shellsmith Stub。
    #[arg(long, value_enum, default_value_t = ProtectionEngineArg::Mocika)]
    pub engine: ProtectionEngineArg,
    /// `--engine xop` 时使用的 Xop Packer fat JAR。
    #[arg(long, value_name = "JAR")]
    pub xop_packer: Option<PathBuf>,
    /// `--engine mocika` 时以 transform-only 方式嵌入单 Stub 的 Xop PVM2 Packer。
    #[arg(long, value_name = "JAR")]
    pub xop_pvm2_packer: Option<PathBuf>,
    /// AAB 中要交给嵌入式 PVM2 的类描述符前缀，可重复传入。
    #[arg(long = "xop-true-vmp-prefix")]
    pub xop_true_vmp_prefix: Vec<String>,
    /// 关键方法清单（UTF-8）：每行 模块名<TAB>完整 DEX 方法描述符。
    #[arg(long, value_name = "FILE")]
    pub pvm2_required_methods: Option<PathBuf>,
    /// Native 证据清单（UTF-8）：模块/lib/ABI/库名.so<TAB>SDK schema 2 报告路径。
    #[arg(long, value_name = "FILE")]
    pub native_vmp_evidence: Option<PathBuf>,
    /// `--engine xop` 时使用的 Xop shell-files 目录。
    #[arg(long, value_name = "DIR")]
    pub xop_shell_dir: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = XopProfileArg::Industry)]
    pub xop_profile: XopProfileArg,
    #[arg(long)]
    pub xop_no_protect_so: bool,
    #[arg(long)]
    pub xop_encrypt_assets: bool,
    #[arg(long)]
    pub xop_enable_res_protect: bool,
    #[arg(long)]
    pub xop_detect_proxy: bool,
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u8).range(0..=2))]
    pub xop_rasp_action: u8,
    #[arg(long, value_delimiter = ',')]
    pub exclude_abis: Vec<String>,
    /// 可选：对最终 AAB 生成 default APKS，便于本地 split 验证。
    #[arg(long, value_name = "APKS")]
    pub apks_output: Option<PathBuf>,
    /// 生成 APKS 后提交到连接的测试设备。
    #[arg(long)]
    pub install_apks: bool,
    /// 可选 bundletool 设备规格；生成 device-specific APKS 以验证目标 ABI/API split。
    #[arg(long, value_name = "JSON")]
    pub device_spec: Option<PathBuf>,
    #[arg(long)]
    pub device_id: Option<String>,
    /// 安装后用 monkey 启动并通过 pidof 检查进程仍存活。
    #[arg(long, value_name = "PACKAGE")]
    pub smoke_package: Option<String>,
    #[arg(long)]
    pub json: bool,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum XopProfileArg {
    Balanced,
    #[default]
    Industry,
    Aggressive,
    Perf,
    Max,
}

impl XopProfileArg {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Balanced => "balanced",
            Self::Industry => "industry",
            Self::Aggressive => "aggressive",
            Self::Perf => "perf",
            Self::Max => "max",
        }
    }
}

#[derive(Args, Default)]
pub(crate) struct ProtectXopArgs {
    #[arg(short, long, value_name = "APK")]
    pub input: PathBuf,
    #[arg(short, long, value_name = "APK")]
    pub output: PathBuf,
    /// 已构建的 Xop protector-packer fat JAR。
    #[arg(long, value_name = "JAR")]
    pub packer: PathBuf,
    /// Xop exportShellFiles 生成的 shell-files 目录。
    #[arg(long, value_name = "DIR")]
    pub shell_dir: PathBuf,
    /// 输出 APK 的签名 keystore；默认必填，确保产物可直接安装。
    #[arg(long, value_name = "KEYSTORE")]
    pub ks: Option<PathBuf>,
    #[arg(long)]
    pub key_alias: Option<String>,
    #[arg(long, env = "MOCIKA_SHIELD_KS_PASS", hide_env_values = true)]
    pub ks_pass: Option<String>,
    #[arg(long, env = "MOCIKA_SHIELD_KEY_PASS", hide_env_values = true)]
    pub key_pass: Option<String>,
    #[arg(long, value_enum, default_value_t = KeystoreTypeArg::Jks)]
    pub ks_type: KeystoreTypeArg,
    #[arg(long, value_name = "JAR")]
    pub apksigner: Option<PathBuf>,
    /// 仅生成未签名中间 APK；不能作为安装包或发布包。
    #[arg(long)]
    pub allow_unsigned: bool,
    #[arg(long, value_enum, default_value_t = XopProfileArg::Industry)]
    pub profile: XopProfileArg,
    #[arg(long, value_enum, default_value_t = AiResistanceArg::High)]
    pub ai_resistance: AiResistanceArg,
    #[arg(long = "hollow-prefix")]
    pub hollow_prefix: Vec<String>,
    #[arg(long = "vmp-prefix")]
    pub vmp_prefix: Vec<String>,
    #[arg(long = "true-vmp-prefix")]
    pub true_vmp_prefix: Vec<String>,
    #[arg(long)]
    pub no_protect_so: bool,
    #[arg(long)]
    pub encrypt_assets: bool,
    #[arg(long)]
    pub enable_res_protect: bool,
    #[arg(long)]
    pub detect_proxy: bool,
    /// 0=alert, 1=degrade, 2=block。
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u8).range(0..=2))]
    pub rasp_action: u8,
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Default)]
pub(crate) struct ProtectArgs {
    #[command(flatten)]
    pub runtime_ui: RuntimeUiArgs,
    /// 明确排除不需要且不受支持的 ABI（逗号分隔），仅对本次任务有效。
    #[arg(long, value_delimiter = ',')]
    pub exclude_abis: Vec<String>,
    #[arg(short, long, value_name = "APK")]
    pub input: Option<PathBuf>,
    #[arg(short, long, value_name = "APK")]
    pub output: Option<PathBuf>,
    #[arg(long, value_name = "JAR")]
    pub apktool: Option<PathBuf>,
    /// 内部回归测试使用的运行时资源包。
    #[arg(long, value_name = "ZIP", hide = true)]
    pub resources: Option<PathBuf>,
    #[arg(long, value_name = "JAR")]
    pub apksigner: Option<PathBuf>,
    /// 运行时环境策略：兼容模式仅执行反调试，严格模式额外拒绝高置信 Root 环境。
    #[arg(long, value_enum)]
    pub environment_policy: Option<EnvironmentPolicyArg>,
    /// 保护级别：compat、balanced 或 strict。
    #[arg(long, value_enum)]
    pub profile: Option<ProtectionProfileArg>,
    /// 额外保护策略等级；新包统一单层压缩，效果以逐方法覆盖和产物验证为准。
    #[arg(long, value_enum)]
    pub ai_resistance: Option<AiResistanceArg>,
    /// Xop transform-only Packer JAR；仅嵌入 PVM2，不引入第二个 Application/JNI 壳。
    #[arg(long, value_name = "JAR")]
    pub xop_pvm2_packer: Option<PathBuf>,
    /// 要交给 Xop PVM2 的 DEX 类型描述符前缀，可重复传入（例如 Lcom/example/pay/）。
    #[arg(long = "xop-true-vmp-prefix")]
    pub xop_true_vmp_prefix: Vec<String>,
    /// 关键方法清单（UTF-8）：每行 模块名<TAB>完整 DEX 方法描述符。
    #[arg(long, value_name = "FILE")]
    pub pvm2_required_methods: Option<PathBuf>,
    /// Native 证据清单（UTF-8）：模块/lib/ABI/库名.so<TAB>SDK schema 2 报告路径。
    #[arg(long, value_name = "FILE")]
    pub native_vmp_evidence: Option<PathBuf>,
    /// 每行输出一个 JSON 事件，兼容原有 --json-progress 参数。
    #[arg(long, alias = "json-progress")]
    pub json: bool,
    #[arg(short, long)]
    pub verbose: bool,
}

#[derive(Args, Default)]
pub(crate) struct SignArgs {
    #[arg(short, long, value_name = "APK")]
    pub input: Option<PathBuf>,
    #[arg(short, long, value_name = "APK")]
    pub output: Option<PathBuf>,
    #[arg(long, value_name = "KEYSTORE")]
    pub ks: Option<PathBuf>,
    #[arg(long)]
    pub key_alias: Option<String>,
    /// Keystore 密码；自动化环境优先使用 MOCIKA_SHIELD_KS_PASS。
    #[arg(long, env = "MOCIKA_SHIELD_KS_PASS", hide_env_values = true)]
    pub ks_pass: Option<String>,
    /// Key 密码；未提供时沿用 Keystore 密码。
    #[arg(long, env = "MOCIKA_SHIELD_KEY_PASS", hide_env_values = true)]
    pub key_pass: Option<String>,
    #[arg(long, value_enum)]
    pub ks_type: Option<KeystoreTypeArg>,
    #[arg(long, value_name = "JAR")]
    pub apksigner: Option<PathBuf>,
    #[arg(long)]
    pub v1: Option<bool>,
    #[arg(long)]
    pub v2: Option<bool>,
    #[arg(long)]
    pub v3: Option<bool>,
    #[arg(long)]
    pub v4: Option<bool>,
    /// 每行输出一个 JSON 事件。
    #[arg(long)]
    pub json: bool,
}

/// APK/AAB 共用界面保护参数；Option 保留命令行覆盖配置文件的语义。
#[derive(Args, Default)]
pub struct RuntimeUiArgs {
    /// 防止受保护窗口被系统截图；不阻止视图树读取。
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    pub secure_screen: Option<bool>,
    /// 防截图例外，使用完整 Activity 类名；逗号分隔。
    #[arg(long, value_delimiter = ',')]
    pub screen_exempt_activities: Option<Vec<String>>,
    /// 调试环境策略：off、report、block；block 对未知状态也拒绝运行。
    #[arg(long)]
    pub adb_policy: Option<shield_core::AdbPolicy>,
    /// 在应用前台定期复查已有反调试/Root 策略。
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    pub runtime_recheck: Option<bool>,
    /// 保守混淆可安全改名的资源 id 条目（暂仅 APK）。
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    pub obfuscate_resource_names: Option<bool>,
    /// 资源条目保留名；逗号分隔。
    #[arg(long, value_delimiter = ',')]
    pub resource_name_keep: Option<Vec<String>>,
    /// 界面/资源变换器 JAR；默认查找随包分发的 xop-pvm2-packer.jar。
    #[arg(long, value_name = "JAR")]
    pub ui_packer: Option<PathBuf>,
}

impl RuntimeUiArgs {
    pub fn resolve(
        &self,
        mut base: shield_core::RuntimeUiProtection,
    ) -> anyhow::Result<shield_core::RuntimeUiProtection> {
        if let Some(v) = self.secure_screen {
            base.secure_screen = v;
            if !v {
                base.screen_exempt_activities.clear();
            }
        }
        if let Some(v) = &self.screen_exempt_activities {
            base.screen_exempt_activities = v.clone();
        }
        if let Some(v) = self.adb_policy {
            base.adb_policy = v;
        }
        if let Some(v) = self.runtime_recheck {
            base.runtime_recheck = v;
        }
        if let Some(v) = self.obfuscate_resource_names {
            base.obfuscate_resource_names = v;
            if !v {
                base.resource_name_keep.clear();
            }
        }
        if let Some(v) = &self.resource_name_keep {
            base.resource_name_keep = v.clone();
        }
        base.validate()?;
        Ok(base)
    }

    #[allow(dead_code)] // GUI 通过库入口使用，CLI 二进制不调用。
    pub fn from_options(v: shield_core::RuntimeUiProtection, ui_packer: Option<PathBuf>) -> Self {
        Self {
            secure_screen: Some(v.secure_screen),
            screen_exempt_activities: Some(v.screen_exempt_activities),
            adb_policy: Some(v.adb_policy),
            runtime_recheck: Some(v.runtime_recheck),
            obfuscate_resource_names: Some(v.obfuscate_resource_names),
            resource_name_keep: Some(v.resource_name_keep),
            ui_packer,
        }
    }
}
