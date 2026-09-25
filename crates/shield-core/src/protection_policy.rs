use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// 用户可选择的保护级别。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ProtectionProfile {
    Compat,
    #[default]
    Balanced,
    Strict,
}

impl ProtectionProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Compat => "compat",
            Self::Balanced => "balanced",
            Self::Strict => "strict",
        }
    }
}

impl FromStr for ProtectionProfile {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "compat" | "compatible" => Ok(Self::Compat),
            "balanced" | "balance" => Ok(Self::Balanced),
            "strict" => Ok(Self::Strict),
            _ => Err(format!(
                "保护级别仅支持 compat、balanced 或 strict，收到 {value}"
            )),
        }
    }
}

/// 面向 AI 静态语义恢复的额外保护强度。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum AiResistance {
    Off,
    #[default]
    Balanced,
    High,
}

impl AiResistance {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Balanced => "balanced",
            Self::High => "high",
        }
    }

    /// DEXB v6 的实际压缩层数，范围固定为 1..=3。
    pub fn compression_layers(self) -> u8 {
        match self {
            Self::Off => 1,
            Self::Balanced => 2,
            Self::High => 3,
        }
    }
}

impl FromStr for AiResistance {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" | "disabled" => Ok(Self::Off),
            "balanced" | "default" => Ok(Self::Balanced),
            "high" | "strict" => Ok(Self::High),
            _ => Err(format!(
                "AI 分析抵抗级别仅支持 off、balanced 或 high，收到 {value}"
            )),
        }
    }
}

/// Packer 侧的保护决策。该结构只描述目标能力，不绕过运行时能力检测。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectionPolicy {
    pub profile: ProtectionProfile,
    pub ai_resistance: AiResistance,
    pub pvm2: bool,
    pub hollow: bool,
    pub string_jit: bool,
    pub native_safe: bool,
    pub memory_preferred: bool,
}

impl Default for ProtectionPolicy {
    fn default() -> Self {
        Self::for_profile(ProtectionProfile::Balanced, AiResistance::Balanced)
    }
}

impl ProtectionPolicy {
    pub fn for_profile(profile: ProtectionProfile, ai_resistance: AiResistance) -> Self {
        match profile {
            ProtectionProfile::Compat => Self {
                profile,
                ai_resistance,
                pvm2: false,
                hollow: true,
                string_jit: !matches!(ai_resistance, AiResistance::Off),
                native_safe: false,
                memory_preferred: false,
            },
            ProtectionProfile::Balanced => Self {
                profile,
                ai_resistance,
                pvm2: true,
                hollow: true,
                string_jit: !matches!(ai_resistance, AiResistance::Off),
                native_safe: true,
                memory_preferred: false,
            },
            ProtectionProfile::Strict => Self {
                profile,
                ai_resistance,
                pvm2: true,
                hollow: true,
                string_jit: true,
                native_safe: true,
                memory_preferred: true,
            },
        }
    }

    /// 设备侧能力协商。API19–22 不启用 Xop 高级 Native 能力，避免把不兼容
    /// 的保护策略强行写入旧系统 APK。
    pub fn negotiate(self, api_level: u32, abi: &str, memory_candidate: bool) -> CapabilityPlan {
        let modern_abi = matches!(abi, "armeabi-v7a" | "arm64-v8a" | "x86" | "x86_64");
        let native_available = api_level >= 23 && modern_abi;
        let memory_available = api_level >= 31 && memory_candidate && native_available;

        CapabilityPlan {
            profile: self.profile,
            ai_resistance: self.ai_resistance,
            pvm2: self.pvm2 && native_available,
            hollow: self.hollow,
            string_jit: self.string_jit,
            native_safe: self.native_safe && native_available,
            memory_loader: self.memory_preferred && memory_available,
            fallback: if native_available {
                "hollow_then_dex"
            } else {
                "dex_file"
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityPlan {
    pub profile: ProtectionProfile,
    pub ai_resistance: AiResistance,
    pub pvm2: bool,
    pub hollow: bool,
    pub string_jit: bool,
    pub native_safe: bool,
    pub memory_loader: bool,
    pub fallback: &'static str,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 兼容模式在旧系统关闭高级_native能力() {
        let plan = ProtectionPolicy::default().negotiate(21, "armeabi-v7a", true);
        assert!(!plan.pvm2);
        assert!(!plan.native_safe);
        assert!(!plan.memory_loader);
        assert_eq!(plan.fallback, "dex_file");
    }

    #[test]
    fn 严格模式仅在现代系统和候选资源同时存在时使用内存加载() {
        let policy = ProtectionPolicy::for_profile(ProtectionProfile::Strict, AiResistance::High);
        assert!(!policy.negotiate(30, "arm64-v8a", true).memory_loader);
        assert!(policy.negotiate(31, "arm64-v8a", true).memory_loader);
        assert!(!policy.negotiate(31, "mips", true).memory_loader);
    }

    #[test]
    fn 配置字符串可解析() {
        assert_eq!(
            "balanced".parse::<ProtectionProfile>().unwrap(),
            ProtectionProfile::Balanced
        );
        assert_eq!("high".parse::<AiResistance>().unwrap(), AiResistance::High);
        assert!("unknown".parse::<ProtectionProfile>().is_err());
    }

    #[test]
    fn ai_resistance_selects_bounded_compression_layers() {
        assert_eq!(AiResistance::Off.compression_layers(), 1);
        assert_eq!(AiResistance::Balanced.compression_layers(), 2);
        assert_eq!(AiResistance::High.compression_layers(), 3);
    }
}
