//! Shellsmith/Xop 融合边界。
//!
//! 这一层只描述跨项目必须保持一致的协议和降级契约，不把 Xop 的第二套
//! Application、JNI 入口或解密缓存偷偷嵌套进 Shellsmith。真正接入 Xop 变换时，
//! 只能实现本契约并复用现有 DEXB v6 与 Stub 生命周期。

use crate::protection_policy::{AiResistance, ProtectionProfile};

pub const FUSION_CONTRACT_VERSION: u32 = 1;
pub const DEXB_PROTOCOL_VERSION: u32 = 6;
pub const XOP_ADAPTER_PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XopCapability {
    Hollow,
    Pvm2,
    NativeSo,
    RuntimeRasp,
}

/// Xop transform-only 适配器向 Shellsmith Stub 声明的最小边界。
///
/// 仅有一个外部 Packer JAR 或一个“能力清单”不能使适配器就绪；调用方必须
/// 同时证明变换只产生 DEXB v6，并且复用 Shellsmith 的单一 Stub 生命周期。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XopAdapterContract {
    pub protocol_version: u32,
    pub dex_protocol_version: u32,
    pub transform_only: bool,
    pub single_stub_runtime: bool,
    pub capabilities: Vec<XopCapability>,
}

impl XopAdapterContract {
    pub fn validate(&self) -> Result<(), String> {
        if self.protocol_version != XOP_ADAPTER_PROTOCOL_VERSION {
            return Err(format!(
                "不支持的 Xop 适配器协议：{}，期望 {}",
                self.protocol_version, XOP_ADAPTER_PROTOCOL_VERSION
            ));
        }
        if self.dex_protocol_version != DEXB_PROTOCOL_VERSION {
            return Err(format!(
                "Xop 适配器必须输出 DEXB v{}，实际为 v{}",
                DEXB_PROTOCOL_VERSION, self.dex_protocol_version
            ));
        }
        if !self.transform_only {
            return Err("Xop 适配器必须是 transform-only，禁止嵌套第二套壳".to_string());
        }
        if !self.single_stub_runtime {
            return Err("Xop 适配器必须复用 Shellsmith 单一 Stub 生命周期".to_string());
        }
        if self.capabilities.is_empty() {
            return Err("Xop 适配器未声明任何能力".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FusionPlan {
    pub contract_version: u32,
    pub dex_protocol_version: u32,
    pub profile: ProtectionProfile,
    pub ai_resistance: AiResistance,
    pub requested_xop_capabilities: Vec<XopCapability>,
    pub xop_pvm2_embedded: bool,
    pub xop_adapter_ready: bool,
    pub single_shell_required: bool,
}

impl FusionPlan {
    /// 生成一份可审计的融合计划。v1 严格档位只把已经具备单壳接入路径的
    /// PVM2 作为必需 Xop 能力；Hollow/SO/RASP 在真正融合前不进入请求集合。
    pub fn for_policy(profile: ProtectionProfile, ai_resistance: AiResistance) -> Self {
        let mut requested_xop_capabilities = Vec::new();
        if !matches!(profile, ProtectionProfile::Compat)
            && !matches!(ai_resistance, AiResistance::Off)
        {
            requested_xop_capabilities.push(XopCapability::Pvm2);
        }

        Self {
            contract_version: FUSION_CONTRACT_VERSION,
            dex_protocol_version: DEXB_PROTOCOL_VERSION,
            profile,
            ai_resistance,
            requested_xop_capabilities,
            xop_pvm2_embedded: false,
            xop_adapter_ready: false,
            single_shell_required: true,
        }
    }

    pub fn status(&self) -> &'static str {
        if self.xop_adapter_ready {
            "xop-adapter-ready"
        } else if self.xop_pvm2_embedded {
            "xop-pvm2-embedded"
        } else {
            "xop-contract-only"
        }
    }

    /// 只提升已真实接入的 PVM2 子能力，不把 Hollow/SO/RASP 冒充为完整适配器。
    pub fn with_embedded_pvm2(mut self) -> Self {
        self.xop_pvm2_embedded = true;
        self
    }

    /// 严格档位至少要求真实的 PVM2 单壳嵌入；完整适配器就绪后也满足该门禁。
    /// Hollow/SO/RASP 未接入时仍保持 `xop-pvm2-embedded`，不冒充完整适配器。
    pub fn satisfies_profile(&self) -> bool {
        !matches!(self.profile, ProtectionProfile::Strict)
            || self.xop_pvm2_embedded
            || self.xop_adapter_ready
    }

    /// 只有通过契约校验的 transform-only 适配器才能把计划提升为 ready。
    pub fn attach_xop_adapter(mut self, adapter: XopAdapterContract) -> Result<Self, String> {
        adapter.validate()?;
        self.xop_adapter_ready = true;
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 兼容模式不会请求_pvm2() {
        let plan = FusionPlan::for_policy(ProtectionProfile::Compat, AiResistance::Balanced);
        assert!(!plan
            .requested_xop_capabilities
            .contains(&XopCapability::Pvm2));
        assert_eq!(plan.dex_protocol_version, 6);
        assert!(plan.single_shell_required);
    }

    #[test]
    fn 严格模式只要求当前已接入的_pvm2() {
        let plan = FusionPlan::for_policy(ProtectionProfile::Strict, AiResistance::High);
        assert!(plan
            .requested_xop_capabilities
            .contains(&XopCapability::Pvm2));
        assert!(!plan
            .requested_xop_capabilities
            .contains(&XopCapability::NativeSo));
        assert!(!plan
            .requested_xop_capabilities
            .contains(&XopCapability::RuntimeRasp));
        assert!(!plan
            .requested_xop_capabilities
            .contains(&XopCapability::Hollow));
        assert!(!plan.xop_adapter_ready);
        assert_eq!(plan.status(), "xop-contract-only");
    }

    #[test]
    fn 适配器必须声明单壳和_dexb_v6() {
        let plan = FusionPlan::for_policy(ProtectionProfile::Balanced, AiResistance::Balanced);
        let adapter = XopAdapterContract {
            protocol_version: XOP_ADAPTER_PROTOCOL_VERSION,
            dex_protocol_version: DEXB_PROTOCOL_VERSION,
            transform_only: true,
            single_stub_runtime: true,
            capabilities: vec![XopCapability::Hollow, XopCapability::Pvm2],
        };
        assert_eq!(
            plan.attach_xop_adapter(adapter).unwrap().status(),
            "xop-adapter-ready"
        );

        let nested = XopAdapterContract {
            transform_only: false,
            ..XopAdapterContract {
                protocol_version: XOP_ADAPTER_PROTOCOL_VERSION,
                dex_protocol_version: DEXB_PROTOCOL_VERSION,
                transform_only: true,
                single_stub_runtime: true,
                capabilities: vec![XopCapability::Hollow],
            }
        };
        assert!(
            FusionPlan::for_policy(ProtectionProfile::Balanced, AiResistance::Balanced)
                .attach_xop_adapter(nested)
                .is_err()
        );
    }

    #[test]
    fn pvm2_embedded_does_not_claim_full_adapter() {
        let plan = FusionPlan::for_policy(ProtectionProfile::Strict, AiResistance::High)
            .with_embedded_pvm2();
        assert!(plan.xop_pvm2_embedded);
        assert!(!plan.xop_adapter_ready);
        assert_eq!(plan.status(), "xop-pvm2-embedded");
        assert!(plan.satisfies_profile());
    }

    #[test]
    fn strict_without_runtime_transform_fails_closed() {
        let strict = FusionPlan::for_policy(ProtectionProfile::Strict, AiResistance::High);
        assert!(!strict.satisfies_profile());
        assert!(
            FusionPlan::for_policy(ProtectionProfile::Balanced, AiResistance::High)
                .satisfies_profile()
        );
    }
}
