pub mod apk_inspect;
pub mod bundle_inspect;
mod dex_packer;
#[cfg(test)]
mod dex_research;
pub mod diagnostic;
pub mod error;
pub mod fusion_contract;
pub mod keytool;
mod preflight;
mod protect;
mod protect_api;
pub mod protection_policy;
pub mod signing;
pub mod utils;
pub mod zipalign;

pub use apk_inspect::{
    check_apk, extract_apk_cert_fingerprint, extract_keystore_cert_fingerprint,
    normalize_fingerprint, ApkCheckOutcome,
};
pub use bundle_inspect::{
    inspect_aab, validate_aab_for_module_processing, AabInspection, AabModuleInspection,
};
pub use error::ShieldError;
pub use fusion_contract::{
    FusionPlan, XopAdapterContract, XopCapability, DEXB_PROTOCOL_VERSION, FUSION_CONTRACT_VERSION,
    XOP_ADAPTER_PROTOCOL_VERSION,
};
pub use preflight::{
    preflight_apk, PreflightCheck, PreflightFacts, PreflightOptions, PreflightReport,
    PreflightSeverity, RuntimeProfile,
};
pub use protect_api::{
    protect_apk, EnvironmentPolicy, ProgressEvent, ProgressStep, ProtectOptions,
    XOP_PVM2_MIN_JAVA_MAJOR_VERSION,
};
pub use protection_policy::{AiResistance, CapabilityPlan, ProtectionPolicy, ProtectionProfile};
pub use signing::{
    check_apksigner, find_apksigner, sign_apk, sign_apk_with_progress, KeystoreType, SignOptions,
    SigningProgressStep, SigningVersions,
};
pub use zipalign::{align_apk, verify_apk_alignment, AlignmentIssue};
