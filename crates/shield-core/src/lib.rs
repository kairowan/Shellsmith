pub mod apk_inspect;
pub mod bundle_inspect;
mod dex_packer;
#[cfg(test)]
mod dex_research;
pub mod diagnostic;
pub mod error;
pub mod fusion_contract;
pub mod keytool;
#[doc(hidden)]
pub mod local_secret;
mod native_vmp;
mod preflight;
pub mod project_protection;
mod protect;
mod protect_api;
pub mod protection_policy;
pub mod protection_report;
pub mod runtime_ui;
pub use runtime_ui::{AdbPolicy, RuntimeUiProtection};
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
    check_apksigner, find_apksigner, sign_apk, sign_apk_with_progress, write_password_file,
    KeystoreType, SignOptions, SigningProgressStep, SigningVersions,
};
pub use zipalign::{align_apk, verify_apk_alignment, AlignmentIssue};
#[cfg(test)]
mod byos_tests;
mod remote_key;

pub use remote_key::validate_options as validate_byos_options;
pub use remote_key::{check_connection as check_byos_connection, ByosAuth, ByosConnectionCheck};
