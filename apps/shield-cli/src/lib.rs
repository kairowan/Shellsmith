// ponytail: the library exposes the already-tested AAB command path to the GUI;
// binary-only handlers share the same module and are intentionally unused here.
#![allow(dead_code)]

mod args;
mod cli_json;
mod commands;
mod config;

pub use args::{
    AiResistanceArg, EnvironmentPolicyArg, KeystoreTypeArg, ProtectAabArgs, ProtectionEngineArg,
    ProtectionProfileArg, XopProfileArg,
};
pub use commands::{run_check_aab, run_protect_aab_with_control};
pub use shield_core::*;
