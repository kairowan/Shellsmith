use anyhow::Result;
use clap::Parser;

mod args;
mod cli_json;
mod commands;
mod config;

use args::{Cli, Commands};
use cli_json::error_event_json;
use commands::{
    run_check_aab, run_check_apk, run_check_ios, run_check_keystore, run_install_apks, run_protect,
    run_protect_aab, run_protect_ios, run_protect_xop, run_sign,
};
use config::CliConfig;

fn main() {
    let cli = Cli::parse();
    let machine_output = cli.command.machine_output();
    if let Err(error) = execute(cli) {
        if machine_output {
            println!("{}", error_event_json(format!("{error:#}")));
        } else {
            eprintln!("{error:#}");
        }
        std::process::exit(1);
    }
}

fn execute(cli: Cli) -> Result<()> {
    let config = CliConfig::load(cli.config.as_deref())?;

    match cli.command {
        Commands::Protect(args) => run_protect(config.merge_protect(args)?)?,
        Commands::ProtectAab(args) => run_protect_aab(args)?,
        Commands::ProtectXop(args) => run_protect_xop(args)?,
        Commands::ProtectIos(args) => run_protect_ios(args)?,
        Commands::Sign(args) => run_sign(config.merge_sign(args)?)?,
        Commands::CheckApk { path } => {
            let result = run_check_apk(path)?;
            println!("{result}");
        }
        Commands::CheckAab {
            path,
            bundletool,
            apks_output,
            device_spec,
            apks_mode,
            ks,
            ks_alias,
            ks_pass,
        } => {
            let result = run_check_aab(
                path,
                bundletool,
                apks_output,
                device_spec,
                apks_mode,
                ks,
                ks_alias,
                ks_pass,
            )?;
            println!("{result}");
        }
        Commands::CheckIos { project, scheme } => {
            let result = run_check_ios(project, scheme.as_deref())?;
            println!("{result}");
        }
        Commands::CheckKeystore { ks, alias, ks_pass } => {
            let result = run_check_keystore(ks, alias, ks_pass)?;
            println!("{result}");
        }
        Commands::InstallApks {
            path,
            bundletool,
            device_id,
        } => run_install_apks(path, bundletool, device_id.as_deref())?,
    }

    Ok(())
}
