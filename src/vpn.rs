use clap::{Args, Subcommand};
use serde::{Serialize, Serializer};
use std::fmt::Debug;
use log::debug;

use crate::config::{Config, VpnConfig};
use crate::password_manager::PasswordManager;

#[derive(Args, Debug)]
pub struct VpnArgs {
    #[command(subcommand)]
    command: VpnCommands,
}

#[derive(Subcommand, Debug)]
pub enum VpnCommands {
    On,
    Off,
    Status,
}

pub trait VpnApp: Debug {
    fn connect(&self, args: &VpnArgs, config: &VpnConfig, password_manager: &Box<dyn PasswordManager>) -> anyhow::Result<()>;
    fn disconnect(&self, args: &VpnArgs, config: &VpnConfig) -> anyhow::Result<()>;
    fn status(&self, args: &VpnArgs, config: &VpnConfig) -> anyhow::Result<()>;
    fn to_str(&self) -> &str;
}

impl Serialize for dyn VpnApp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_str())
    }
}

pub fn run(args: &VpnArgs, config: &Config) -> anyhow::Result<()> {
    let vpn_app = &config.vpn_app;
    let vpn_config = &config.vpn;
    let password_manager = &config.password_manager;

    debug!{"vpn command"};
    match &args.command {
        VpnCommands::On => vpn_app.connect(args, &vpn_config, password_manager)?,
        VpnCommands::Off => vpn_app.disconnect(args, &vpn_config)?,
        VpnCommands::Status => vpn_app.status(args, &vpn_config)?,
    }

    Ok(())
}
