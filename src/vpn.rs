use clap::{Args, Subcommand};
use std::io;
use std::io::Write;
use std::process::{Command, Stdio};
use anyhow::{anyhow, bail};
use log::debug;

use crate::config::{Config, VpnConfig};
use crate::password_manager::PasswordManager;

#[derive(Args, Debug)]
pub struct VpnArgs {
    #[command(subcommand)]
    command: VpnCommands,
}

#[derive(Subcommand, Debug)]
enum VpnCommands {
    On,
    Off,
    Status,
}

pub fn run(args: &VpnArgs, config: &Config) -> anyhow::Result<()> {
    let vpn_config = &config.vpn;
    let password_manager = &config.password_manager;

    debug!{"vpn command"};
    match &args.command {
        VpnCommands::On => connect(args, &vpn_config, password_manager)?,
        VpnCommands::Off => disconnect(args, &vpn_config)?,
        VpnCommands::Status => status(args, &vpn_config)?,
    }

    Ok(())
}

fn connect(args: &VpnArgs, config: &VpnConfig, password_manager: &Box<dyn PasswordManager>) -> anyhow::Result<()> {
    debug!("vpn on subcommand");
    debug!("{:?}", args);
    debug!("{:?}", config);

    let credentials = password_manager.get_credentials(config.pass_service.clone(), config.username.clone())?;

    let mut command = Command::new(&config.client.path);
    command.args(&config.client.connect_args);
    command.arg(&config.host);

    command.stdin(Stdio::piped());

    debug!("calling command: {:?}", command);
    let mut child = command.spawn()?;

    let input_string = config.client.connect_stdin_template
        .replace("{username}", &credentials.username)
        .replace("{domain}", &config.domain)
        .replace("{password}", &credentials.password)
        .replace("{totp}", &credentials.totp.unwrap());

    let mut child_stdin = child.stdin.take().ok_or_else(|| {
        anyhow!("Failed to open stdin for child process.")
    })?;
    child_stdin.write_all(input_string.as_bytes())?;

    let output = child.wait_with_output()?;
    if output.status.success() {
        println!("VPN connected!");
        if !output.stdout.is_empty() {
            println!("VPN connect stdout:");
            io::stdout().write(&output.stdout)?;
            io::stdout().flush()?;
        }
    } else {
        eprintln!("VPN connection failed with status: {}", output.status);
        if !output.stderr.is_empty() {
            eprintln!("VPN connect stderr:");
            io::stderr().write(&output.stderr)?;
            io::stderr().flush()?;
        }
        bail!("VPN connection failed.");
    }

    Ok(())
}

fn disconnect(args: &VpnArgs, config: &VpnConfig) -> anyhow::Result<()> {
    debug!("vpn off subcommand");
    debug!("{:?}", args);
    debug!("{:?}", config);

    let mut command = Command::new(&config.client.path);
    command.args(&config.client.disconnect_args);

    debug!("calling command: {:?}", command);
    let output = command.output()?;
    if output.status.success() {
        println!("VPN disconnected!");
        if !output.stdout.is_empty() {
            println!("VPN disconnect stdout:");
            io::stdout().write(&output.stdout)?;
            io::stdout().flush()?;
        }
    } else {
        eprintln!("VPN disconnection failed with status: {}", output.status);
        if !output.stderr.is_empty() {
            eprintln!("VPN disconnect stderr:");
            io::stderr().write(&output.stderr)?;
            io::stderr().flush()?;
        }
        bail!("VPN disconnect failed.");
    }

    Ok(())
}

fn status(args: &VpnArgs, config: &VpnConfig) -> anyhow::Result<()> {
    debug!("vpn status subcommand");
    debug!("{:?}", args);
    debug!("{:?}", config);

    let mut command = Command::new(&config.client.path);
    command.args(&config.client.status_args);

    debug!("calling command: {:?}", command);
    let output = command.output()?;
    if output.status.success() {
        if !output.stdout.is_empty() {
            println!("VPN status stdout:");
            io::stdout().write(&output.stdout)?;
            io::stdout().flush()?;
        }
    } else {
        eprintln!("VPN status failed with status: {}", output.status);
        if !output.stderr.is_empty() {
            eprintln!("VPN status stderr:");
            io::stderr().write(&output.stderr)?;
            io::stderr().flush()?;
        }
        bail!("VPN disconnect failed.");
    }

    Ok(())
}
