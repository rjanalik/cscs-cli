use clap::{Args, Subcommand};
//use tokio::process::{Command, Stdio};
use tokio::process::{Command};
use tokio::io::AsyncWriteExt;
use std::io;
use std::io::Write;
use std::process::Stdio;
use anyhow::{anyhow, bail};
use log::debug;

use crate::config::VpnConfig;
use crate::pass::get_credentials;

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

pub async fn run(args: &VpnArgs, config: &VpnConfig) -> anyhow::Result<()> {
    debug!{"vpn command"};
    match &args.command {
        VpnCommands::On => connect(args, config).await?,
        VpnCommands::Off => disconnect(args, config).await?,
        VpnCommands::Status => status(args, config).await?,
    }

    Ok(())
}

async fn connect(args: &VpnArgs, config: &VpnConfig) -> anyhow::Result<()> {
    debug!("vpn on subcommand");
    debug!("{:?}", args);
    debug!("{:?}", config);

    let credentials = get_credentials(config.pass_service.clone(), config.username.clone()).await?;

    let mut command = Command::new(&config.client.path);
    command.args(&config.client.connect_args);
    command.arg(&config.host);

    command.stdin(Stdio::piped());

    debug!("calling command: {:?}", command.as_std());
    let mut child = command.spawn()?;

    let input_string = config.client.connect_stdin_template
        .replace("{username}", &credentials.username)
        .replace("{domain}", &config.domain)
        .replace("{password}", &credentials.password)
        .replace("{totp}", &credentials.totp.unwrap());

    let mut child_stdin = child.stdin.take().ok_or_else(|| {
        anyhow!("Failed to open stdin for child process.")
    })?;
    child_stdin.write_all(input_string.as_bytes()).await?;

    let output = child.wait_with_output().await?;
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

async fn disconnect(args: &VpnArgs, config: &VpnConfig) -> anyhow::Result<()> {
    debug!("vpn off subcommand");
    debug!("{:?}", args);
    debug!("{:?}", config);

    let mut command = Command::new(&config.client.path);
    command.args(&config.client.disconnect_args);

    debug!("calling command: {:?}", command.as_std());
    let output = command.output().await?;
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

async fn status(args: &VpnArgs, config: &VpnConfig) -> anyhow::Result<()> {
    debug!("vpn status subcommand");
    debug!("{:?}", args);
    debug!("{:?}", config);

    let mut command = Command::new(&config.client.path);
    command.args(&config.client.status_args);

    debug!("calling command: {:?}", command.as_std());
    let output = command.output().await?;
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
