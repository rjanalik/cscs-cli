use std::io;
use std::io::Write;
use std::process::{Command, Stdio};
use anyhow::{anyhow, bail};
use log::debug;

use crate::config::VpnConfig;
use crate::password_manager::PasswordManager;
use crate::vpn::{VpnArgs,VpnApp};

#[derive(Debug, Default)]
pub struct CiscoSecureConnect;

impl VpnApp for CiscoSecureConnect {
    fn connect(&self, args: &VpnArgs, config: &VpnConfig, password_manager: &Box<dyn PasswordManager>) -> anyhow::Result<()> {
        debug!("vpn on subcommand");
        debug!("{:?}", args);
        debug!("{:?}", config);

        let credentials = password_manager.get_credentials(config.pass_service.clone(), config.username.clone())?;

        let mut command = Command::new(&config.cisco.path);
        command.args(["-s", "connect", &config.host]);

        command.stdin(Stdio::piped());

        debug!("calling command: {:?}", command);
        let mut child = command.spawn()?;

        let input_string = format!("{}@{}\n{}\n{}\n",
            &credentials.username,
            &config.domain,
            &credentials.password,
            &credentials.totp.unwrap());

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

    fn disconnect(&self, args: &VpnArgs, config: &VpnConfig) -> anyhow::Result<()> {
        debug!("vpn off subcommand");
        debug!("{:?}", args);
        debug!("{:?}", config);

        let mut command = Command::new(&config.cisco.path);
        command.args(["-s", "disconnect"]);

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

    fn status(&self, args: &VpnArgs, config: &VpnConfig) -> anyhow::Result<()> {
        debug!("vpn status subcommand");
        debug!("{:?}", args);
        debug!("{:?}", config);

        let mut command = Command::new(&config.cisco.path);
        command.args(["-s", "status"]);

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

    fn to_str(&self) -> &str {
        "cisco"
    }
}
