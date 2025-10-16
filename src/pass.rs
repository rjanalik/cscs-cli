use std::process::Command;
//use std::io;
//use std::io::Write;
//use std::process::Stdio;
use anyhow::{anyhow, bail};
use log::debug;

//use crate::config::VpnConfig;
use crate::password_manager::{Credentials, PasswordManager};

#[derive(Debug, Default)]
pub struct Pass;

impl PasswordManager for Pass {
    fn get_credentials(&self, pass_service: String, username: String) -> anyhow::Result<Credentials> {
        debug!("Getting credentials from pass: service {}, username {}", pass_service, username);

        let pass_name = format!("{}/{}", pass_service, username);
        let password: String;
        let totp: Option<String>;

        // Get password
        let mut password_command = Command::new("pass");
        password_command.arg(&pass_name);

        let password_output = password_command.output()?;
        if password_output.status.success() {
            let password_stdout_string = String::from_utf8(password_output.stdout)?;
            password = password_stdout_string
                .lines()
                .next()
                .ok_or_else(|| anyhow!("Pass command returned empty output."))?
                .trim()
                .to_string();
        } else {
            bail!("pass failed with status: {}", password_output.status);
        }

        // Get TOTP
        let mut totp_command = Command::new("pass");
        totp_command.arg("otp");
        totp_command.arg(&pass_name);

        let totp_output = totp_command.output()?;
        if totp_output.status.success() {
            let totp_stdout_string = String::from_utf8(totp_output.stdout)?;
            let totp_string = totp_stdout_string
                .trim()
                .to_string();
            totp = Some(totp_string);
        } else {
            bail!("pass otp failed with status: {}", totp_output.status);
        }

        let credentials = Credentials{
            username: username,
            password: password,
            totp: totp,
        };

        Ok(credentials)
    }

    fn to_str(&self) -> &str {
        "pass"
    }
}
