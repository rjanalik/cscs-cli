use tokio::process::Command;
//use tokio::io::AsyncWriteExt;
//use std::io;
//use std::io::Write;
//use std::process::Stdio;
use std::fmt::{self, Debug, Formatter};
use anyhow::{anyhow, bail};
use log::debug;

//use crate::config::VpnConfig;

pub struct Credentials {
    pub username: String,
    pub password: String,
    pub totp: Option<String>,
}

impl Debug for Credentials {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .field("password", &"******")
            .field("totp", &"******")
            .finish()
    }
}

pub async fn get_credentials(pass_service: String, username: String) -> anyhow::Result<Credentials> {
    debug!("Getting credentials from pass: service {}, username {}", pass_service, username);

    let pass_name = format!("{}/{}", pass_service, username);
    let password: String;
    let totp: Option<String>;

    // Get password
    let mut password_command = Command::new("pass");
    password_command.arg(&pass_name);

    let password_output = password_command.output().await?;
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

    let totp_output = totp_command.output().await?;
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
