use clap::{Args, Subcommand};
use tokio::fs::{File, metadata};
use tokio::io::AsyncWriteExt;
use std::time::SystemTime;
use std::path::PathBuf;
use reqwest;
use serde::{Serialize, Deserialize};
use anyhow::{anyhow, bail};
use log::{info, debug};

use crate::config::SshKeysConfig;
use crate::pass::get_credentials;

#[derive(Args, Debug)]
pub struct SshArgs {
    #[command(subcommand)]
    command: SshCommands,
}

#[derive(Subcommand, Debug)]
enum SshCommands {
    Gen,
    Status,
}

#[derive(Serialize, Debug)]
struct SshserviceCredentials {
    username: String,
    password: String,
    otp: String,
}

#[derive(Deserialize, Debug)]
struct SshserviceResponse {
    public: String,
    private: String,
}

pub async fn run(args: &SshArgs, config: &SshKeysConfig) -> anyhow::Result<()> {
    debug!{"ssh-key command"};
    match &args.command {
        SshCommands::Gen => download_key(args, config).await?,
        SshCommands::Status => status_key(args, config).await?,
    }

    Ok(())
}

async fn download_key(args: &SshArgs, config: &SshKeysConfig) -> anyhow::Result<()> {
    debug!("ssh-key gen subcommand");
    debug!("{:?}", args);
    debug!("{:?}", config);

    info!("Downloading SSH key from: {}", config.url);

    let credentials = get_credentials(config.pass_service.clone(), config.username.clone()).await?;

    let client = reqwest::Client::new();
    let request_body = SshserviceCredentials {
        username: credentials.username,
        password: credentials.password,
        otp: credentials.totp.unwrap(),
    };

    let response = client.post(&config.url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(&request_body)
        .send()
        .await?;

    if !response.status().is_success() {
        //let error_text = response.text().await.unwrap_or_else(|_| "Failed to read error response".to_string());
        //bail!("Failed to download SSH key. HTTP status: {}. Response: {}", response.status(), error_text);
    }

    let response_struct: SshserviceResponse = response.json().await?;
    //let response_struct = response.text().await?;
    debug!("{:?}", response_struct);

    let private_key_path = config.key_path.clone();
    let public_key_path = PathBuf::from(format!("{}-cert.pub", private_key_path.display()));

    if let Some(parent) = private_key_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    // Save public key
    let mut public_file = File::create(&public_key_path).await?;
    info!("Saving public key in {}", public_key_path.display());
    public_file.write_all(response_struct.public.as_bytes()).await?;
    #[cfg(unix)] // Only apply on Unix-like systems
    {
        info!("Setting permissions for public key to 0o644: {}", public_key_path.display());
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = public_file.metadata().await?.permissions();
        permissions.set_mode(0o644); // Read/write for owner only
        tokio::fs::set_permissions(&public_key_path, permissions).await?;
    }
    info!("Public SSH key successfully downloaded to {}", public_key_path.display());

    // Save private key
    let mut private_file = File::create(&private_key_path).await?;
    info!("Saving private key in {}", private_key_path.display());
    private_file.write_all(response_struct.private.as_bytes()).await?;
    #[cfg(unix)] // Only apply on Unix-like systems
    {
        info!("Setting permissions for private key to 0o600: {}", private_key_path.display());
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = private_file.metadata().await?.permissions();
        permissions.set_mode(0o600); // Read/write for owner only
        tokio::fs::set_permissions(&private_key_path, permissions).await?;
    }
    println!("Private SSH key successfully downloaded to: {}", private_key_path.display());

    Ok(())
}

async fn status_key(args: &SshArgs, config: &SshKeysConfig) -> anyhow::Result<()> {
    debug!("ssh-key status subcommand");
    debug!("{:?}", args);
    debug!("{:?}", config);

    let metadata_result = metadata(&config.key_path).await;
    let file_metadata = match metadata_result {
        Ok(meta) => {
            if meta.is_file() {
                info!("SSH key file found at: {}", &config.key_path.display());
                meta
            } else {
                bail!("Path '{}' exists but is not a file (it's a directory or other type).", &config.key_path.display());
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            bail!("SSH key file not found at: {}. Please run 'ssh-key download'.", &config.key_path.display());
        },
        Err(e) => {
            bail!("Error accessing SSH key file at {}: {}", &config.key_path.display(), e);
        }
    };

    debug!("{:?}", file_metadata);
    let modified_time = file_metadata.modified()?;
    let now = SystemTime::now();
    let duration_since_modified = now.duration_since(modified_time)
        .map_err(|e| anyhow!("System time is earlier than file modification time: {}", e))?;

    let validity = std::time::Duration::from_secs(24 * 60 * 60);

    if duration_since_modified > validity {
        println!("SSH key is EXPIRED (last modified {} ago).",
            format_duration(&duration_since_modified));
        bail!("SSH key is expired. Please run 'ssh-key download' to renew.");
    } else {
        println!("SSH key is VALID (last modified {} ago).",
            format_duration(&duration_since_modified));
    }

    Ok(())
}

fn format_duration(duration: &std::time::Duration) -> String {
    let secs = duration.as_secs();
    if secs < 60 {
        format!("{} seconds", secs)
    } else if secs < 3600 {
        format!("{} minutes", secs / 60)
    } else if secs < 86400 {
        format!("{} hours", secs / 3600)
    } else {
        format!("{} days", secs / 86400)
    }
}
