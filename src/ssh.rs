use clap::{Args, Subcommand};
use std::fs;
use std::fs::{File, metadata};
use std::io::Write;
use std::fmt::{self, Debug, Formatter};
use std::time::SystemTime;
use std::path::PathBuf;
use reqwest;
use serde::{Serialize, Deserialize, Deserializer};
use anyhow::{anyhow, bail};
use log::{info, debug};

use crate::config::{Config, SshKeysConfig};
use crate::oidc::oidc_get_access_token;
use crate::password_manager::PasswordManager;

#[derive(Args, Debug)]
pub struct SshArgs {
    #[command(subcommand)]
    command: SshCommands,
}

#[derive(Subcommand, Debug)]
enum SshCommands {
    Gen,
    GenOIDC,
    SignOIDC,
    Status,
    List,
    Revoke,
}

#[derive(Serialize)]
struct SshserviceCredentials {
    username: String,
    password: String,
    otp: String,
}

impl Debug for SshserviceCredentials {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SshserviceCredentials")
            .field("username", &self.username)
            .field("password", &"******")
            .field("otp", &"******")
            .finish()
    }
}

#[derive(Deserialize)]
struct SshserviceResponse {
    public: String,
    private: String,
}

impl Debug for SshserviceResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SshserviceResponse")
            .field("public", &format!("{}...", &self.public[..32]))
            .field("private", &format!("{}...", &self.private[..32]))
            .finish()
    }
}

#[derive(Serialize)]
struct SshKeyDuration {
    duration: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicKey {
    public_key: String,
    duration: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SshKeyNew {
    #[serde(deserialize_with = "ensure_newline")]
    public_key: String,
    #[serde(deserialize_with = "ensure_newline")]
    private_key: String,
    expire_time: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SshserviceResponseNew {
    ssh_key: SshKeyNew,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SshKeyCertNew {
    #[serde(deserialize_with = "ensure_newline")]
    public_key: String,
    expire_time: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SshserviceResponseCertNew {
    ssh_key: SshKeyCertNew,
}

// Ensure downloaded ssh keys end with \n
fn ensure_newline<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let mut s = String::deserialize(deserializer)?;

    if !s.ends_with('\n') {
        s.push('\n');
    }

    Ok(s)
}

pub fn run(args: &SshArgs, config: &Config) -> anyhow::Result<()> {
    let ssh_config = &config.ssh_keys;
    let password_manager = &config.password_manager.provider;

    debug!{"ssh-key command"};
    match &args.command {
        SshCommands::Gen => download_key(args, &ssh_config, password_manager)?,
        SshCommands::GenOIDC => download_key_oidc(args, &ssh_config)?,
        SshCommands::SignOIDC => sign_key_oidc(args, &ssh_config)?,
        SshCommands::Status => status_key(args, &ssh_config)?,
        SshCommands::List => list_keys(args, &ssh_config)?,
        SshCommands::Revoke => revoke_keys(args, &ssh_config)?,
    }

    Ok(())
}

fn download_key(args: &SshArgs, config: &SshKeysConfig, password_manager: &Box<dyn PasswordManager>) -> anyhow::Result<()> {
    debug!("ssh-key gen subcommand");
    debug!("{:?}", args);
    debug!("{:?}", config);

    info!("Downloading SSH key from: {}", config.url);

    let credentials = password_manager.get_credentials(config.pass_service.clone(), config.username.clone())?;

    let client = reqwest::blocking::Client::new();
    let request_body = SshserviceCredentials {
        username: credentials.username,
        password: credentials.password,
        otp: credentials.totp.unwrap(),
    };

    let response = client.post(&config.url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(&request_body)
        .send()?;

    if !response.status().is_success() {
        //let error_text = response.text().unwrap_or_else(|_| "Failed to read error response".to_string());
        //bail!("Failed to download SSH key. HTTP status: {}. Response: {}", response.status(), error_text);
    }

    let response_struct: SshserviceResponse = response.json()?;
    //let response_struct = response.text()?;
    debug!("{:?}", response_struct);

    let private_key_path = config.key_path.clone();
    let public_key_path = PathBuf::from(format!("{}-cert.pub", private_key_path.display()));

    if let Some(parent) = private_key_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Save public key
    let mut public_file = File::create(&public_key_path)?;
    info!("Saving public key in {}", public_key_path.display());
    public_file.write_all(response_struct.public.as_bytes())?;
    #[cfg(unix)] // Only apply on Unix-like systems
    {
        info!("Setting permissions for public key to 0o644: {}", public_key_path.display());
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = public_file.metadata()?.permissions();
        permissions.set_mode(0o644); // Read/write for owner only
        std::fs::set_permissions(&public_key_path, permissions)?;
    }
    info!("Public SSH key successfully downloaded to {}", public_key_path.display());

    // Save private key
    let mut private_file = File::create(&private_key_path)?;
    info!("Saving private key in {}", private_key_path.display());
    private_file.write_all(response_struct.private.as_bytes())?;
    #[cfg(unix)] // Only apply on Unix-like systems
    {
        info!("Setting permissions for private key to 0o600: {}", private_key_path.display());
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = private_file.metadata()?.permissions();
        permissions.set_mode(0o600); // Read/write for owner only
        std::fs::set_permissions(&private_key_path, permissions)?;
    }
    println!("Private SSH key successfully downloaded to: {}", private_key_path.display());

    Ok(())
}

fn download_key_oidc(args: &SshArgs, config: &SshKeysConfig) -> anyhow::Result<()> {
    debug!("ssh-key gen-new subcommand");
    debug!("{:?}", args);
    debug!("{:?}", config);

    let key_duration = SshKeyDuration {
        duration: config.key_validity_str.clone(),
    };

    info!("Get OIDC token");

    let access_token = oidc_get_access_token(&config)?;
    println!("got token: {}", access_token);

    let client = reqwest::blocking::Client::new();

    let response = client.post(config.keys_url.clone())
        //.header("Content-Type", "application/json")
        //.header("Accept", "application/json")
        .bearer_auth(&access_token)
        .json(&key_duration)
        .send()?;

    if !response.status().is_success() {
        //let error_text = response.text().unwrap_or_else(|_| "Failed to read error response".to_string());
        //bail!("Failed to download SSH key. HTTP status: {}. Response: {}", response.status(), error_text);
    }

    let response_struct: SshserviceResponseNew = response.json()?;

    let private_key_path = config.key_path.clone();
    let public_key_path = PathBuf::from(format!("{}-cert.pub", private_key_path.display()));

    if let Some(parent) = private_key_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Save public key
    let mut public_file = File::create(&public_key_path)?;
    info!("Saving public key in {}", public_key_path.display());
    public_file.write_all(response_struct.ssh_key.public_key.as_bytes())?;
    #[cfg(unix)] // Only apply on Unix-like systems
    {
        info!("Setting permissions for public key to 0o644: {}", public_key_path.display());
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = public_file.metadata()?.permissions();
        permissions.set_mode(0o644); // Read/write for owner only
        std::fs::set_permissions(&public_key_path, permissions)?;
    }
    info!("Public SSH key successfully downloaded to {}", public_key_path.display());

    // Save private key
    let mut private_file = File::create(&private_key_path)?;
    info!("Saving private key in {}", private_key_path.display());
    private_file.write_all(response_struct.ssh_key.private_key.as_bytes())?;
    #[cfg(unix)] // Only apply on Unix-like systems
    {
        info!("Setting permissions for private key to 0o600: {}", private_key_path.display());
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = private_file.metadata()?.permissions();
        permissions.set_mode(0o600); // Read/write for owner only
        std::fs::set_permissions(&private_key_path, permissions)?;
    }
    println!("Private SSH key successfully downloaded to: {}", private_key_path.display());

    Ok(())
}

fn sign_key_oidc(args: &SshArgs, config: &SshKeysConfig) -> anyhow::Result<()> {
    debug!("ssh-key gen-new subcommand");
    debug!("{:?}", args);
    debug!("{:?}", config);

    let private_key_path = config.key_path.clone();
    let public_key_path = PathBuf::from(format!("{}-signing.pub", private_key_path.display()));
    info!("Reading public key in {}", public_key_path.display());
    let content = fs::read_to_string(public_key_path)?;

    let public_key = PublicKey {
        public_key: content,
        duration: config.key_validity_str.clone(),
    };

    info!("Get OIDC token");

    let access_token = oidc_get_access_token(&config)?;

    let client = reqwest::blocking::Client::new();

    let response = client.post(config.sign_url.clone())
        //.header("Content-Type", "application/json")
        //.header("Accept", "application/json")
        .bearer_auth(&access_token)
        .json(&public_key)
        .send()?;

    if !response.status().is_success() {
        //let error_text = response.text().unwrap_or_else(|_| "Failed to read error response".to_string());
        //bail!("Failed to download SSH key. HTTP status: {}. Response: {}", response.status(), error_text);
    }

    //debug!("response: {:?}", response);
    //debug!("response.text: {:?}", response.text()?);

    let response_struct: SshserviceResponseCertNew = response.json()?;
    //let response_struct = response.text()?;
    debug!("{:?}", response_struct);

    let private_key_path = config.key_path.clone();
    let public_key_path = PathBuf::from(format!("{}-signing-cert.pub", private_key_path.display()));

    if let Some(parent) = private_key_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Save public key
    let mut public_file = File::create(&public_key_path)?;
    info!("Saving public key in {}", public_key_path.display());
    public_file.write_all(response_struct.ssh_key.public_key.as_bytes())?;
    #[cfg(unix)] // Only apply on Unix-like systems
    {
        info!("Setting permissions for public key to 0o644: {}", public_key_path.display());
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = public_file.metadata()?.permissions();
        permissions.set_mode(0o644); // Read/write for owner only
        std::fs::set_permissions(&public_key_path, permissions)?;
    }
    info!("Public SSH key successfully downloaded to {}", public_key_path.display());

    Ok(())
}

fn status_key(args: &SshArgs, config: &SshKeysConfig) -> anyhow::Result<()> {
    debug!("ssh-key status subcommand");
    debug!("{:?}", args);
    debug!("{:?}", config);

    let metadata_result = metadata(&config.key_path);
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

    let validity = config.key_validity;

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

fn list_keys(args: &SshArgs, config: &SshKeysConfig) -> anyhow::Result<()> {
    debug!("ssh-key list subcommand");
    debug!("{:?}", args);
    debug!("{:?}", config);

    todo!("ssh-key list");

    Ok(())
}

fn revoke_keys(args: &SshArgs, config: &SshKeysConfig) -> anyhow::Result<()> {
    debug!("ssh-key revoke subcommand");
    debug!("{:?}", args);
    debug!("{:?}", config);

    todo!("ssh-key revoke");

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
