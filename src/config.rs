use serde::{Deserialize, Deserializer, Serialize};
use directories::ProjectDirs;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use duration_str::deserialize_duration;
use anyhow::Context;
use log::info;

use crate::cisco_secure_connect::CiscoSecureConnect;
use crate::password_manager::PasswordManager;
use crate::pass::Pass;
use crate::keepassxc::KeePassXC;
use crate::vpn::VpnApp;

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct Config {
    pub password_manager: PasswordManagerConfig,
    pub vpn: VpnConfig,
    pub ssh_keys: SshKeysConfig,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PasswordManagerConfig {
    #[serde(deserialize_with = "deserialize_password_manager")]
    pub provider: Box<dyn PasswordManager>,
    pub pass: PasswordManagerPassConfig,
    pub keepassxc: PasswordManagerKeePassXCConfig,
}

impl Default for PasswordManagerConfig {
    fn default() -> Self {
        PasswordManagerConfig {
            provider: Box::new(Pass),
            pass: PasswordManagerPassConfig::default(),
            keepassxc: PasswordManagerKeePassXCConfig::default(),
        }
    }
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct PasswordManagerPassConfig {
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct PasswordManagerKeePassXCConfig {
}

#[derive(Debug, Deserialize, Serialize)]
pub struct VpnConfig {
    #[serde(deserialize_with = "deserialize_vpn_provider")]
    pub provider: Box<dyn VpnApp>,
    pub cisco: VpnCiscoConfig,
    pub pass_service: String,
    pub username: String,
    pub domain: String,
    pub host: String,
}

impl Default for VpnConfig {
    fn default() -> Self {
        VpnConfig {
            provider: Box::new(CiscoSecureConnect),
            cisco: VpnCiscoConfig::default(),
            pass_service: String::default(),
            username: String::default(),
            domain: String::default(),
            host: String::default(),
        }
    }
}


#[derive(Debug, Default, Deserialize, Serialize)]
pub struct VpnCiscoConfig {
    #[serde(deserialize_with = "deserialize_path")]
    pub path: PathBuf,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct SshKeysConfig {
    #[serde(deserialize_with = "deserialize_path")]
    pub key_path: PathBuf,
    //#[serde(deserialize_with = "duration-str::deserialize_from_str", serialize_with = "duration-str::serialize_to_string", default = "default_key_validity_duration")]
    #[serde(deserialize_with = "deserialize_duration")]
    pub key_validity: Duration,
    pub key_validity_str: String,
    pub pkce_client_id: String,
    pub url: String,
    pub issuer_url: String,
    pub keys_url: String,
    pub sign_url: String,
    pub pass_service: String,
    pub username: String,
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let mut config = Self::default();

        if let Some(proj_dirs) = ProjectDirs::from("ch", "cscs", "cscs-cli") {
            let config_dir = proj_dirs.config_dir();
            let config_file_path = config_dir.join("config.toml");

            if config_file_path.exists() {
                info!("Loading configuration from: {:?}", config_file_path);

                let config_str = fs::read_to_string(&config_file_path)
                    .with_context(|| format!("Failed to read config file at {:?}", config_file_path))?;
                let file_config: Config = toml::from_str(&config_str)
                    .with_context(|| format!("Failed to parse config file at {:?}", config_file_path))?;
                config.vpn = file_config.vpn;
                config.ssh_keys = file_config.ssh_keys;
                config.password_manager = file_config.password_manager;
            } else {
                info!("No configuration file found at {:?}. Creating default.", config_file_path);

                fs::create_dir_all(config_dir)
                    .with_context(|| format!("Failed to create config directory at {:?}", config_dir))?;
                let default_toml = toml::to_string_pretty(&config)
                    .context("Failed to serialize default config")?;
                fs::write(&config_file_path, default_toml)
                    .with_context(|| format!("Failed to write default config file to {:?}", config_file_path))?;
            }
        }

        Ok(config)
    }
}

//Resolve path, e.g. "~"
fn deserialize_path<'de, D>(d: D) -> Result<PathBuf, D::Error>
where
    D: Deserializer<'de>,
{
    let path_str = String::deserialize(d)?;

    if path_str.starts_with("~/") {
        let home_dir = dirs::home_dir()
            .ok_or_else(|| panic!("Could not determine home directory for path: {}", path_str))?;
            //.unwrap_or_else(|| panic!("Could not determine home directory for path: {}", path_str));

        if path_str == "~" {
            Ok(home_dir)
        } else {
            // Remove "~/" and append to home_dir
            let relative_path = PathBuf::from(&path_str[2..]);
            Ok(home_dir.join(relative_path))
        }
    } else {
        // Does not start wit '~' => Return as is
        Ok(PathBuf::from(path_str))
    }
}

fn deserialize_password_manager<'de, D>(d: D) -> Result<Box<dyn PasswordManager>, D::Error>
where
    D: Deserializer<'de>,
{
    let password_manager_str = String::deserialize(d)?;

    match password_manager_str.as_str() {
        "pass" => Ok(Box::new(Pass)),
        "keepassxc" => Ok(Box::new(KeePassXC)),
        _ => panic!("Unsupported manager"),
    }
}

fn deserialize_vpn_provider<'de, D>(d: D) -> Result<Box<dyn VpnApp>, D::Error>
where
    D: Deserializer<'de>,
{
    let vpn_str = String::deserialize(d)?;

    match vpn_str.as_str() {
        "cisco" => Ok(Box::new(CiscoSecureConnect)),
        _ => panic!("Unsupported manager"),
    }
}
