use serde::{Deserialize, Serialize};
use directories::ProjectDirs;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use duration_str::deserialize_duration;
use anyhow::{anyhow, Context};
use log::info;

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct Config {
    pub vpn: VpnConfig,
    pub ssh_keys: SshKeysConfig,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct VpnConfig {
    pub client: VpnClientConfig,
    pub pass_service: String,
    pub username: String,
    pub domain: String,
    pub host: String,
}


#[derive(Debug, Default, Deserialize, Serialize)]
pub struct VpnClientConfig {
    pub path: PathBuf,
    pub connect_args: Vec<String>,
    pub disconnect_args: Vec<String>,
    pub status_args: Vec<String>,
    pub connect_stdin_template: String,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct SshKeysConfig {
    pub key_path: PathBuf,
    //#[serde(deserialize_with = "duration-str::deserialize_from_str", serialize_with = "duration-str::serialize_to_string", default = "default_key_validity_duration")]
    #[serde(deserialize_with = "deserialize_duration")]
    pub key_validity: Duration,
    pub url: String,
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

                //Resolve path, e.g. "~"
                config.ssh_keys.key_path = resolve_path(&config.ssh_keys.key_path)?;
                config.vpn.client.path = resolve_path(&config.vpn.client.path)?;
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

fn resolve_path(path: &Path) -> anyhow::Result<PathBuf> {
    let path_str = path.to_str().ok_or_else(|| {
        anyhow!("Invalid path: contains non-UTF8 characters")
    })?;

    if path_str.starts_with("~/") {
        let home_dir = dirs::home_dir()
            .ok_or_else(|| anyhow!("Could not determine home directory for path: {}", path.display()))?;

        if path_str == "~" {
            Ok(home_dir)
        } else {
            // Remove "~/" and append to home_dir
            let relative_path = PathBuf::from(&path_str[2..]);
            Ok(home_dir.join(relative_path))
        }
    } else {
        Ok(path.to_path_buf()) // Return as is if no '~'
    }
}
