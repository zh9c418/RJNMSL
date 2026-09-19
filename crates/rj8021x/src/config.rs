use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EapMethod {
    Md5,
    Peap,
}

impl Default for EapMethod {
    fn default() -> Self {
        EapMethod::Md5
    }
}

fn d_eapol_version() -> u8 {
    1
}
fn d_start_timeout() -> u64 {
    5
}
fn d_max_start_attempts() -> u32 {
    3
}
fn d_retry_delay() -> u64 {
    5
}
fn d_maintain_timeout() -> u64 {
    1800
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// pcap device name, adapter MAC, or a substring of the description.
    pub interface: String,

    /// 802.1X identity / username.
    pub identity: String,

    /// 802.1X password.
    pub password: String,

    #[serde(default)]
    pub method: EapMethod,

    /// Outer identity for PEAP (optional).
    #[serde(default)]
    pub anonymous_identity: Option<String>,

    /// EAPOL version used for frames we originate.
    #[serde(default = "d_eapol_version")]
    pub eapol_version: u8,

    /// Override the local MAC if pcap cannot report it.
    #[serde(default)]
    pub local_mac: Option<String>,

    /// Seconds before retransmitting when nothing is heard back.
    #[serde(default = "d_start_timeout")]
    pub start_timeout_secs: u64,

    /// Max retransmits before giving up an attempt.
    #[serde(default = "d_max_start_attempts")]
    pub max_start_attempts: u32,

    /// Delay before restarting after failure / timeout.
    #[serde(default = "d_retry_delay")]
    pub retry_delay_secs: u64,

    /// Idle timeout while authorised before re-initiating.
    #[serde(default = "d_maintain_timeout")]
    pub maintain_timeout_secs: u64,

    /// Exit right after the first successful authentication.
    #[serde(default)]
    pub exit_on_success: bool,
}

impl Config {
    pub fn load(path: &str) -> Result<Config> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read config file {path}"))?;
        let cfg: Config =
            toml::from_str(&text).with_context(|| format!("cannot parse config file {path}"))?;
        Ok(cfg)
    }
}