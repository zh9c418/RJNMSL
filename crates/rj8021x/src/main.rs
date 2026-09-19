//! Minimal 802.1X (EAPOL) supplicant.
#![allow(dead_code)] // protocol tables intentionally carry the full registry

mod config;
mod eap;
mod eapol;
mod eth;
mod pcap_io;
mod supplicant;

#[cfg(feature = "peap")]
mod mschapv2;
#[cfg(feature = "peap")]
mod peap;

use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "rj8021x", version, about = "Minimal 802.1X (EAPOL) supplicant")]
struct Cli {
    /// Path to the TOML config file.
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    /// List available pcap interfaces and exit.
    #[arg(long)]
    list: bool,
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();

    if cli.list {
        pcap_io::list_devices()?;
        return Ok(());
    }

    let cfg = config::Config::load(&cli.config)?;
    supplicant::run(cfg)
}
