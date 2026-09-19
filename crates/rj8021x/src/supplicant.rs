//! The 802.1X supplicant state machine.
//!
//! Flow:
//!   * `authenticate()`: send EAPOL-Start, drive the EAP exchange to a result.
//!   * `maintain()`: after success, answer re-auth requests until we are kicked
//!     (EAP-Failure) or go idle.
//!   * `run()`: outer loop that ties them together.

use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::config::{Config, EapMethod};
use crate::eap::*;
use crate::eapol::*;
use crate::eth::*;
use crate::pcap_io::Link;

/// Per-authentication-session state.
#[derive(Default)]
struct Cx {
    #[cfg(feature = "peap")]
    peap: Option<crate::peap::PeapSession>,
}

enum Handled {
    Respond {
        dst: [u8; 6],
        version: u8,
        packets: Vec<EapPacket>,
    },
    Success,
    Failure,
    None,
}

enum AuthResult {
    Success,
    Failure,
    Timeout,
}

pub fn run(cfg: Config) -> Result<()> {
    if matches!(cfg.method, EapMethod::Peap) {
        #[cfg(not(feature = "peap"))]
        bail!("config uses method = \"peap\", but this binary was built without the `peap` feature; rebuild with `cargo build --release --features peap`");
    }

    let mac_override = match &cfg.local_mac {
        Some(s) => Some(parse_mac(s).with_context(|| format!("invalid local_mac {s:?}"))?),
        None => None,
    };

    let mut link = Link::open(&cfg.interface, mac_override)?;
    let local = link.local_mac;

    log::info!("interface : {}", link.dev_name);
    log::info!("local MAC : {}", fmt_mac(&local));
    log::info!("identity  : {}", cfg.identity);
    log::info!("method    : {:?}", cfg.method);

    loop {
        match authenticate(&mut link, &cfg, local)? {
            AuthResult::Success => {
                log::info!(">>> authentication SUCCESS");
                if cfg.exit_on_success {
                    return Ok(());
                }
                log::info!("session authorised; listening for re-authentication");
                if !maintain(&mut link, &cfg, local)? {
                    log::warn!("session ended; restarting authentication");
                }
            }
            AuthResult::Failure => {
                log::warn!(">>> authentication FAILURE (check username/password)");
                std::thread::sleep(Duration::from_secs(cfg.retry_delay_secs));
            }
            AuthResult::Timeout => {
                log::warn!(">>> authentication TIMEOUT (no answer from authenticator)");
                std::thread::sleep(Duration::from_secs(cfg.retry_delay_secs));
            }
        }
    }
}

/// Initiate and run one authentication to a result.
fn authenticate(link: &mut Link, cfg: &Config, local: [u8; 6]) -> Result<AuthResult> {
    let mut cx = Cx::default();

    // Kick off with EAPOL-Start.
    let start = eth_wrap(PAE_GROUP, local, EapolFrame::start(cfg.eapol_version));
    link.send(&start)?;
    let mut last_tx: Vec<Vec<u8>> = vec![start];
    let mut attempts: u32 = 1;
    let mut last_send = Instant::now();
    let timeout = Duration::from_secs(cfg.start_timeout_secs);
    log::info!(
        "sent EAPOL-Start (attempt {}/{})",
        attempts,
        cfg.max_start_attempts
    );

    loop {
        match link.recv()? {
            None => {
                if last_send.elapsed() >= timeout {
                    attempts += 1;
                    if attempts > cfg.max_start_attempts {
                        return Ok(AuthResult::Timeout);
                    }
                    log::warn!(
                        "no response, retransmitting (attempt {}/{})",
                        attempts,
                        cfg.max_start_attempts
                    );
                    for f in &last_tx {
                        link.send(f)?;
                    }
                    last_send = Instant::now();
                }
            }
            Some(frame) => match handle(&frame, cfg, local, &mut cx)? {
                Handled::Respond {
                    dst,
                    version,
                    packets,
                } => {
                    attempts = 0;
                    last_send = Instant::now();
                    let mut sent = Vec::with_capacity(packets.len());
                    for p in &packets {
                        let f = eth_wrap(dst, local, EapolFrame::eap(version, p));
                        link.send(&f)?;
                        sent.push(f);
                    }
                    last_tx = sent;
                }
                Handled::Success => return Ok(AuthResult::Success),
                Handled::Failure => return Ok(AuthResult::Failure),
                Handled::None => {}
            },
        }
    }
}

/// Stay authorised: answer re-auth requests, bail on EAP-Failure / idle timeout.
/// Returns `false` when the outer loop should restart authentication.
fn maintain(link: &mut Link, cfg: &Config, local: [u8; 6]) -> Result<bool> {
    let mut cx = Cx::default();
    let idle = Duration::from_secs(cfg.maintain_timeout_secs);
    let mut last_seen = Instant::now();

    loop {
        match link.recv()? {
            None => {
                if last_seen.elapsed() >= idle {
                    log::info!("idle for {}s, re-initiating", cfg.maintain_timeout_secs);
                    return Ok(false);
                }
            }
            Some(frame) => match handle(&frame, cfg, local, &mut cx)? {
                Handled::Respond {
                    dst,
                    version,
                    packets,
                } => {
                    last_seen = Instant::now();
                    for p in &packets {
                        link.send(&eth_wrap(dst, local, EapolFrame::eap(version, p)))?;
                    }
                }
                Handled::Success => {
                    last_seen = Instant::now();
                }
                Handled::Failure => {
                    log::warn!("authenticator sent EAP-Failure (deauthorised)");
                    return Ok(false);
                }
                Handled::None => {}
            },
        }
    }
}

fn handle(frame: &[u8], cfg: &Config, local: [u8; 6], cx: &mut Cx) -> Result<Handled> {
    let eth = match EthFrame::parse(frame) {
        Some(e) => e,
        None => return Ok(Handled::None),
    };
    // Ignore our own transmitted frames and anything that is not EAPOL.
    if eth.ethertype != ETHERTYPE_EAPOL || eth.src == local {
        return Ok(Handled::None);
    }

    let eapol = match EapolFrame::parse(&eth.payload) {
        Some(e) => e,
        None => return Ok(Handled::None),
    };
    if eapol.ptype != EAPOL_TYPE_EAP_PACKET {
        return Ok(Handled::None);
    }

    let pkt = match EapPacket::parse(&eapol.body) {
        Some(p) => p,
        None => return Ok(Handled::None),
    };

    match pkt.code {
        EAP_CODE_SUCCESS => Ok(Handled::Success),
        EAP_CODE_FAILURE => Ok(Handled::Failure),
        EAP_CODE_REQUEST => {
            let t = pkt.etype.unwrap_or(0);
            let packets = build_response(cfg, cx, &pkt, t)?;
            if packets.is_empty() {
                Ok(Handled::None)
            } else {
                log::debug!("EAP-Request type {t} -> responding");
                Ok(Handled::Respond {
                    dst: eth.src,
                    version: eapol.version,
                    packets,
                })
            }
        }
        _ => Ok(Handled::None),
    }
}

fn build_response(cfg: &Config, cx: &mut Cx, pkt: &EapPacket, t: u8) -> Result<Vec<EapPacket>> {
    let _ = &cx;
    let packets = match t {
        EAP_TYPE_IDENTITY => vec![EapPacket::identity_response(pkt.id, &outer_identity(cfg))],

        EAP_TYPE_MD5 => match md5_challenge(&pkt.data) {
            Some(challenge) => {
                if matches!(cfg.method, EapMethod::Peap) {
                    log::warn!("server asked for EAP-MD5 while method=peap; check your config");
                }
                vec![EapPacket::md5_response(
                    pkt.id,
                    cfg.password.as_bytes(),
                    challenge,
                )]
            }
            None => Vec::new(),
        },

        EAP_TYPE_NOTIFICATION => vec![EapPacket::notification_response(pkt.id)],

        EAP_TYPE_PEAP => {
            #[cfg(feature = "peap")]
            {
                peap_response(cx, cfg, pkt)?
            }
            #[cfg(not(feature = "peap"))]
            {
                log::warn!(
                    "server requested EAP-PEAP but this build has no `peap` feature; NAKing"
                );
                vec![EapPacket::nak(pkt.id, EAP_TYPE_MD5)]
            }
        }

        other => {
            log::warn!("unsupported EAP method {other} requested by server; NAKing MD5");
            vec![EapPacket::nak(pkt.id, EAP_TYPE_MD5)]
        }
    };
    Ok(packets)
}

fn outer_identity(cfg: &Config) -> Vec<u8> {
    match cfg.method {
        EapMethod::Peap => cfg
            .anonymous_identity
            .clone()
            .unwrap_or_else(|| cfg.identity.clone())
            .into_bytes(),
        EapMethod::Md5 => cfg.identity.clone().into_bytes(),
    }
}

#[cfg(feature = "peap")]
fn peap_response(cx: &mut Cx, cfg: &Config, pkt: &EapPacket) -> Result<Vec<EapPacket>> {
    if cx.peap.is_none() {
        cx.peap = Some(crate::peap::PeapSession::new(&cfg.identity, &cfg.password)?);
    }
    let session = cx.peap.as_mut().expect("peap session just created");
    let blobs = session.handle(pkt.id, &pkt.data)?;
    Ok(blobs
        .into_iter()
        .map(|data| EapPacket {
            code: EAP_CODE_RESPONSE,
            id: pkt.id,
            etype: Some(EAP_TYPE_PEAP),
            data,
        })
        .collect())
}

fn eth_wrap(dst: [u8; 6], src: [u8; 6], eapol: Vec<u8>) -> Vec<u8> {
    EthFrame {
        dst,
        src,
        ethertype: ETHERTYPE_EAPOL,
        payload: eapol,
    }
    .build()
}
