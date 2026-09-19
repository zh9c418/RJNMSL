//! EAP-PEAP (EAP type 25) session, driving a rustls TLS client over EAPOL and
//! running EAP-MSCHAPv2 as the inner method.
//!
//! Only compiled with `--features peap`.
//!
//! PEAP packet layout (inside EAP-Response/Request, type 25):
//!   flags (1) | [ length (4) if L set ] | TLS record data...

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::sync::Arc;

use anyhow::{bail, Context, Result};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme};

use crate::eap::*;
use crate::mschapv2;

const PEAP_FLAG_L: u8 = 0x80; // length included
const PEAP_FLAG_M: u8 = 0x40; // more fragments
const PEAP_FLAG_S: u8 = 0x20; // start

/// Keep each EAPOL frame comfortably under the 1500-byte Ethernet MTU.
const MAX_TLS_FRAGMENT: usize = 1024;

/// Accept any server certificate (campus PEAP servers are typically
/// self-signed and the security here comes from MSCHAPv2, not PKI).
#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

/// Reads TLS bytes out of an in-memory queue for rustls.
struct BufReader<'a>(&'a mut VecDeque<u8>);

impl Read for BufReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.0.is_empty() {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "empty"));
        }
        let n = buf.len().min(self.0.len());
        for slot in buf.iter_mut().take(n) {
            *slot = self.0.pop_front().unwrap();
        }
        Ok(n)
    }
}

/// Collects TLS bytes produced by rustls.
struct VecWriter<'a>(&'a mut Vec<u8>);

impl Write for VecWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct PeapSession {
    conn: ClientConnection,
    /// TLS bytes received from the authenticator, waiting to be consumed.
    in_buf: VecDeque<u8>,
    /// TLS bytes we still need to send out, as PEAP.
    out_buf: Vec<u8>,
    /// Reassembly buffer for a fragmented incoming PEAP message.
    fragment_buf: Vec<u8>,
    /// Reassembly buffer for inner EAP packets carried over TLS application data.
    inner_buf: Vec<u8>,

    username: String,
    nt_hash: [u8; 16],
    peer_challenge: [u8; 16],
    auth_challenge: Option<[u8; 16]>,
    nt_response: Option<[u8; 24]>,

    hello_sent: bool,
}

impl PeapSession {
    pub fn new(username: &str, password: &str) -> Result<PeapSession> {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();

        let server_name = ServerName::try_from("peap.local")
            .map_err(|e| anyhow::anyhow!("invalid TLS server name: {e}"))?;
        let conn = ClientConnection::new(Arc::new(config), server_name)
            .map_err(|e| anyhow::anyhow!("rustls init failed: {e}"))?;

        let mut peer_challenge = [0u8; 16];
        {
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut peer_challenge);
        }

        let mut session = PeapSession {
            conn,
            in_buf: VecDeque::new(),
            out_buf: Vec::new(),
            fragment_buf: Vec::new(),
            inner_buf: Vec::new(),
            username: username.to_string(),
            nt_hash: mschapv2::nt_password_hash(password),
            peer_challenge,
            auth_challenge: None,
            nt_response: None,
            hello_sent: false,
        };

        // Make sure the ClientHello is queued.
        if let Err(e) = session.conn.process_new_packets() {
            log::debug!("peap: initial process_new_packets: {e}");
        }
        session.flush_tls()?;
        Ok(session)
    }

    /// Feed one inbound EAP-Request/PEAP payload, return zero or more
    /// EAP-Response/PEAP payloads to send back.
    pub fn handle(&mut self, _id: u8, data: &[u8]) -> Result<Vec<Vec<u8>>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }
        let flags = data[0];
        let off = if flags & PEAP_FLAG_L != 0 { 5 } else { 1 };
        if data.len() < off {
            return Ok(Vec::new());
        }
        self.fragment_buf.extend_from_slice(&data[off..]);

        if flags & PEAP_FLAG_M != 0 {
            // Wait for the remaining fragments.
            return Ok(Vec::new());
        }

        let complete = std::mem::take(&mut self.fragment_buf);
        self.in_buf.extend(complete);

        self.pump()?;
        self.process_inner()?;
        self.flush_tls()?;
        Ok(self.take_out())
    }

    fn pump(&mut self) -> Result<()> {
        loop {
            match self.conn.read_tls(&mut BufReader(&mut self.in_buf)) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(anyhow::anyhow!("peap read_tls: {e}")),
            }
            self.conn
                .process_new_packets()
                .map_err(|e| anyhow::anyhow!("peap tls process: {e}"))?;
        }
        Ok(())
    }

    fn flush_tls(&mut self) -> Result<()> {
        while self.conn.wants_write() {
            self.conn
                .write_tls(&mut VecWriter(&mut self.out_buf))
                .map_err(|e| anyhow::anyhow!("peap write_tls: {e}"))?;
        }
        Ok(())
    }

    fn read_inner(&mut self) -> Result<()> {
        let mut buf = [0u8; 4096];
        loop {
            match self.conn.reader().read(&mut buf) {
                Ok(0) => break,
                Ok(n) => self.inner_buf.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(anyhow::anyhow!("peap tls read: {e}")),
            }
        }
        Ok(())
    }

    fn process_inner(&mut self) -> Result<()> {
        self.read_inner()?;
        loop {
            if self.inner_buf.len() < EAP_HEADER_LEN {
                break;
            }
            let len = u16::from_be_bytes([self.inner_buf[2], self.inner_buf[3]]) as usize;
            if len < EAP_HEADER_LEN || self.inner_buf.len() < len {
                break;
            }
            let pkt = EapPacket::parse(&self.inner_buf[..len]).context("bad inner EAP packet")?;
            self.inner_buf.drain(..len);
            self.handle_inner(&pkt)?;
        }
        Ok(())
    }

    fn handle_inner(&mut self, pkt: &EapPacket) -> Result<()> {
        if pkt.code != EAP_CODE_REQUEST {
            return Ok(());
        }
        let t = pkt.etype.unwrap_or(0);
        match t {
            EAP_TYPE_IDENTITY => {
                let resp = EapPacket::identity_response(pkt.id, self.username.as_bytes());
                self.write_inner(&resp)?;
            }
            EAP_TYPE_MSCHAPV2 => self.handle_mschapv2(pkt)?,
            EAP_TYPE_NAK => {}
            other => log::warn!("peap: inner EAP method {other} not supported"),
        }
        Ok(())
    }

    fn handle_mschapv2(&mut self, pkt: &EapPacket) -> Result<()> {
        let data = &pkt.data;
        if data.is_empty() {
            return Ok(());
        }
        let op = data[0];
        match op {
            // 1 = Challenge
            1 => {
                if data.len() < 18 {
                    bail!("short MSCHAPv2 challenge from server");
                }
                let mschap_id = data[1];
                let auth_challenge: [u8; 16] = data[2..18].try_into().unwrap();

                let ch = mschapv2::challenge_hash(
                    &self.peer_challenge,
                    &auth_challenge,
                    &self.username,
                );
                let nt = mschapv2::challenge_response(&self.nt_hash, &ch);

                let mut v = Vec::with_capacity(50);
                v.push(2u8); // Response
                v.push(mschap_id);
                v.extend_from_slice(&self.peer_challenge); // 16
                v.extend_from_slice(&[0u8; 8]); // reserved
                v.extend_from_slice(&nt); // 24
                v.push(0u8); // flags

                self.auth_challenge = Some(auth_challenge);
                self.nt_response = Some(nt);

                let resp = EapPacket {
                    code: EAP_CODE_RESPONSE,
                    id: pkt.id,
                    etype: Some(EAP_TYPE_MSCHAPV2),
                    data: v,
                };
                self.write_inner(&resp)?;
            }
            // 3 = Success
            3 => {
                if data.len() < 2 {
                    bail!("short MSCHAPv2 success from server");
                }
                let mschap_id = data[1];
                let msg = &data[2..];
                let take = msg.len().min(42);
                let msg42 = &msg[..take];

                if let (Some(nt_response), Some(auth)) = (self.nt_response, self.auth_challenge) {
                    let expected = mschapv2::generate_authenticator_response(
                        &self.nt_hash,
                        &nt_response,
                        &self.peer_challenge,
                        &auth,
                        &self.username,
                    );
                    let got = String::from_utf8_lossy(msg42);
                    if let Some(idx) = got.find("S=") {
                        let sval: String = got[idx..].chars().take(42).collect();
                        if !sval.starts_with(&expected) {
                            log::warn!(
                                "peap: MSCHAPv2 authenticator response mismatch (expected {expected}, got {sval})"
                            );
                        } else {
                            log::debug!("peap: MSCHAPv2 authenticator response verified");
                        }
                    }
                }

                let mut v = Vec::with_capacity(2 + take);
                v.push(4u8); // Success ack
                v.push(mschap_id);
                v.extend_from_slice(msg42);
                let resp = EapPacket {
                    code: EAP_CODE_RESPONSE,
                    id: pkt.id,
                    etype: Some(EAP_TYPE_MSCHAPV2),
                    data: v,
                };
                self.write_inner(&resp)?;
            }
            other => log::debug!("peap: ignoring MSCHAPv2 opcode {other}"),
        }
        Ok(())
    }

    fn write_inner(&mut self, pkt: &EapPacket) -> Result<()> {
        self.conn
            .writer()
            .write_all(&pkt.encode())
            .map_err(|e| anyhow::anyhow!("peap tls write: {e}"))?;
        self.flush_tls()?;
        Ok(())
    }

    /// Turn the pending outbound TLS bytes into one or more PEAP payloads.
    fn take_out(&mut self) -> Vec<Vec<u8>> {
        let tls = std::mem::take(&mut self.out_buf);
        if tls.is_empty() {
            return Vec::new();
        }
        let total = tls.len();
        let mut out = Vec::new();

        if total <= MAX_TLS_FRAGMENT {
            let mut d = Vec::with_capacity(5 + total);
            let mut flags = PEAP_FLAG_L;
            if !self.hello_sent {
                flags |= PEAP_FLAG_S;
            }
            d.push(flags);
            d.extend_from_slice(&(total as u32).to_be_bytes());
            d.extend_from_slice(&tls);
            out.push(d);
            self.hello_sent = true;
            return out;
        }

        let mut off = 0usize;
        let mut first = true;
        while off < total {
            let take = (total - off).min(MAX_TLS_FRAGMENT);
            let last = off + take >= total;
            let mut d = Vec::new();
            if first {
                let mut flags = PEAP_FLAG_L;
                if !self.hello_sent {
                    flags |= PEAP_FLAG_S;
                }
                if !last {
                    flags |= PEAP_FLAG_M;
                }
                d.push(flags);
                d.extend_from_slice(&(total as u32).to_be_bytes());
            } else {
                d.push(if last { 0 } else { PEAP_FLAG_M });
            }
            d.extend_from_slice(&tls[off..off + take]);
            out.push(d);
            off += take;
            first = false;
        }
        self.hello_sent = true;
        out
    }
}