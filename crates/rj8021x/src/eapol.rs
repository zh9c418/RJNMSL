//! EAPOL (IEEE 802.1X) frame encoding / parsing.
//!
//! EAPOL header:
//!   version (1) | type (1) | length (2, big endian) | body

use crate::eap::EapPacket;

pub const EAPOL_TYPE_EAP_PACKET: u8 = 0;
pub const EAPOL_TYPE_START: u8 = 1;
pub const EAPOL_TYPE_LOGOFF: u8 = 2;
pub const EAPOL_TYPE_KEY: u8 = 3;

pub const EAPOL_HEADER_LEN: usize = 4;

#[derive(Debug, Clone)]
pub struct EapolFrame {
    pub version: u8,
    pub ptype: u8,
    pub body: Vec<u8>,
}

impl EapolFrame {
    pub fn parse(buf: &[u8]) -> Option<EapolFrame> {
        if buf.len() < EAPOL_HEADER_LEN {
            return None;
        }
        let version = buf[0];
        let ptype = buf[1];
        let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if buf.len() < EAPOL_HEADER_LEN + len {
            return None;
        }
        Some(EapolFrame {
            version,
            ptype,
            body: buf[EAPOL_HEADER_LEN..EAPOL_HEADER_LEN + len].to_vec(),
        })
    }

    pub fn build(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(EAPOL_HEADER_LEN + self.body.len());
        v.push(self.version);
        v.push(self.ptype);
        v.extend_from_slice(&(self.body.len() as u16).to_be_bytes());
        v.extend_from_slice(&self.body);
        v
    }

    pub fn start(version: u8) -> Vec<u8> {
        EapolFrame {
            version,
            ptype: EAPOL_TYPE_START,
            body: Vec::new(),
        }
        .build()
    }

    pub fn logoff(version: u8) -> Vec<u8> {
        EapolFrame {
            version,
            ptype: EAPOL_TYPE_LOGOFF,
            body: Vec::new(),
        }
        .build()
    }

    pub fn eap(version: u8, pkt: &EapPacket) -> Vec<u8> {
        EapolFrame {
            version,
            ptype: EAPOL_TYPE_EAP_PACKET,
            body: pkt.encode(),
        }
        .build()
    }
}