//! Ethernet II frame encoding / parsing.

pub const ETHERTYPE_EAPOL: u16 = 0x888E;

/// 802.1X PAE group address.
pub const PAE_GROUP: [u8; 6] = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x03];

pub const ETH_HEADER_LEN: usize = 14;

#[derive(Debug, Clone)]
pub struct EthFrame {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ethertype: u16,
    pub payload: Vec<u8>,
}

impl EthFrame {
    pub fn parse(buf: &[u8]) -> Option<EthFrame> {
        if buf.len() < ETH_HEADER_LEN {
            return None;
        }
        let mut dst = [0u8; 6];
        dst.copy_from_slice(&buf[0..6]);
        let mut src = [0u8; 6];
        src.copy_from_slice(&buf[6..12]);
        let ethertype = u16::from_be_bytes([buf[12], buf[13]]);
        Some(EthFrame {
            dst,
            src,
            ethertype,
            payload: buf[ETH_HEADER_LEN..].to_vec(),
        })
    }

    pub fn build(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(ETH_HEADER_LEN + self.payload.len());
        v.extend_from_slice(&self.dst);
        v.extend_from_slice(&self.src);
        v.extend_from_slice(&self.ethertype.to_be_bytes());
        v.extend_from_slice(&self.payload);
        v
    }
}

pub fn fmt_mac(m: &[u8; 6]) -> String {
    m.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split([':', '-']).collect();
    if parts.len() != 6 {
        return None;
    }
    let mut m = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        m[i] = u8::from_str_radix(p.trim(), 16).ok()?;
    }
    Some(m)
}