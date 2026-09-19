//! EAP packet encoding / parsing (RFC 3748) plus the methods we need directly.

pub const EAP_CODE_REQUEST: u8 = 1;
pub const EAP_CODE_RESPONSE: u8 = 2;
pub const EAP_CODE_SUCCESS: u8 = 3;
pub const EAP_CODE_FAILURE: u8 = 4;

pub const EAP_TYPE_IDENTITY: u8 = 1;
pub const EAP_TYPE_NOTIFICATION: u8 = 2;
pub const EAP_TYPE_NAK: u8 = 3;
pub const EAP_TYPE_MD5: u8 = 4;
pub const EAP_TYPE_OTP: u8 = 5;
pub const EAP_TYPE_GTC: u8 = 6;
pub const EAP_TYPE_TLS: u8 = 13;
pub const EAP_TYPE_PEAP: u8 = 25;
pub const EAP_TYPE_MSCHAPV2: u8 = 26;
pub const EAP_TYPE_EXPANDED: u8 = 254;

pub const EAP_HEADER_LEN: usize = 4;

#[derive(Debug, Clone)]
pub struct EapPacket {
    pub code: u8,
    pub id: u8,
    /// `None` for Success / Failure.
    pub etype: Option<u8>,
    /// Data following the type byte.
    pub data: Vec<u8>,
}

impl EapPacket {
    pub fn parse(buf: &[u8]) -> Option<EapPacket> {
        if buf.len() < EAP_HEADER_LEN {
            return None;
        }
        let code = buf[0];
        let id = buf[1];
        let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        let end = len.min(buf.len());

        if code == EAP_CODE_SUCCESS || code == EAP_CODE_FAILURE {
            return Some(EapPacket {
                code,
                id,
                etype: None,
                data: Vec::new(),
            });
        }
        if end < EAP_HEADER_LEN + 1 {
            return None;
        }
        let etype = buf[4];
        Some(EapPacket {
            code,
            id,
            etype: Some(etype),
            data: buf[EAP_HEADER_LEN + 1..end].to_vec(),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let body_len = match self.code {
            EAP_CODE_SUCCESS | EAP_CODE_FAILURE => 0,
            _ => 1 + self.data.len(),
        };
        let total = EAP_HEADER_LEN + body_len;
        let mut v = Vec::with_capacity(total);
        v.push(self.code);
        v.push(self.id);
        v.extend_from_slice(&(total as u16).to_be_bytes());
        if body_len > 0 {
            v.push(self.etype.unwrap_or(0));
            v.extend_from_slice(&self.data);
        }
        v
    }

    pub fn request(id: u8, etype: u8, data: Vec<u8>) -> EapPacket {
        EapPacket {
            code: EAP_CODE_REQUEST,
            id,
            etype: Some(etype),
            data,
        }
    }

    pub fn identity_response(id: u8, identity: &[u8]) -> EapPacket {
        EapPacket {
            code: EAP_CODE_RESPONSE,
            id,
            etype: Some(EAP_TYPE_IDENTITY),
            data: identity.to_vec(),
        }
    }

    pub fn notification_response(id: u8) -> EapPacket {
        EapPacket {
            code: EAP_CODE_RESPONSE,
            id,
            etype: Some(EAP_TYPE_NOTIFICATION),
            data: Vec::new(),
        }
    }

    pub fn nak(id: u8, desired: u8) -> EapPacket {
        EapPacket {
            code: EAP_CODE_RESPONSE,
            id,
            etype: Some(EAP_TYPE_NAK),
            data: vec![desired],
        }
    }

    /// EAP-Response/MD5-Challenge (RFC 3748 section 5.4).
    ///
    /// value = MD5(Identifier | password | challenge)
    pub fn md5_response(id: u8, password: &[u8], challenge: &[u8]) -> EapPacket {
        use md5::{Digest, Md5};
        let mut h = Md5::new();
        h.update([id]);
        h.update(password);
        h.update(challenge);
        let digest = h.finalize();

        let mut data = Vec::with_capacity(1 + 16);
        data.push(16u8);
        data.extend_from_slice(&digest);
        EapPacket {
            code: EAP_CODE_RESPONSE,
            id,
            etype: Some(EAP_TYPE_MD5),
            data,
        }
    }
}

/// Split an EAP-Request/MD5-Challenge payload into its challenge bytes.
pub fn md5_challenge(data: &[u8]) -> Option<&[u8]> {
    if data.is_empty() {
        return None;
    }
    let size = data[0] as usize;
    let avail = data.len() - 1;
    let n = size.min(avail);
    Some(&data[1..1 + n])
}
