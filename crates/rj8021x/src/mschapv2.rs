//! MSCHAPv2 (RFC 2759) crypto primitives, used inside EAP-PEAP.
//!
//! Only compiled with `--features peap`.

use des::cipher::{BlockEncrypt, KeyInit};
use des::Des;
use md4::Md4;
use sha1::{Digest, Sha1};

const MAGIC1: &[u8] = b"Magic server to client signing constant";
const MAGIC2: &[u8] = b"Pad to make it do more than one iteration";

/// NT password hash: MD4 over the UTF-16LE encoding of the password.
pub fn nt_password_hash(password: &str) -> [u8; 16] {
    let mut buf = Vec::with_capacity(password.len() * 2);
    for u in password.encode_utf16() {
        buf.extend_from_slice(&u.to_le_bytes());
    }
    let mut h = Md4::new();
    h.update(&buf);
    let d = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&d);
    out
}

/// MD4(NT password hash).
pub fn hash_nt_password_hash(nt: &[u8; 16]) -> [u8; 16] {
    let mut h = Md4::new();
    h.update(nt);
    let d = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&d);
    out
}

/// SHA1(peer_challenge | auth_challenge | username), first 8 bytes.
pub fn challenge_hash(peer: &[u8; 16], auth: &[u8; 16], user: &str) -> [u8; 8] {
    let mut h = Sha1::new();
    h.update(peer);
    h.update(auth);
    h.update(user.as_bytes());
    let d = h.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&d[..8]);
    out
}

/// Expand a 7-byte DES key into 8 bytes with the odd parity bit positions zeroed.
fn expand_des_key(key7: &[u8; 7]) -> [u8; 8] {
    let mut k = [0u8; 8];
    k[0] = key7[0] & 0xFE;
    k[1] = (((key7[0] as u16) << 7) | ((key7[1] as u16) >> 1)) as u8 & 0xFE;
    k[2] = (((key7[1] as u16) << 6) | ((key7[2] as u16) >> 2)) as u8 & 0xFE;
    k[3] = (((key7[2] as u16) << 5) | ((key7[3] as u16) >> 3)) as u8 & 0xFE;
    k[4] = (((key7[3] as u16) << 4) | ((key7[4] as u16) >> 4)) as u8 & 0xFE;
    k[5] = (((key7[4] as u16) << 3) | ((key7[5] as u16) >> 5)) as u8 & 0xFE;
    k[6] = (((key7[5] as u16) << 2) | ((key7[6] as u16) >> 6)) as u8 & 0xFE;
    k[7] = ((key7[6] as u16) << 1) as u8 & 0xFE;
    k
}

fn des_encrypt_block(key: &[u8; 8], data: &[u8; 8]) -> [u8; 8] {
    let cipher = Des::new_from_slice(key).expect("8-byte DES key");
    let mut block = des::cipher::Block::<Des>::clone_from_slice(data);
    cipher.encrypt_block(&mut block);
    let mut out = [0u8; 8];
    out.copy_from_slice(&block);
    out
}

/// MSCHAPv2 ChallengeResponse: 24 bytes (three DES ECB encryptions of the
/// 8-byte challenge using 7-byte slices of the 16-byte NT hash padded to 21).
pub fn challenge_response(nt: &[u8; 16], challenge: &[u8; 8]) -> [u8; 24] {
    let mut key = [0u8; 21];
    key[..16].copy_from_slice(nt);
    let mut out = [0u8; 24];
    for i in 0..3 {
        let mut k7 = [0u8; 7];
        k7.copy_from_slice(&key[i * 7..i * 7 + 7]);
        let k8 = expand_des_key(&k7);
        let enc = des_encrypt_block(&k8, challenge);
        out[i * 8..i * 8 + 8].copy_from_slice(&enc);
    }
    out
}

/// GenerateAuthenticatorResponse, returned as the `S=<40 hex chars>` string.
pub fn generate_authenticator_response(
    nt: &[u8; 16],
    nt_response: &[u8; 24],
    peer: &[u8; 16],
    auth: &[u8; 16],
    user: &str,
) -> String {
    let pw_hash_hash = hash_nt_password_hash(nt);

    let mut h = Sha1::new();
    h.update(pw_hash_hash);
    h.update(nt_response);
    h.update(MAGIC1);
    h.update(peer);
    h.update(auth);
    h.update(user.as_bytes());
    let digest = h.finalize();

    let mut h2 = Sha1::new();
    h2.update(digest);
    h2.update(MAGIC2);
    h2.update(pw_hash_hash);
    let resp = h2.finalize();

    format!("S={}", hex::encode(resp))
}