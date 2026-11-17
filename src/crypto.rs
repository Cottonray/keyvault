//! Value encryption and machine tokens.
//!
//! Values are sealed with AES-256-GCM under a single 32-byte master key that lives in a file
//! outside the database. The additional authenticated data binds each ciphertext to its
//! `path\0key`, so a row copied onto another path or key fails to open.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub type MasterKey = [u8; 32];

/// Ciphertext with the GCM tag appended (as produced by `aes-gcm`).
#[derive(Clone, Debug)]
pub struct Sealed {
    pub iv: Vec<u8>,
    pub data: Vec<u8>,
}

/// Accepts exactly 32 raw bytes or 64 hex characters. Anything else is rejected so a short or
/// truncated key never runs silently.
pub fn load_master_key(raw: &[u8]) -> Result<MasterKey, String> {
    if raw.len() == 32 {
        return Ok(raw.try_into().unwrap());
    }
    let text = std::str::from_utf8(raw).map_err(|_| "master key is neither 32 bytes nor hex")?.trim();
    if text.len() == 64 {
        if let Ok(bytes) = hex::decode(text) {
            return Ok(bytes.try_into().unwrap());
        }
    }
    Err("master key must be 32 raw bytes or 64 hex characters".into())
}

fn aad(path: &str, key: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(path.len() + key.len() + 1);
    v.extend_from_slice(path.as_bytes());
    v.push(0);
    v.extend_from_slice(key.as_bytes());
    v
}

pub fn seal(master: &MasterKey, path: &str, key: &str, value: &str) -> Sealed {
    let cipher = Aes256Gcm::new(master.into());
    let mut iv = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut iv);
    let data = cipher
        .encrypt(Nonce::from_slice(&iv), Payload { msg: value.as_bytes(), aad: &aad(path, key) })
        .expect("AES-GCM encryption does not fail for in-memory input");
    Sealed { iv: iv.to_vec(), data }
}

pub fn open(master: &MasterKey, path: &str, key: &str, sealed: &Sealed) -> Result<String, String> {
    if sealed.iv.len() != 12 {
        return Err("corrupt nonce".into());
    }
    let cipher = Aes256Gcm::new(master.into());
    let plain = cipher
        .decrypt(Nonce::from_slice(&sealed.iv), Payload { msg: &sealed.data, aad: &aad(path, key) })
        .map_err(|_| format!("cannot decrypt {path}:{key} (wrong master key or moved row)"))?;
    String::from_utf8(plain).map_err(|_| "decrypted value is not UTF-8".into())
}

/// Short fingerprint of the master key: compare a backup copy with the live key without
/// revealing either.
pub fn fingerprint(master: &MasterKey) -> String {
    hex::encode(&Sha256::digest(master)[..8])
}

pub fn random_master_key_hex() -> String {
    let mut k = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut k);
    hex::encode(k)
}

// ─── Machine tokens ─────────────────────────────────────────────────────────
// Format: kv_<id 12 chars>_<secret 43 chars>. Only the id and sha256(secret) are stored; the
// full token is shown once at creation.

pub struct NewToken {
    pub id: String,
    pub token: String,
    pub hash: String,
}

pub fn new_token() -> NewToken {
    let mut id = [0u8; 9];
    let mut secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut id);
    rand::rngs::OsRng.fill_bytes(&mut secret);
    let id = URL_SAFE_NO_PAD.encode(id);
    let secret = URL_SAFE_NO_PAD.encode(secret);
    NewToken { token: format!("kv_{id}_{secret}"), hash: hash_secret(&secret), id }
}

pub fn hash_secret(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}

fn b64url(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Splits by position, not by `_`, because base64url itself contains `_`.
pub fn parse_token(token: &str) -> Option<(String, String)> {
    if token.len() != 59 || !token.starts_with("kv_") || token.as_bytes()[15] != b'_' {
        return None;
    }
    let (id, secret) = (&token[3..15], &token[16..]);
    (b64url(id) && b64url(secret)).then(|| (id.to_string(), secret.to_string()))
}

pub fn same_hash(a: &str, b: &str) -> bool {
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_binding() {
        let k = [7u8; 32];
        let s = seal(&k, "deploy/a/.env", "TOKEN", "hello world");
        assert_eq!(open(&k, "deploy/a/.env", "TOKEN", &s).unwrap(), "hello world");
        assert!(open(&k, "deploy/b/.env", "TOKEN", &s).is_err(), "moved path must fail");
        assert!(open(&k, "deploy/a/.env", "OTHER", &s).is_err(), "moved key must fail");
        assert!(open(&[8u8; 32], "deploy/a/.env", "TOKEN", &s).is_err(), "wrong master must fail");
    }

    #[test]
    fn master_key_formats() {
        assert!(load_master_key(&[1u8; 32]).is_ok());
        assert!(load_master_key(format!("{}\n", "ab".repeat(32)).as_bytes()).is_ok());
        assert!(load_master_key(b"short").is_err());
        assert!(load_master_key("zz".repeat(32).as_bytes()).is_err());
    }

    #[test]
    fn tokens() {
        let t = new_token();
        let (id, secret) = parse_token(&t.token).unwrap();
        assert_eq!(id, t.id);
        assert!(same_hash(&hash_secret(&secret), &t.hash));
        assert!(parse_token("kv_short").is_none());
        assert!(parse_token(&t.token.replace("kv_", "xx_")).is_none());
    }
}
