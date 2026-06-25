//! Encrypted-cookie session: holds the user's Stalwart OIDC tokens.
//!
//! The cookie payload is AES-256-GCM-encrypted CBOR-less JSON. We avoid
//! server-side state for ≤5 users, but if the cookie exceeds 4 KB we'll
//! switch to a keyed in-memory map.

use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, generic_array::GenericArray},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

pub const COOKIE_NAME: &str = "office_portal_session";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Session {
    pub sub: String,
    pub email: String,
    pub name: Option<String>,
    pub access_token: String,
    pub refresh_token: Option<String>,
    /// Unix-second timestamp the access token expires at.
    pub access_token_exp: i64,
}

impl Session {
    pub fn email_domain(&self) -> Option<&str> {
        self.email.split_once('@').map(|(_, d)| d)
    }

    #[allow(dead_code)]
    pub fn is_access_token_expired(&self, now: OffsetDateTime) -> bool {
        now.unix_timestamp() >= self.access_token_exp
    }

    /// Encrypt the session into the form stored in the cookie value.
    pub fn encrypt(&self, key: &[u8; 32]) -> Result<String, SessionError> {
        let payload = serde_json::to_vec(self)?;
        let cipher = Aes256Gcm::new(key.into());
        let mut nonce_bytes = [0u8; 12];
        rand::Rng::fill(&mut rand::thread_rng(), &mut nonce_bytes);
        let nonce = GenericArray::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(nonce, payload.as_ref())
            .map_err(|_| SessionError::Encrypt)?;
        // wire format: base64url(nonce || ciphertext)
        let mut buf = Vec::with_capacity(12 + ct.len());
        buf.extend_from_slice(&nonce_bytes);
        buf.extend_from_slice(&ct);
        Ok(URL_SAFE_NO_PAD.encode(buf))
    }

    pub fn decrypt(value: &str, key: &[u8; 32]) -> Result<Self, SessionError> {
        let buf = URL_SAFE_NO_PAD
            .decode(value.as_bytes())
            .map_err(|_| SessionError::Decode)?;
        if buf.len() < 12 + 16 {
            return Err(SessionError::Decode);
        }
        let (nonce_bytes, ct) = buf.split_at(12);
        let cipher = Aes256Gcm::new(key.into());
        let nonce = GenericArray::from_slice(nonce_bytes);
        let pt = cipher
            .decrypt(nonce, ct)
            .map_err(|_| SessionError::Decrypt)?;
        Ok(serde_json::from_slice(&pt)?)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed")]
    Decrypt,
    #[error("cookie decode failed")]
    Decode,
    #[error("session serialization: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Session {
        Session {
            sub: "abc".into(),
            email: "user@example.com".into(),
            name: Some("Test User".into()),
            access_token: "at".into(),
            refresh_token: Some("rt".into()),
            access_token_exp: 9_999_999_999,
        }
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [7u8; 32];
        let s = sample();
        let enc = s.encrypt(&key).unwrap();
        let dec = Session::decrypt(&enc, &key).unwrap();
        assert_eq!(s, dec);
    }

    #[test]
    fn decrypt_rejects_wrong_key() {
        let s = sample();
        let enc = s.encrypt(&[1u8; 32]).unwrap();
        assert!(Session::decrypt(&enc, &[2u8; 32]).is_err());
    }

    #[test]
    fn decrypt_rejects_garbage() {
        assert!(Session::decrypt("not-base64!!!", &[0u8; 32]).is_err());
        assert!(Session::decrypt("AAAA", &[0u8; 32]).is_err());
    }

    #[test]
    fn email_domain_extracts() {
        assert_eq!(sample().email_domain(), Some("example.com"));
    }

    #[test]
    fn access_token_expiry_check() {
        let mut s = sample();
        s.access_token_exp = 100;
        let now = OffsetDateTime::from_unix_timestamp(99).unwrap();
        assert!(!s.is_access_token_expired(now));
        let later = OffsetDateTime::from_unix_timestamp(100).unwrap();
        assert!(s.is_access_token_expired(later));
    }
}
