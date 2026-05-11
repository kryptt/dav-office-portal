//! Short-lived JWTs that OnlyOffice DS uses to fetch/save a single file
//! via the portal. The portal mints them when rendering the editor page,
//! and verifies them on `/api/file/:jwt` and `/api/callback/:jwt`.
//!
//! The JWT carries everything OnlyOffice needs to talk back to the portal
//! about one file:
//!   - which user (email)
//!   - which path on WebDAV
//!   - whether the caller is allowed to GET (read) or POST (write)
//!   - encrypted-at-rest session blob so the portal can act as the user
//!     without holding a separate server-side cache. The session is
//!     encrypted with the portal's session key (same one as the browser
//!     cookie) so only the portal can unwrap it.

use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

use crate::session::Session;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Read,
    Write,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileClaims {
    pub sub: String,
    pub email: String,
    pub path: String,
    pub action: Action,
    /// Encrypted Session (so OnlyOffice DS can authenticate to WebDAV
    /// via the portal without us holding server-side state).
    pub session_enc: String,
    pub exp: i64,
    pub iat: i64,
}

pub fn mint(
    session: &Session,
    path: &str,
    action: Action,
    ttl_secs: i64,
    jwt_key: &[u8; 32],
    session_key: &[u8; 32],
) -> Result<String, FileJwtError> {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let claims = FileClaims {
        sub: session.sub.clone(),
        email: session.email.clone(),
        path: path.to_string(),
        action,
        session_enc: session.encrypt(session_key)?,
        exp: now + ttl_secs,
        iat: now,
    };
    let token = encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(jwt_key),
    )?;
    Ok(token)
}

pub fn verify(
    token: &str,
    expected_action: Action,
    jwt_key: &[u8; 32],
    session_key: &[u8; 32],
) -> Result<(FileClaims, Session), FileJwtError> {
    let mut v = Validation::new(jsonwebtoken::Algorithm::HS256);
    v.validate_exp = true;
    v.leeway = 0;
    v.required_spec_claims.clear();
    let data = decode::<FileClaims>(token, &DecodingKey::from_secret(jwt_key), &v)?;
    if data.claims.action != expected_action {
        return Err(FileJwtError::WrongAction);
    }
    let session = Session::decrypt(&data.claims.session_enc, session_key)
        .map_err(|_| FileJwtError::SessionDecrypt)?;
    Ok((data.claims, session))
}

#[derive(Debug, thiserror::Error)]
pub enum FileJwtError {
    #[error("jwt error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("session encryption failed")]
    Session(#[from] crate::session::SessionError),
    #[error("session decrypt failed")]
    SessionDecrypt,
    #[error("token action doesn't match endpoint")]
    WrongAction,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> Session {
        Session {
            sub: "u1".into(),
            email: "rhansen@fida.finance".into(),
            name: None,
            access_token: "at".into(),
            refresh_token: None,
            access_token_exp: 9_999_999_999,
        }
    }

    #[test]
    fn mint_and_verify_roundtrip() {
        let jk = [3u8; 32];
        let sk = [4u8; 32];
        let s = session();
        let tok = mint(&s, "/dav/file/x.docx", Action::Write, 60, &jk, &sk).unwrap();
        let (claims, recovered) = verify(&tok, Action::Write, &jk, &sk).unwrap();
        assert_eq!(claims.path, "/dav/file/x.docx");
        assert_eq!(claims.email, "rhansen@fida.finance");
        assert_eq!(recovered.access_token, "at");
    }

    #[test]
    fn verify_rejects_wrong_action() {
        let jk = [3u8; 32];
        let sk = [4u8; 32];
        let tok = mint(&session(), "/x", Action::Read, 60, &jk, &sk).unwrap();
        let res = verify(&tok, Action::Write, &jk, &sk);
        assert!(matches!(res, Err(FileJwtError::WrongAction)));
    }

    #[test]
    fn verify_rejects_expired() {
        let jk = [3u8; 32];
        let sk = [4u8; 32];
        let tok = mint(&session(), "/x", Action::Read, -10, &jk, &sk).unwrap();
        assert!(verify(&tok, Action::Read, &jk, &sk).is_err());
    }

    #[test]
    fn verify_rejects_wrong_jwt_key() {
        let tok = mint(&session(), "/x", Action::Read, 60, &[1u8; 32], &[2u8; 32]).unwrap();
        assert!(verify(&tok, Action::Read, &[9u8; 32], &[2u8; 32]).is_err());
    }
}
