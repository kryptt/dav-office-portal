//! Stalwart OIDC client: authorization code + PKCE flow done by hand
//! against reqwest. The `openidconnect` crate's v4 type system is more
//! pain than it's worth for the three HTTP calls we make.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::Rng;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

#[derive(Debug, Clone)]
pub struct OidcClient {
    http: Client,
    discovery: Discovery,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    scopes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    #[serde(default)]
    pub jwks_uri: Option<String>,
}

impl OidcClient {
    pub async fn discover(
        issuer: Url,
        client_id: String,
        client_secret: String,
        redirect_uri: Url,
        scopes: Vec<String>,
    ) -> Result<Self, OidcError> {
        let http = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| OidcError::Http(e.to_string()))?;
        let discovery_url = issuer
            .join(".well-known/openid-configuration")
            .map_err(|e| OidcError::Discovery(e.to_string()))?;
        let resp = http
            .get(discovery_url)
            .send()
            .await
            .map_err(|e| OidcError::Discovery(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(OidcError::Discovery(format!(
                "HTTP {}",
                resp.status().as_u16()
            )));
        }
        let discovery: Discovery = resp
            .json()
            .await
            .map_err(|e| OidcError::Discovery(e.to_string()))?;
        Ok(Self {
            http,
            discovery,
            client_id,
            client_secret,
            redirect_uri: redirect_uri.to_string(),
            scopes,
        })
    }

    pub fn discovery(&self) -> &Discovery {
        &self.discovery
    }

    /// Build the authorize URL plus the per-attempt state to round-trip
    /// through the user's browser via a temporary cookie.
    pub fn begin(&self) -> Result<(Url, AuthState), OidcError> {
        let csrf_token = random_string(32);
        let nonce = random_string(32);
        let pkce_verifier = random_string(64);
        let pkce_challenge = pkce_s256(&pkce_verifier);

        let mut url = Url::parse(&self.discovery.authorization_endpoint)
            .map_err(|e| OidcError::Discovery(e.to_string()))?;
        let scope = self.scopes.join(" ");
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("scope", &scope)
            .append_pair("state", &csrf_token)
            .append_pair("nonce", &nonce)
            .append_pair("code_challenge", &pkce_challenge)
            .append_pair("code_challenge_method", "S256");
        Ok((
            url,
            AuthState {
                csrf_token,
                nonce,
                pkce_verifier,
            },
        ))
    }

    pub async fn exchange_code(
        &self,
        code: &str,
        state: &AuthState,
    ) -> Result<Tokens, OidcError> {
        let form = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &self.redirect_uri),
            ("client_id", &self.client_id),
            ("code_verifier", &state.pkce_verifier),
        ];
        let resp = self
            .http
            .post(&self.discovery.token_endpoint)
            .basic_auth(&self.client_id, Some(&self.client_secret))
            .form(&form)
            .send()
            .await
            .map_err(|e| OidcError::Http(e.to_string()))?;
        let status = resp.status();
        let body_bytes = resp.bytes().await.map_err(|e| OidcError::Http(e.to_string()))?;
        if !status.is_success() {
            return Err(OidcError::Token(format!(
                "token endpoint returned {}: {}",
                status.as_u16(),
                String::from_utf8_lossy(&body_bytes)
            )));
        }
        let token_resp: TokenResponse = serde_json::from_slice(&body_bytes)
            .map_err(|e| OidcError::Token(format!("parse: {e}")))?;

        let claims = extract_claims_unverified(&token_resp.id_token)?;
        Ok(Tokens {
            access_token: token_resp.access_token,
            refresh_token: token_resp.refresh_token,
            expires_in: token_resp.expires_in.unwrap_or(3600),
            sub: claims.sub,
            email: claims.email.unwrap_or_default(),
            name: claims.name,
        })
    }

    pub async fn refresh(&self, refresh_token: &str) -> Result<Tokens, OidcError> {
        let form = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", &self.client_id),
        ];
        let resp = self
            .http
            .post(&self.discovery.token_endpoint)
            .basic_auth(&self.client_id, Some(&self.client_secret))
            .form(&form)
            .send()
            .await
            .map_err(|e| OidcError::Http(e.to_string()))?;
        let status = resp.status();
        let body_bytes = resp.bytes().await.map_err(|e| OidcError::Http(e.to_string()))?;
        if !status.is_success() {
            return Err(OidcError::Token(format!(
                "refresh returned {}: {}",
                status.as_u16(),
                String::from_utf8_lossy(&body_bytes)
            )));
        }
        let token_resp: TokenResponse = serde_json::from_slice(&body_bytes)
            .map_err(|e| OidcError::Token(format!("parse: {e}")))?;
        let claims = extract_claims_unverified(&token_resp.id_token)?;
        Ok(Tokens {
            access_token: token_resp.access_token,
            refresh_token: token_resp.refresh_token,
            expires_in: token_resp.expires_in.unwrap_or(3600),
            sub: claims.sub,
            email: claims.email.unwrap_or_default(),
            name: claims.name,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthState {
    pub csrf_token: String,
    pub nonce: String,
    pub pkce_verifier: String,
}

#[derive(Debug, Clone, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<i64>,
    id_token: String,
}

#[derive(Debug, Clone)]
pub struct Tokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: i64,
    pub sub: String,
    pub email: String,
    pub name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IdTokenClaimsRaw {
    sub: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

fn extract_claims_unverified(id_token: &str) -> Result<IdTokenClaimsRaw, OidcError> {
    let parts: Vec<&str> = id_token.split('.').collect();
    if parts.len() != 3 {
        return Err(OidcError::Token("malformed id_token".into()));
    }
    let payload = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| OidcError::Token(format!("id_token payload decode: {e}")))?;
    let claims: IdTokenClaimsRaw = serde_json::from_slice(&payload)
        .map_err(|e| OidcError::Token(format!("id_token payload parse: {e}")))?;
    Ok(claims)
}

fn random_string(n_bytes: usize) -> String {
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..n_bytes).map(|_| rng.r#gen()).collect();
    URL_SAFE_NO_PAD.encode(bytes)
}

fn pkce_s256(verifier: &str) -> String {
    let mut h = Sha256::new();
    h.update(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(h.finalize())
}

#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    #[error("http error: {0}")]
    Http(String),
    #[error("oidc discovery failed: {0}")]
    Discovery(String),
    #[error("oidc token exchange failed: {0}")]
    Token(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_claims_parses_minimal_jwt_payload() {
        let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"u1","email":"e@x","name":"E"}"#);
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let token = format!("{header}.{payload}.sig");
        let claims = extract_claims_unverified(&token).unwrap();
        assert_eq!(claims.sub, "u1");
        assert_eq!(claims.email.as_deref(), Some("e@x"));
    }

    #[test]
    fn pkce_s256_is_deterministic() {
        let a = pkce_s256("verifier-abcdef-0123456789-very-long-string");
        let b = pkce_s256("verifier-abcdef-0123456789-very-long-string");
        assert_eq!(a, b);
        let c = pkce_s256("different");
        assert_ne!(a, c);
    }

    #[test]
    fn random_string_yields_url_safe_chars() {
        let s = random_string(32);
        assert!(s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        assert!(!s.is_empty());
    }
}
