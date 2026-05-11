use std::net::SocketAddr;
use url::Url;

#[derive(Debug, Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub metrics_bind: SocketAddr,
    pub public_base_url: Url,
    pub oidc_issuer: Url,
    pub oidc_client_id: String,
    pub oidc_client_secret: String,
    pub oo_document_server_url: Url,
    pub oo_jwt_secret: String,
    pub file_jwt_key: [u8; 32],
    pub session_key: [u8; 32],
    pub dav_base_url_template: String,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind = env_or("BIND_ADDR", "0.0.0.0:3000").parse()?;
        let metrics_bind = env_or("METRICS_ADDR", "0.0.0.0:9090").parse()?;
        let public_base_url = parse_url(&require_env("PUBLIC_BASE_URL")?)?;
        let oidc_issuer = parse_url(&env_or("OIDC_ISSUER", "https://stalwart.hr-home.xyz"))?;
        let oidc_client_id = env_or("OIDC_CLIENT_ID", "office-portal");
        let oidc_client_secret = require_env("OIDC_CLIENT_SECRET")?;
        let oo_document_server_url = parse_url(&require_env("OO_DOCUMENT_SERVER_URL")?)?;
        let oo_jwt_secret = require_env("OO_JWT_SECRET")?;
        let file_jwt_key = decode_key("FILE_JWT_KEY")?;
        let session_key = decode_key("SESSION_KEY")?;
        let dav_base_url_template = env_or("DAV_BASE_URL_TEMPLATE", "https://dav.{domain}");

        Ok(Self {
            bind,
            metrics_bind,
            public_base_url,
            oidc_issuer,
            oidc_client_id,
            oidc_client_secret,
            oo_document_server_url,
            oo_jwt_secret,
            file_jwt_key,
            session_key,
            dav_base_url_template,
        })
    }

    /// Resolve the WebDAV base URL for a user, given their email's domain.
    pub fn dav_base_url(&self, email_domain: &str) -> Result<Url, url::ParseError> {
        let s = self.dav_base_url_template.replace("{domain}", email_domain);
        Url::parse(&s)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing required env var {0}")]
    Missing(String),
    #[error("invalid socket address: {0}")]
    Addr(#[from] std::net::AddrParseError),
    #[error("invalid URL: {0}")]
    Url(#[from] url::ParseError),
    #[error("invalid key for {var}: {reason}")]
    Key { var: String, reason: String },
}

fn env_or(var: &str, default: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| default.to_string())
}

fn require_env(var: &str) -> Result<String, ConfigError> {
    std::env::var(var).map_err(|_| ConfigError::Missing(var.to_string()))
}

fn parse_url(s: &str) -> Result<Url, ConfigError> {
    Ok(Url::parse(s)?)
}

/// Decode a 32-byte key from a hex- or base64-encoded env var.
fn decode_key(var: &str) -> Result<[u8; 32], ConfigError> {
    use base64::Engine;
    let raw = require_env(var)?;
    let bytes = if raw.len() == 64 && raw.chars().all(|c| c.is_ascii_hexdigit()) {
        (0..raw.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&raw[i..i + 2], 16))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| ConfigError::Key {
                var: var.to_string(),
                reason: e.to_string(),
            })?
    } else {
        base64::engine::general_purpose::STANDARD
            .decode(raw.trim())
            .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(raw.trim()))
            .map_err(|e| ConfigError::Key {
                var: var.to_string(),
                reason: e.to_string(),
            })?
    };
    if bytes.len() != 32 {
        return Err(ConfigError::Key {
            var: var.to_string(),
            reason: format!("expected 32 bytes, got {}", bytes.len()),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dav_base_url_substitutes_domain() {
        let cfg = Config {
            bind: "0.0.0.0:3000".parse().unwrap(),
            metrics_bind: "0.0.0.0:9090".parse().unwrap(),
            public_base_url: Url::parse("https://office.hr-home.xyz").unwrap(),
            oidc_issuer: Url::parse("https://stalwart.hr-home.xyz").unwrap(),
            oidc_client_id: "office-portal".into(),
            oidc_client_secret: "x".into(),
            oo_document_server_url: Url::parse("https://docs.hr-home.xyz").unwrap(),
            oo_jwt_secret: "x".into(),
            file_jwt_key: [0u8; 32],
            session_key: [0u8; 32],
            dav_base_url_template: "https://dav.{domain}".into(),
        };
        let url = cfg.dav_base_url("fida.finance").unwrap();
        assert_eq!(url.as_str(), "https://dav.fida.finance/");
    }

    #[test]
    fn decode_key_accepts_hex_and_base64() {
        use base64::Engine;
        // hex (64 chars)
        let hex = "0".repeat(64);
        unsafe { std::env::set_var("K_HEX", &hex) };
        assert_eq!(decode_key("K_HEX").unwrap(), [0u8; 32]);

        // base64 (44 chars w/ padding)
        let b64 = base64::engine::general_purpose::STANDARD.encode([1u8; 32]);
        unsafe { std::env::set_var("K_B64", &b64) };
        assert_eq!(decode_key("K_B64").unwrap(), [1u8; 32]);
    }
}
