use axum::Router;
use axum::response::IntoResponse;
use axum::routing::get;
use axum_extra::extract::cookie::Key;
use std::sync::Arc;
use tracing_subscriber::{EnvFilter, fmt};

mod config;
mod dav;
mod file_jwt;
mod oidc;
mod onlyoffice;
mod routes;
mod session;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .json()
        .init();

    let cfg = Arc::new(config::Config::from_env()?);
    tracing::info!(
        public_base_url = %cfg.public_base_url,
        oidc_issuer = %cfg.oidc_issuer,
        "dav-office-portal starting"
    );

    let redirect_uri = cfg
        .public_base_url
        .join("/oidc/callback")
        .expect("PUBLIC_BASE_URL must be a valid URL");
    let oidc = oidc::OidcClient::discover(
        cfg.oidc_issuer.clone(),
        cfg.oidc_client_id.clone(),
        cfg.oidc_client_secret.clone(),
        redirect_uri,
        vec![
            "openid".to_string(),
            "offline_access".to_string(),
        ],
    )
    .await?;

    // axum-extra's `Key` needs 64 bytes; derive deterministically from our
    // 32-byte session key.
    let cookie_key = {
        let mut padded = vec![0u8; 64];
        padded[..32].copy_from_slice(&cfg.session_key);
        padded[32..].copy_from_slice(&cfg.session_key);
        Key::from(&padded)
    };

    let state = routes::AppState {
        config: cfg.clone(),
        oidc: Arc::new(oidc),
        cookie_key: cookie_key.clone(),
    };

    let app = routes::router(state.clone()).layer(
        tower_http::trace::TraceLayer::new_for_http(),
    );
    let metrics_app = Router::new().route("/healthz", get(healthz));

    let public_listener = tokio::net::TcpListener::bind(cfg.bind).await?;
    let metrics_listener = tokio::net::TcpListener::bind(cfg.metrics_bind).await?;
    tracing::info!(bind = %cfg.bind, metrics_bind = %cfg.metrics_bind, "listening");

    let (a, b) = tokio::join!(
        axum::serve(public_listener, app),
        axum::serve(metrics_listener, metrics_app),
    );
    a?;
    b?;
    Ok(())
}

async fn healthz() -> impl IntoResponse {
    "ok"
}

#[cfg(test)]
mod tests {
    #[test]
    fn placeholder() {
        assert_eq!(2 + 2, 4);
    }
}
