//! Axum routes for the portal.

use axum::{
    Json, Router,
    body::Body,
    extract::{FromRef, Multipart, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use axum_extra::extract::{
    PrivateCookieJar,
    cookie::{Cookie, Key, SameSite},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use time::OffsetDateTime;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

use crate::config::Config;
use crate::dav::{DavClient, DavEntry};
use crate::file_jwt::{self, Action};
use crate::metrics::{self, Metrics};
use crate::oidc::{AuthState, OidcClient};
use crate::onlyoffice::{self, Callback, FileKind};
use crate::session::{COOKIE_NAME, Session};

const AUTH_STATE_COOKIE: &str = "office_portal_auth_state";

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub oidc: Arc<OidcClient>,
    pub cookie_key: Key,
    pub metrics: Arc<Metrics>,
}

impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.cookie_key.clone()
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/healthz", get(healthz))
        .route("/oidc/login", get(oidc_login))
        .route("/oidc/callback", get(oidc_callback))
        .route("/oidc/logout", post(oidc_logout))
        .route("/api/files", get(list_files))
        .route("/api/upload", post(upload))
        .route("/api/mkdir", post(mkdir))
        .route("/api/rename", post(rename))
        .route("/api/delete", post(delete))
        .route("/editor", get(editor))
        .route("/api/file/{token}", get(file_get))
        .route("/api/callback/{token}", post(file_callback))
        .with_state(state)
}

async fn healthz() -> impl IntoResponse {
    "ok"
}

async fn index(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
) -> Response {
    match load_session(&state, &jar) {
        Some(_) => Html(include_str!("templates/browser.html")).into_response(),
        None => Redirect::to("/oidc/login").into_response(),
    }
}

async fn oidc_login(State(state): State<AppState>, jar: PrivateCookieJar) -> Response {
    let (auth_url, auth_state) = match state.oidc.begin() {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error=?e, "oidc begin failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "oidc begin failed").into_response();
        }
    };
    let state_cookie = Cookie::build((AUTH_STATE_COOKIE, serde_json::to_string(&auth_state).unwrap()))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::minutes(15))
        .build();
    let jar = jar.add(state_cookie);
    (jar, Redirect::to(auth_url.as_str())).into_response()
}

#[derive(Debug, Deserialize)]
struct OidcCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

async fn oidc_callback(
    State(state): State<AppState>,
    Query(q): Query<OidcCallbackQuery>,
    jar: PrivateCookieJar,
) -> Response {
    if let Some(err) = q.error {
        let desc = q.error_description.unwrap_or_default();
        return (StatusCode::BAD_REQUEST, format!("oidc error: {err} {desc}")).into_response();
    }
    let code = match q.code {
        Some(c) => c,
        None => return (StatusCode::BAD_REQUEST, "missing code").into_response(),
    };
    let returned_state = q.state.unwrap_or_default();

    let state_cookie = match jar.get(AUTH_STATE_COOKIE) {
        Some(c) => c,
        None => return (StatusCode::BAD_REQUEST, "missing auth state").into_response(),
    };
    let auth_state: AuthState = match serde_json::from_str(state_cookie.value()) {
        Ok(s) => s,
        Err(_) => return (StatusCode::BAD_REQUEST, "bad auth state").into_response(),
    };
    if auth_state.csrf_token != returned_state {
        return (StatusCode::BAD_REQUEST, "csrf mismatch").into_response();
    }

    let tokens = match state.oidc.exchange_code(&code, &auth_state).await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error=?e, "token exchange failed");
            return (StatusCode::BAD_GATEWAY, format!("token exchange failed: {e}")).into_response();
        }
    };
    let session = Session {
        sub: tokens.sub,
        email: tokens.email,
        name: tokens.name,
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        access_token_exp: OffsetDateTime::now_utc().unix_timestamp() + tokens.expires_in,
    };
    let session_value = match session.encrypt(&state.config.session_key) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error=?e, "session encrypt failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "session encrypt failed").into_response();
        }
    };
    let session_cookie = Cookie::build((COOKIE_NAME, session_value))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::days(7))
        .build();
    let jar = jar.add(session_cookie).remove(Cookie::from(AUTH_STATE_COOKIE));
    (jar, Redirect::to("/")).into_response()
}

async fn oidc_logout(jar: PrivateCookieJar) -> Response {
    let jar = jar.remove(Cookie::from(COOKIE_NAME));
    (jar, Redirect::to("/oidc/login")).into_response()
}

// -- File browser API ---------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ListQuery {
    path: Option<String>,
}

async fn list_files(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Query(q): Query<ListQuery>,
) -> Response {
    let session = match load_session(&state, &jar) {
        Some(s) => s,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };
    let (session, jar) = maybe_refresh_session(&state, session, jar).await;
    let client = match dav_client_for(&state, &session) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let path = q.path.unwrap_or_default();
    let start = std::time::Instant::now();
    match client.list(&path).await {
        Ok(entries) => {
            state.metrics.dav_duration.get_or_create(&metrics::DavOpLabels { op: "list" }).observe(start.elapsed().as_secs_f64());
            (jar, Json(ListResponse { entries })).into_response()
        }
        Err(e) => {
            tracing::warn!(error=?e, path=%path, "list failed");
            (jar, (StatusCode::BAD_GATEWAY, format!("list failed: {e}"))).into_response()
        }
    }
}

#[derive(Debug, Serialize)]
struct ListResponse {
    entries: Vec<DavEntry>,
}

async fn upload(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Query(q): Query<ListQuery>,
    mut multipart: Multipart,
) -> Response {
    let session = match load_session(&state, &jar) {
        Some(s) => s,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };
    let (session, jar) = maybe_refresh_session(&state, session, jar).await;
    let client = match dav_client_for(&state, &session) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let dir = q.path.unwrap_or_default();
    while let Ok(Some(field)) = multipart.next_field().await {
        let Some(filename) = field.file_name().map(|s| s.to_string()) else {
            continue;
        };
        let body = match field.bytes().await {
            Ok(b) => b,
            Err(e) => return (jar, (StatusCode::BAD_REQUEST, format!("read: {e}"))).into_response(),
        };
        let rel = if dir.is_empty() {
            filename
        } else {
            format!("{}/{}", dir.trim_end_matches('/'), filename)
        };
        let start = std::time::Instant::now();
        if let Err(e) = client.put_bytes(&rel, body).await {
            return (jar, (StatusCode::BAD_GATEWAY, format!("upload: {e}"))).into_response();
        }
        state.metrics.dav_duration.get_or_create(&metrics::DavOpLabels { op: "put" }).observe(start.elapsed().as_secs_f64());
    }
    (jar, StatusCode::NO_CONTENT).into_response()
}

#[derive(Debug, Deserialize)]
struct PathBody {
    path: String,
}

async fn mkdir(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Json(body): Json<PathBody>,
) -> Response {
    let session = match load_session(&state, &jar) {
        Some(s) => s,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };
    let (session, jar) = maybe_refresh_session(&state, session, jar).await;
    let client = match dav_client_for(&state, &session) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let start = std::time::Instant::now();
    match client.mkcol(&body.path).await {
        Ok(_) => {
            state.metrics.dav_duration.get_or_create(&metrics::DavOpLabels { op: "mkcol" }).observe(start.elapsed().as_secs_f64());
            (jar, StatusCode::CREATED).into_response()
        }
        Err(e) => (jar, (StatusCode::BAD_GATEWAY, format!("mkdir: {e}"))).into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct RenameBody {
    from: String,
    to: String,
}

async fn rename(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Json(body): Json<RenameBody>,
) -> Response {
    let session = match load_session(&state, &jar) {
        Some(s) => s,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };
    let (session, jar) = maybe_refresh_session(&state, session, jar).await;
    let client = match dav_client_for(&state, &session) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let start = std::time::Instant::now();
    match client.mv(&body.from, &body.to).await {
        Ok(_) => {
            state.metrics.dav_duration.get_or_create(&metrics::DavOpLabels { op: "move" }).observe(start.elapsed().as_secs_f64());
            (jar, StatusCode::NO_CONTENT).into_response()
        }
        Err(e) => (jar, (StatusCode::BAD_GATEWAY, format!("rename: {e}"))).into_response(),
    }
}

async fn delete(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Json(body): Json<PathBody>,
) -> Response {
    let session = match load_session(&state, &jar) {
        Some(s) => s,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };
    let (session, jar) = maybe_refresh_session(&state, session, jar).await;
    let client = match dav_client_for(&state, &session) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let start = std::time::Instant::now();
    match client.delete(&body.path).await {
        Ok(_) => {
            state.metrics.dav_duration.get_or_create(&metrics::DavOpLabels { op: "delete" }).observe(start.elapsed().as_secs_f64());
            (jar, StatusCode::NO_CONTENT).into_response()
        }
        Err(e) => (jar, (StatusCode::BAD_GATEWAY, format!("delete: {e}"))).into_response(),
    }
}

// -- OnlyOffice editor --------------------------------------------------------

#[derive(Debug, Deserialize)]
struct EditorQuery {
    path: String,
}

async fn editor(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Query(q): Query<EditorQuery>,
) -> Response {
    let session = match load_session(&state, &jar) {
        Some(s) => s,
        None => return Redirect::to("/oidc/login").into_response(),
    };
    let (session, _jar) = maybe_refresh_session(&state, session, jar).await;
    let kind = FileKind::from_path(&q.path);

    let read_jwt = match file_jwt::mint(
        &session,
        &q.path,
        Action::Read,
        4 * 3600,
        &state.config.file_jwt_key,
        &state.config.session_key,
    ) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error=?e, "file jwt mint failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "jwt mint").into_response();
        }
    };
    let write_jwt = match file_jwt::mint(
        &session,
        &q.path,
        Action::Write,
        4 * 3600,
        &state.config.file_jwt_key,
        &state.config.session_key,
    ) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error=?e, "file jwt mint failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "jwt mint").into_response();
        }
    };
    let base = state.config.public_base_url.as_str().trim_end_matches('/');
    let file_url = format!("{base}/api/file/{read_jwt}");
    let callback_url = format!("{base}/api/callback/{write_jwt}");
    let title = q.path.rsplit('/').next().unwrap_or(&q.path).to_string();
    let key_hash = Sha256::digest(format!("{}:{}:{}", session.sub, q.path, read_jwt));
    let document_key = URL_SAFE_NO_PAD.encode(&key_hash[..16]);

    let editor_cfg = match onlyoffice::build_and_sign(
        &title,
        kind,
        &document_key,
        &file_url,
        &callback_url,
        &session.sub,
        session.name.as_deref().unwrap_or(&session.email),
        state.config.oo_jwt_secret.as_bytes(),
    ) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error=?e, "oo config sign failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "oo config sign").into_response();
        }
    };

    let cfg_json = serde_json::to_string(&editor_cfg).unwrap_or_else(|_| "{}".to_string());
    let docs_url = state.config.oo_document_server_url.as_str().trim_end_matches('/');
    let html = include_str!("templates/editor.html")
        .replace("{{TITLE}}", &html_escape(&title))
        .replace("{{DOC_SERVER}}", docs_url)
        .replace("{{CONFIG_JSON}}", &cfg_json);
    Html(html).into_response()
}

async fn file_get(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Response {
    let (claims, session) = match file_jwt::verify(
        &token,
        Action::Read,
        &state.config.file_jwt_key,
        &state.config.session_key,
    ) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error=?e, "file_get jwt verify failed");
            return StatusCode::FORBIDDEN.into_response();
        }
    };
    let session = maybe_refresh_session_bare(&state, session).await;
    let client = match dav_client_for(&state, &session) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let start = std::time::Instant::now();
    let resp = match client.get(&claims.path).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error=?e, path=%claims.path, "file_get dav failed");
            return (StatusCode::BAD_GATEWAY, format!("dav get: {e}")).into_response();
        }
    };
    let mut hdrs = HeaderMap::new();
    if let Some(ct) = resp.headers().get(header::CONTENT_TYPE) {
        hdrs.insert(header::CONTENT_TYPE, ct.clone());
    } else {
        let guess = mime_guess::from_path(&claims.path).first_or_octet_stream();
        if let Ok(v) = HeaderValue::from_str(guess.as_ref()) {
            hdrs.insert(header::CONTENT_TYPE, v);
        }
    }
    if let Some(cl) = resp.headers().get(header::CONTENT_LENGTH) {
        hdrs.insert(header::CONTENT_LENGTH, cl.clone());
    }
    state.metrics.dav_duration.get_or_create(&metrics::DavOpLabels { op: "get" }).observe(start.elapsed().as_secs_f64());
    let body = Body::from_stream(resp.bytes_stream());
    (StatusCode::OK, hdrs, body).into_response()
}

#[derive(Debug, Serialize)]
struct OoCallbackResponse {
    error: i32,
}

async fn file_callback(
    State(state): State<AppState>,
    Path(token): Path<String>,
    Json(cb): Json<Callback>,
) -> Response {
    let (claims, session) = match file_jwt::verify(
        &token,
        Action::Write,
        &state.config.file_jwt_key,
        &state.config.session_key,
    ) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error=?e, "callback jwt verify failed");
            state.metrics.oo_callbacks.get_or_create(&metrics::CallbackLabels { result: "jwt_error" }).inc();
            return (StatusCode::FORBIDDEN, Json(OoCallbackResponse { error: 1 })).into_response();
        }
    };
    let session = maybe_refresh_session_bare(&state, session).await;
    use crate::onlyoffice::CallbackStatus::*;
    let status = cb.status_enum();
    tracing::info!(?status, path=%claims.path, "onlyoffice callback");
    match status {
        ReadyToSave | Forcesave => {
            let Some(url) = cb.url.as_deref() else {
                state.metrics.oo_callbacks.get_or_create(&metrics::CallbackLabels { result: "missing_url" }).inc();
                return Json(OoCallbackResponse { error: 1 }).into_response();
            };
            let http = reqwest::Client::new();
            let bytes = match http.get(url).send().await {
                Ok(r) if r.status().is_success() => match r.bytes().await {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::warn!(error=?e, "callback fetch body failed");
                        state.metrics.oo_callbacks.get_or_create(&metrics::CallbackLabels { result: "fetch_error" }).inc();
                        return Json(OoCallbackResponse { error: 1 }).into_response();
                    }
                },
                Ok(r) => {
                    tracing::warn!(status=%r.status(), "callback fetch returned non-2xx");
                    state.metrics.oo_callbacks.get_or_create(&metrics::CallbackLabels { result: "fetch_error" }).inc();
                    return Json(OoCallbackResponse { error: 1 }).into_response();
                }
                Err(e) => {
                    tracing::warn!(error=?e, "callback fetch failed");
                    state.metrics.oo_callbacks.get_or_create(&metrics::CallbackLabels { result: "fetch_error" }).inc();
                    return Json(OoCallbackResponse { error: 1 }).into_response();
                }
            };
            let client = match dav_client_for(&state, &session) {
                Ok(c) => c,
                Err(_) => {
                    state.metrics.oo_callbacks.get_or_create(&metrics::CallbackLabels { result: "dav_error" }).inc();
                    return Json(OoCallbackResponse { error: 1 }).into_response();
                }
            };
            if let Err(e) = client.put_bytes(&claims.path, bytes).await {
                tracing::warn!(error=?e, path=%claims.path, "callback dav put failed");
                state.metrics.oo_callbacks.get_or_create(&metrics::CallbackLabels { result: "dav_error" }).inc();
                return Json(OoCallbackResponse { error: 1 }).into_response();
            }
            state.metrics.oo_callbacks.get_or_create(&metrics::CallbackLabels { result: "saved" }).inc();
        }
        _ => {
            state.metrics.oo_callbacks.get_or_create(&metrics::CallbackLabels { result: "noop" }).inc();
        }
    }
    Json(OoCallbackResponse { error: 0 }).into_response()
}

// -- Helpers ------------------------------------------------------------------

fn load_session(state: &AppState, jar: &PrivateCookieJar) -> Option<Session> {
    let cookie = jar.get(COOKIE_NAME)?;
    Session::decrypt(cookie.value(), &state.config.session_key).ok()
}

/// If the access token is expired or within 60s of expiry, refresh it.
/// Returns (refreshed_session, updated_cookie_jar) on success.
async fn maybe_refresh_session(
    state: &AppState,
    session: Session,
    jar: PrivateCookieJar,
) -> (Session, PrivateCookieJar) {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if now < session.access_token_exp - 60 {
        return (session, jar);
    }
    let Some(ref rt) = session.refresh_token else {
        tracing::warn!(email=%session.email, "token near expiry but no refresh_token");
        return (session, jar);
    };
    state.metrics.session_refreshes.inc();
    match state.oidc.refresh(rt, &session.sub, &session.email, session.name.as_deref()).await {
        Ok(tokens) => {
            let refreshed = Session {
                sub: tokens.sub,
                email: tokens.email,
                name: tokens.name,
                access_token: tokens.access_token,
                refresh_token: tokens.refresh_token,
                access_token_exp: now + tokens.expires_in,
            };
            let jar = match refreshed.encrypt(&state.config.session_key) {
                Ok(v) => {
                    let cookie = Cookie::build((COOKIE_NAME, v))
                        .path("/")
                        .http_only(true)
                        .secure(true)
                        .same_site(SameSite::Lax)
                        .max_age(time::Duration::days(7))
                        .build();
                    jar.add(cookie)
                }
                Err(_) => jar,
            };
            tracing::debug!(email=%refreshed.email, "session refreshed");
            (refreshed, jar)
        }
        Err(e) => {
            tracing::warn!(error=?e, email=%session.email, "token refresh failed");
            (session, jar)
        }
    }
}

/// Refresh a session recovered from a file JWT (no cookie to update).
async fn maybe_refresh_session_bare(state: &AppState, session: Session) -> Session {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if now < session.access_token_exp - 60 {
        return session;
    }
    let Some(ref rt) = session.refresh_token else {
        return session;
    };
    state.metrics.session_refreshes.inc();
    match state.oidc.refresh(rt, &session.sub, &session.email, session.name.as_deref()).await {
        Ok(tokens) => Session {
            sub: tokens.sub,
            email: tokens.email,
            name: tokens.name,
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            access_token_exp: now + tokens.expires_in,
        },
        Err(e) => {
            tracing::warn!(error=?e, "file-jwt session refresh failed");
            session
        }
    }
}

fn dav_client_for(state: &AppState, session: &Session) -> Result<DavClient, Response> {
    let Some(domain) = session.email_domain() else {
        return Err((StatusCode::BAD_REQUEST, "session has no email domain").into_response());
    };
    let base = match state.config.dav_base_url(domain) {
        Ok(u) => u,
        Err(e) => {
            return Err(
                (StatusCode::INTERNAL_SERVER_ERROR, format!("bad dav base: {e}")).into_response(),
            );
        }
    };
    Ok(DavClient::new(
        base,
        &session.email,
        session.access_token.clone(),
    ))
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Convenience builder used by tests that bypass cookie key encoding.
#[allow(dead_code)]
pub fn _build_cookie_key(bytes: &[u8; 32]) -> Key {
    let mut padded = vec![0u8; 64];
    padded[..32].copy_from_slice(bytes);
    padded[32..].copy_from_slice(bytes);
    Key::from(&padded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_escape_handles_specials() {
        assert_eq!(
            html_escape(r#"a&b<c>d"e'f"#),
            "a&amp;b&lt;c&gt;d&quot;e&#39;f"
        );
    }

    #[test]
    fn callback_response_serializes() {
        let s = serde_json::to_string(&OoCallbackResponse { error: 0 }).unwrap();
        assert_eq!(s, r#"{"error":0}"#);
    }
}

