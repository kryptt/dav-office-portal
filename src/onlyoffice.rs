//! Builds the OnlyOffice Document Server editor config and signs it with
//! the shared JWT secret. The browser loads this config into
//! `DocsAPI.DocEditor(elementId, config)`.

use jsonwebtoken::{EncodingKey, Header, encode};
use serde::Serialize;

#[derive(Debug, Clone, Copy)]
pub enum FileKind {
    Docx,
    Xlsx,
    Pptx,
    Other,
}

impl FileKind {
    pub fn from_path(path: &str) -> Self {
        let lower = path.to_ascii_lowercase();
        if lower.ends_with(".docx") || lower.ends_with(".doc") {
            Self::Docx
        } else if lower.ends_with(".xlsx") || lower.ends_with(".xls") {
            Self::Xlsx
        } else if lower.ends_with(".pptx") || lower.ends_with(".ppt") {
            Self::Pptx
        } else {
            Self::Other
        }
    }

    pub fn document_type(self) -> &'static str {
        match self {
            Self::Docx => "word",
            Self::Xlsx => "cell",
            Self::Pptx => "slide",
            Self::Other => "word",
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Self::Docx => "docx",
            Self::Xlsx => "xlsx",
            Self::Pptx => "pptx",
            Self::Other => "txt",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct EditorConfig {
    pub document: Document,
    #[serde(rename = "documentType")]
    pub document_type: &'static str,
    #[serde(rename = "editorConfig")]
    pub editor_config: InnerEditorConfig,
    pub width: &'static str,
    pub height: &'static str,
    pub token: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Document {
    #[serde(rename = "fileType")]
    pub file_type: &'static str,
    pub key: String,
    pub title: String,
    pub url: String,
    pub permissions: Permissions,
}

#[derive(Debug, Clone, Serialize)]
pub struct Permissions {
    pub edit: bool,
    pub download: bool,
    pub print: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct InnerEditorConfig {
    pub mode: &'static str,
    #[serde(rename = "callbackUrl")]
    pub callback_url: String,
    pub user: UserInfo,
    pub lang: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserInfo {
    pub id: String,
    pub name: String,
}

pub fn build_and_sign(
    title: &str,
    file_kind: FileKind,
    document_key: &str,
    file_url: &str,
    callback_url: &str,
    user_id: &str,
    user_name: &str,
    oo_jwt_secret: &[u8],
) -> Result<EditorConfig, jsonwebtoken::errors::Error> {
    // Build the unsigned config and sign the whole thing for the `token` field.
    // OnlyOffice's documented approach is to sign the entire payload object
    // and place the resulting JWT under `token`. DS server validates that
    // signature against its own shared secret.
    #[derive(Serialize)]
    struct Unsigned<'a> {
        document: &'a Document,
        #[serde(rename = "documentType")]
        document_type: &'a str,
        #[serde(rename = "editorConfig")]
        editor_config: &'a InnerEditorConfig,
    }

    let document = Document {
        file_type: file_kind.extension(),
        key: document_key.to_string(),
        title: title.to_string(),
        url: file_url.to_string(),
        permissions: Permissions {
            edit: true,
            download: true,
            print: true,
        },
    };
    let editor_config = InnerEditorConfig {
        mode: "edit",
        callback_url: callback_url.to_string(),
        user: UserInfo {
            id: user_id.to_string(),
            name: user_name.to_string(),
        },
        lang: "en",
    };

    let token = encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &Unsigned {
            document: &document,
            document_type: file_kind.document_type(),
            editor_config: &editor_config,
        },
        &EncodingKey::from_secret(oo_jwt_secret),
    )?;

    Ok(EditorConfig {
        document,
        document_type: file_kind.document_type(),
        editor_config,
        width: "100%",
        height: "100%",
        token,
    })
}

/// Status codes from OnlyOffice's callback API.
/// https://api.onlyoffice.com/editors/callback
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallbackStatus {
    /// 0 — no document with the key id can be found (we never expect this).
    NotFound,
    /// 1 — document is being edited.
    Editing,
    /// 2 — document is ready to be saved (download from `url` and persist).
    ReadyToSave,
    /// 3 — error saving (must NOT save).
    SaveError,
    /// 4 — document is closed with no changes.
    ClosedNoChanges,
    /// 6 — document is being edited, but the current state is saved.
    Forcesave,
    /// 7 — error forcesaving.
    ForcesaveError,
    Other(i64),
}

impl From<i64> for CallbackStatus {
    fn from(n: i64) -> Self {
        match n {
            0 => Self::NotFound,
            1 => Self::Editing,
            2 => Self::ReadyToSave,
            3 => Self::SaveError,
            4 => Self::ClosedNoChanges,
            6 => Self::Forcesave,
            7 => Self::ForcesaveError,
            x => Self::Other(x),
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Callback {
    pub status: i64,
    #[serde(default)]
    pub url: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    pub key: Option<String>,
}

impl Callback {
    pub fn status_enum(&self) -> CallbackStatus {
        CallbackStatus::from(self.status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_kind_from_path() {
        assert!(matches!(FileKind::from_path("foo.docx"), FileKind::Docx));
        assert!(matches!(FileKind::from_path("/a/b.xlsx"), FileKind::Xlsx));
        assert!(matches!(FileKind::from_path("DECK.PPTX"), FileKind::Pptx));
        assert!(matches!(FileKind::from_path("readme.md"), FileKind::Other));
    }

    #[test]
    fn build_and_sign_yields_valid_jwt() {
        let secret = b"shared-secret-1234";
        let cfg = build_and_sign(
            "q4.docx",
            FileKind::Docx,
            "doc-key-abc",
            "https://office.example/api/file/JWT",
            "https://office.example/api/callback/JWT",
            "user-1",
            "Test User",
            secret,
        )
        .unwrap();
        assert_eq!(cfg.document.title, "q4.docx");
        assert_eq!(cfg.document_type, "word");
        // token decodes with the same secret
        use jsonwebtoken::{DecodingKey, Validation, decode};
        let mut v = Validation::new(jsonwebtoken::Algorithm::HS256);
        v.required_spec_claims.clear();
        v.validate_exp = false;
        let _ = decode::<serde_json::Value>(&cfg.token, &DecodingKey::from_secret(secret), &v)
            .unwrap();
    }

    #[test]
    fn callback_status_mapping() {
        assert_eq!(CallbackStatus::from(2), CallbackStatus::ReadyToSave);
        assert_eq!(CallbackStatus::from(6), CallbackStatus::Forcesave);
        assert_eq!(CallbackStatus::from(99), CallbackStatus::Other(99));
    }
}
