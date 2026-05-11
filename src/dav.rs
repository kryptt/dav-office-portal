//! WebDAV client that authenticates with the user's Stalwart OIDC bearer token.
//!
//! Stalwart serves per-user collections at `/dav/file/<user@domain>/`. The
//! portal scopes every operation to the authenticated user's collection
//! — it never reaches outside it. Paths in the API are *relative* to the
//! user's collection root (e.g. `"reports/q4.docx"`, `""` for root).

use reqwest::Client;
use serde::{Deserialize, Serialize};
use url::Url;

pub struct DavClient {
    http: Client,
    base: Url,
    user_root: String,
    access_token: String,
}

impl DavClient {
    pub fn new(base: Url, email: &str, access_token: String) -> Self {
        let user_root = format!("/dav/file/{}/", email);
        Self {
            http: Client::new(),
            base,
            user_root,
            access_token,
        }
    }

    /// Build an absolute URL for a path relative to the user's collection.
    /// Empty `rel` means the collection root.
    pub fn url_for(&self, rel: &str) -> Result<Url, DavError> {
        let trimmed = rel.trim_start_matches('/');
        let full = format!("{}{}", self.user_root, trimmed);
        Ok(self.base.join(&full)?)
    }

    #[allow(dead_code)]
    pub fn user_root(&self) -> &str {
        &self.user_root
    }

    pub async fn list(&self, rel: &str) -> Result<Vec<DavEntry>, DavError> {
        let url = self.url_for(rel)?;
        let resp = self
            .http
            .request(reqwest::Method::from_bytes(b"PROPFIND").unwrap(), url.clone())
            .header("Depth", "1")
            .header("Authorization", format!("Bearer {}", self.access_token))
            .header("Content-Type", "application/xml; charset=utf-8")
            .body(PROPFIND_BODY)
            .send()
            .await?;
        let status = resp.status();
        let body = resp.text().await?;
        if status.as_u16() != 207 && !status.is_success() {
            return Err(DavError::Status(status.as_u16(), body));
        }
        parse_propfind(&body, &self.user_root)
    }

    pub async fn get(&self, rel: &str) -> Result<reqwest::Response, DavError> {
        let url = self.url_for(rel)?;
        let resp = self
            .http
            .get(url)
            .header("Authorization", format!("Bearer {}", self.access_token))
            .send()
            .await?;
        if !resp.status().is_success() {
            let s = resp.status().as_u16();
            let b = resp.text().await.unwrap_or_default();
            return Err(DavError::Status(s, b));
        }
        Ok(resp)
    }

    pub async fn put_bytes(&self, rel: &str, body: bytes::Bytes) -> Result<(), DavError> {
        let url = self.url_for(rel)?;
        let resp = self
            .http
            .put(url)
            .header("Authorization", format!("Bearer {}", self.access_token))
            .body(body)
            .send()
            .await?;
        let s = resp.status().as_u16();
        if !matches!(s, 200 | 201 | 204) {
            let b = resp.text().await.unwrap_or_default();
            return Err(DavError::Status(s, b));
        }
        Ok(())
    }

    pub async fn delete(&self, rel: &str) -> Result<(), DavError> {
        let url = self.url_for(rel)?;
        let resp = self
            .http
            .delete(url)
            .header("Authorization", format!("Bearer {}", self.access_token))
            .send()
            .await?;
        let s = resp.status().as_u16();
        if !matches!(s, 200 | 204) {
            let b = resp.text().await.unwrap_or_default();
            return Err(DavError::Status(s, b));
        }
        Ok(())
    }

    pub async fn mkcol(&self, rel: &str) -> Result<(), DavError> {
        let url = self.url_for(rel)?;
        let resp = self
            .http
            .request(reqwest::Method::from_bytes(b"MKCOL").unwrap(), url)
            .header("Authorization", format!("Bearer {}", self.access_token))
            .send()
            .await?;
        let s = resp.status().as_u16();
        if s != 201 {
            let b = resp.text().await.unwrap_or_default();
            return Err(DavError::Status(s, b));
        }
        Ok(())
    }

    pub async fn mv(&self, from_rel: &str, to_rel: &str) -> Result<(), DavError> {
        let from = self.url_for(from_rel)?;
        let to = self.url_for(to_rel)?;
        let resp = self
            .http
            .request(reqwest::Method::from_bytes(b"MOVE").unwrap(), from)
            .header("Authorization", format!("Bearer {}", self.access_token))
            .header("Destination", to.as_str())
            .header("Overwrite", "F")
            .send()
            .await?;
        let s = resp.status().as_u16();
        if !matches!(s, 201 | 204) {
            let b = resp.text().await.unwrap_or_default();
            return Err(DavError::Status(s, b));
        }
        Ok(())
    }
}

const PROPFIND_BODY: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:">
  <D:prop>
    <D:displayname/>
    <D:resourcetype/>
    <D:getcontentlength/>
    <D:getcontenttype/>
    <D:getlastmodified/>
  </D:prop>
</D:propfind>"#;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DavEntry {
    /// Path relative to the user's collection. `""` means the collection root.
    pub path: String,
    pub name: String,
    pub is_collection: bool,
    pub size: u64,
    pub content_type: Option<String>,
    pub last_modified: Option<String>,
}

fn parse_propfind(xml: &str, user_root: &str) -> Result<Vec<DavEntry>, DavError> {
    use quick_xml::Reader;
    use quick_xml::events::Event;

    let mut r = Reader::from_str(xml);
    r.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut entries: Vec<DavEntry> = Vec::new();
    let mut cur: Option<RawEntry> = None;
    let mut path = Vec::<String>::new();

    loop {
        match r.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let name = strip_ns(&e.name());
                path.push(name.clone());
                if name == "response" {
                    cur = Some(RawEntry::default());
                } else if name == "collection" {
                    if let Some(c) = cur.as_mut() {
                        c.is_collection = true;
                    }
                }
            }
            Ok(Event::Empty(e)) => {
                let name = strip_ns(&e.name());
                if name == "collection" {
                    if let Some(c) = cur.as_mut() {
                        c.is_collection = true;
                    }
                }
            }
            Ok(Event::Text(e)) => {
                let s = e.unescape().unwrap_or_default().to_string();
                if let (Some(c), Some(tag)) = (cur.as_mut(), path.last()) {
                    match tag.as_str() {
                        "href" => c.href = s,
                        "displayname" => c.displayname = Some(s),
                        "getcontentlength" => c.size = s.parse().unwrap_or(0),
                        "getcontenttype" => c.content_type = Some(s),
                        "getlastmodified" => c.last_modified = Some(s),
                        _ => {}
                    }
                }
            }
            Ok(Event::End(e)) => {
                let name = strip_ns(&e.name());
                path.pop();
                if name == "response" {
                    if let Some(c) = cur.take() {
                        if let Some(entry) = c.into_entry(user_root) {
                            entries.push(entry);
                        }
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(DavError::Xml(e.to_string())),
            _ => {}
        }
        buf.clear();
    }

    // The PROPFIND with Depth: 1 includes the parent collection itself
    // (with href == user_root). Filter it out so callers see only children.
    entries.retain(|e| !e.path.is_empty());
    Ok(entries)
}

#[derive(Default)]
struct RawEntry {
    href: String,
    displayname: Option<String>,
    is_collection: bool,
    size: u64,
    content_type: Option<String>,
    last_modified: Option<String>,
}

impl RawEntry {
    fn into_entry(self, user_root: &str) -> Option<DavEntry> {
        // href is URL-encoded; decode it (best effort, only for path chars).
        let href = url_decode(&self.href);
        let rel = href.strip_prefix(user_root)?;
        let rel = rel.trim_end_matches('/').to_string();
        let name = if rel.is_empty() {
            String::new()
        } else {
            rel.rsplit('/').next().unwrap_or(&rel).to_string()
        };
        Some(DavEntry {
            path: rel,
            name: self.displayname.unwrap_or(name),
            is_collection: self.is_collection,
            size: self.size,
            content_type: self.content_type,
            last_modified: self.last_modified,
        })
    }
}

fn strip_ns(name: &quick_xml::name::QName) -> String {
    let raw = String::from_utf8_lossy(name.as_ref()).into_owned();
    if let Some((_, after)) = raw.split_once(':') {
        after.to_string()
    } else {
        raw
    }
}

fn url_decode(s: &str) -> String {
    percent_decode(s.as_bytes()).into_owned()
}

fn percent_decode(input: &[u8]) -> std::borrow::Cow<'_, str> {
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%' && i + 2 < input.len() {
            if let (Some(h), Some(l)) = (
                (input[i + 1] as char).to_digit(16),
                (input[i + 2] as char).to_digit(16),
            ) {
                out.push(((h << 4) | l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(input[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned().into()
}

#[derive(Debug, thiserror::Error)]
pub enum DavError {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("url error: {0}")]
    Url(#[from] url::ParseError),
    #[error("dav status {0}: {1}")]
    Status(u16, String),
    #[error("xml parse error: {0}")]
    Xml(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_for_handles_root_and_subpath() {
        let c = DavClient::new(
            Url::parse("https://dav.fida.finance").unwrap(),
            "rhansen@fida.finance",
            "t".into(),
        );
        assert_eq!(
            c.url_for("").unwrap().as_str(),
            "https://dav.fida.finance/dav/file/rhansen@fida.finance/"
        );
        assert_eq!(
            c.url_for("docs/q4.docx").unwrap().as_str(),
            "https://dav.fida.finance/dav/file/rhansen@fida.finance/docs/q4.docx"
        );
        // Leading slash on rel is tolerated
        assert_eq!(
            c.url_for("/docs").unwrap().as_str(),
            "https://dav.fida.finance/dav/file/rhansen@fida.finance/docs"
        );
    }

    #[test]
    fn parse_propfind_recognizes_collection_and_file() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>/dav/file/rhansen@fida.finance/</D:href>
    <D:propstat><D:prop><D:resourcetype><D:collection/></D:resourcetype></D:prop></D:propstat>
  </D:response>
  <D:response>
    <D:href>/dav/file/rhansen@fida.finance/q4.docx</D:href>
    <D:propstat><D:prop>
      <D:displayname>q4.docx</D:displayname>
      <D:resourcetype/>
      <D:getcontentlength>1234</D:getcontentlength>
      <D:getcontenttype>application/vnd.openxmlformats-officedocument.wordprocessingml.document</D:getcontenttype>
      <D:getlastmodified>Mon, 11 May 2026 12:00:00 GMT</D:getlastmodified>
    </D:prop></D:propstat>
  </D:response>
  <D:response>
    <D:href>/dav/file/rhansen@fida.finance/reports/</D:href>
    <D:propstat><D:prop>
      <D:resourcetype><D:collection/></D:resourcetype>
    </D:prop></D:propstat>
  </D:response>
</D:multistatus>"#;
        let user_root = "/dav/file/rhansen@fida.finance/";
        let entries = parse_propfind(xml, user_root).unwrap();
        assert_eq!(entries.len(), 2);
        let doc = entries.iter().find(|e| e.path == "q4.docx").unwrap();
        assert!(!doc.is_collection);
        assert_eq!(doc.size, 1234);
        assert_eq!(doc.name, "q4.docx");
        let dir = entries.iter().find(|e| e.path == "reports").unwrap();
        assert!(dir.is_collection);
    }

    #[test]
    fn parse_propfind_decodes_percent_encoded_href() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>/dav/file/rhansen%40fida.finance/q4.docx</D:href>
    <D:propstat><D:prop>
      <D:displayname>q4.docx</D:displayname>
      <D:resourcetype/>
      <D:getcontentlength>10</D:getcontentlength>
    </D:prop></D:propstat>
  </D:response>
</D:multistatus>"#;
        let entries = parse_propfind(xml, "/dav/file/rhansen@fida.finance/").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "q4.docx");
    }
}
