//! HTTP. Two entrances that never mix:
//!
//! * `/v1/*` — machines. Only `Authorization: Bearer kv_…` is looked at; the user header is ignored.
//!   The reverse proxy passes this prefix without SSO and must strip the user header.
//! * everything else — people. Only the user header set by the SSO reverse proxy is looked at;
//!   tokens are not accepted. State-changing calls also require the exact `Origin` and the custom
//!   header `X-Keyvault-Request: 1`, which cross-site forms cannot send.
//!
//! The server trusts the user header, so it must only be reachable through that proxy.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use serde_json::{json, Value};

use crate::crypto::{hash_secret, new_token, open, parse_token, same_hash, seal, MasterKey};
use crate::envfile::{format_env, in_scope, normalize_path, parse_env, valid_key};
use crate::store::{Put, Store, StoreError};

pub struct App {
    pub store: Store,
    pub master: MasterKey,
    /// e.g. `https://secrets.example.com` — checked against `Origin` on UI writes.
    pub origin: String,
    /// Header carrying the signed-in user, set by the SSO proxy (lower-case).
    pub user_header: String,
}

const UI: &str = include_str!("ui.html");
const MAX_BODY: usize = 256 * 1024;

pub struct HttpError(StatusCode, String);
type Res<T> = Result<T, HttpError>;

fn err(code: StatusCode, msg: impl Into<String>) -> HttpError {
    HttpError(code, msg.into())
}
impl From<StoreError> for HttpError {
    fn from(e: StoreError) -> Self {
        eprintln!("store error: {}", e.0);
        err(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
    }
}
impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        (self.0, axum::Json(json!({ "error": self.1 }))).into_response()
    }
}

fn path_of(v: Option<&str>) -> Res<String> {
    normalize_path(v.unwrap_or("")).map_err(|e| err(StatusCode::BAD_REQUEST, e))
}
fn key_of(v: Option<&str>) -> Res<String> {
    let k = v.unwrap_or("");
    if valid_key(k) { Ok(k.to_string()) } else { Err(err(StatusCode::BAD_REQUEST, format!("invalid key name: {k}"))) }
}
fn query(uri: &axum::http::Uri, name: &str) -> Option<String> {
    uri.query()?.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        (k == name).then(|| percent_decode(v))
    })
}
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => match std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) {
                Some(v) => {
                    out.push(v);
                    i += 2;
                }
                None => out.push(b'%'),
            },
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn text(body: String) -> Response {
    ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], body).into_response()
}
fn ok(v: Value) -> Response {
    axum::Json(v).into_response()
}

impl App {
    async fn reveal(&self, path: &str) -> Res<Vec<(String, String)>> {
        let rows = self.store.read(path).await?;
        rows.iter()
            .map(|r| open(&self.master, &r.path, &r.key, &r.sealed).map(|v| (r.key.clone(), v)).map_err(|e| {
                eprintln!("{e}");
                err(StatusCode::INTERNAL_SERVER_ERROR, "cannot decrypt stored value")
            }))
            .collect()
    }

    /// Applies `.env` text to a path. Identical values are left alone (no new version);
    /// with `replace`, keys absent from the text are deleted.
    async fn apply(&self, path: &str, text: &str, replace: bool, actor: &str) -> Res<Value> {
        let incoming = parse_env(text);
        let current: std::collections::HashMap<String, String> = self.reveal(path).await?.into_iter().collect();
        let (mut created, mut updated, mut unchanged, mut removed) = (0, 0, 0, 0);
        for (k, v) in &incoming {
            if current.get(k) == Some(v) {
                unchanged += 1;
                continue;
            }
            match self.store.put(path, k, &seal(&self.master, path, k, v), actor).await? {
                Put::Created => created += 1,
                Put::Updated => updated += 1,
            }
        }
        if replace {
            for k in current.keys() {
                if !incoming.iter().any(|(ik, _)| ik == k) && self.store.remove(path, k, actor).await? {
                    removed += 1;
                }
            }
        }
        let result = json!({ "created": created, "updated": updated, "unchanged": unchanged, "removed": removed });
        self.store.audit(actor, "import", Some(path), None, Some(&result.to_string())).await?;
        Ok(result)
    }

    async fn machine(&self, method: &Method, uri: &axum::http::Uri, headers: &HeaderMap, body: Body) -> Res<Response> {
        let bearer = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")).unwrap_or("");
        let unauthorized = || err(StatusCode::UNAUTHORIZED, "missing or invalid token");
        let (id, secret) = parse_token(bearer.trim()).ok_or_else(unauthorized)?;
        let tok = self.store.token(&id).await?.ok_or_else(unauthorized)?;
        if tok.revoked_at.is_some() || !same_hash(&tok.hash, &hash_secret(&secret)) {
            return Err(unauthorized());
        }
        self.store.touch_token(&tok.id).await?;
        let actor = format!("token:{}", tok.name);
        let need = |path: &str, write: bool| -> Res<()> {
            if !in_scope(&tok.scope, path) {
                return Err(err(StatusCode::FORBIDDEN, format!("outside this token's scope ({})", tok.scope)));
            }
            if write && !tok.can_write {
                return Err(err(StatusCode::FORBIDDEN, "read-only token"));
            }
            Ok(())
        };

        match (method, uri.path()) {
            (&Method::GET, "/v1/paths") => {
                let list: Vec<Value> = self.store.paths().await?.into_iter().filter(|p| in_scope(&tok.scope, &p.path)).map(|p| json!({ "path": p.path, "keys": p.keys })).collect();
                Ok(ok(Value::Array(list)))
            }
            (&Method::GET, "/v1/env") => {
                let path = path_of(query(uri, "path").as_deref())?;
                need(&path, false)?;
                let pairs = self.reveal(&path).await?;
                if pairs.is_empty() {
                    return Err(err(StatusCode::NOT_FOUND, format!("{path} is not in the vault")));
                }
                self.store.audit(&actor, "read", Some(&path), None, None).await?;
                Ok(text(format_env(&pairs, Some(&format!("keyvault {path}")))))
            }
            (&Method::PUT, "/v1/env") => {
                let path = path_of(query(uri, "path").as_deref())?;
                need(&path, true)?;
                let raw = to_bytes(body, MAX_BODY).await.map_err(|_| err(StatusCode::PAYLOAD_TOO_LARGE, "body too large"))?;
                let replace = query(uri, "replace").as_deref() == Some("1");
                Ok(ok(self.apply(&path, &String::from_utf8_lossy(&raw), replace, &actor).await?))
            }
            _ => Err(err(StatusCode::NOT_FOUND, "not found")),
        }
    }

    async fn human(&self, method: &Method, uri: &axum::http::Uri, headers: &HeaderMap, body: Body, user: &str) -> Res<Response> {
        if method != Method::GET {
            let from_ui = headers.get("x-keyvault-request").map(|v| v == "1").unwrap_or(false);
            let origin_ok = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) == Some(self.origin.as_str());
            if !from_ui || !origin_ok {
                return Err(err(StatusCode::FORBIDDEN, "request did not come from the vault page"));
            }
        }
        let route = uri.path();
        if method == Method::GET && (route == "/" || route == "/index.html") {
            let mut res = ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], UI).into_response();
            res.headers_mut().insert(
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static("default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; form-action 'none'"),
            );
            return Ok(res);
        }
        let Some(r) = route.strip_prefix("/ui/api") else { return Err(err(StatusCode::NOT_FOUND, "not found")) };
        let body: Value = if method == Method::GET {
            Value::Null
        } else {
            let raw = to_bytes(body, MAX_BODY).await.map_err(|_| err(StatusCode::PAYLOAD_TOO_LARGE, "body too large"))?;
            if raw.is_empty() { json!({}) } else { serde_json::from_slice(&raw).map_err(|_| err(StatusCode::BAD_REQUEST, "body is not JSON"))? }
        };
        let s = |k: &str| body.get(k).and_then(Value::as_str).map(str::to_string);

        match (method, r) {
            (&Method::GET, "/me") => Ok(ok(json!({ "user": user }))),
            (&Method::GET, "/paths") => Ok(ok(serde_json::to_value(self.store.paths().await?).unwrap())),
            (&Method::GET, "/secrets") => {
                let path = path_of(query(uri, "path").as_deref())?;
                let rows: Vec<Value> = self.store.read(&path).await?.into_iter().map(|r| json!({ "key": r.key, "version": r.version, "updated_at": r.updated_at, "updated_by": r.updated_by })).collect();
                Ok(ok(Value::Array(rows)))
            }
            (&Method::POST, "/reveal") => {
                let (path, key) = (path_of(s("path").as_deref())?, key_of(s("key").as_deref())?);
                let row = self.store.read_one(&path, &key).await?.ok_or_else(|| err(StatusCode::NOT_FOUND, "no such key"))?;
                let value = open(&self.master, &path, &key, &row.sealed).map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "cannot decrypt stored value"))?;
                self.store.audit(user, "reveal", Some(&path), Some(&key), None).await?;
                Ok(ok(json!({ "value": value })))
            }
            (&Method::PUT, "/secret") => {
                let (path, key) = (path_of(s("path").as_deref())?, key_of(s("key").as_deref())?);
                let value = s("value").ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing value"))?;
                let r = self.store.put(&path, &key, &seal(&self.master, &path, &key, &value), user).await?;
                let action = if r == Put::Created { "create" } else { "update" };
                self.store.audit(user, action, Some(&path), Some(&key), None).await?;
                Ok(ok(json!({ "result": action })))
            }
            (&Method::DELETE, "/secret") => {
                let (path, key) = (path_of(s("path").as_deref())?, key_of(s("key").as_deref())?);
                if !self.store.remove(&path, &key, user).await? {
                    return Err(err(StatusCode::NOT_FOUND, "no such key"));
                }
                self.store.audit(user, "delete", Some(&path), Some(&key), None).await?;
                Ok(ok(json!({ "ok": true })))
            }
            (&Method::POST, "/import") => {
                let path = path_of(s("path").as_deref())?;
                let replace = body.get("replace").and_then(Value::as_bool).unwrap_or(false);
                Ok(ok(self.apply(&path, &s("text").unwrap_or_default(), replace, user).await?))
            }
            (&Method::GET, "/export") => {
                let path = path_of(query(uri, "path").as_deref())?;
                self.store.audit(user, "export", Some(&path), None, None).await?;
                Ok(text(format_env(&self.reveal(&path).await?, Some(&format!("keyvault {path}")))))
            }
            (&Method::GET, "/history") => {
                let (path, key) = (path_of(query(uri, "path").as_deref())?, key_of(query(uri, "key").as_deref())?);
                Ok(ok(serde_json::to_value(self.store.history(&path, &key).await?).unwrap()))
            }
            (&Method::GET, "/tokens") => Ok(ok(serde_json::to_value(self.store.tokens().await?).unwrap())),
            (&Method::POST, "/tokens") => {
                let name = s("name").unwrap_or_default().trim().to_string();
                let scope = s("scope").unwrap_or_default();
                let can_write = body.get("can_write").and_then(Value::as_bool).unwrap_or(false);
                let token = self.create_token(&name, &scope, can_write, user).await?;
                Ok(ok(json!({ "token": token })))
            }
            (&Method::GET, "/audit") => Ok(ok(serde_json::to_value(self.store.audit_log(200).await?).unwrap())),
            (&Method::DELETE, r) if r.starts_with("/tokens/") => {
                let id = &r["/tokens/".len()..];
                if !self.store.revoke_token(id).await? {
                    return Err(err(StatusCode::NOT_FOUND, "no such active token"));
                }
                self.store.audit(user, "token-revoke", None, None, Some(id)).await?;
                Ok(ok(json!({ "ok": true })))
            }
            _ => Err(err(StatusCode::NOT_FOUND, "not found")),
        }
    }

    /// Shared by the UI and the `token create` command. Returns the full token (shown once).
    pub async fn create_token(&self, name: &str, scope: &str, can_write: bool, by: &str) -> Res<String> {
        if !(2..=40).contains(&name.len()) || !name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')) {
            return Err(err(StatusCode::BAD_REQUEST, "token name: 2-40 chars of A-Z a-z 0-9 . _ -"));
        }
        let scope = if scope == "*" {
            "*".to_string()
        } else if scope.ends_with('/') {
            format!("{}/", path_of(Some(scope))?)
        } else {
            path_of(Some(scope))?
        };
        if self.store.tokens().await?.iter().any(|t| t.name == name) {
            return Err(err(StatusCode::CONFLICT, "a token with this name exists"));
        }
        let t = new_token();
        self.store.add_token(&t.id, name, &t.hash, &scope, can_write, by).await?;
        let detail = format!("{name} {scope} {}", if can_write { "rw" } else { "r" });
        self.store.audit(by, "token-create", None, None, Some(&detail)).await?;
        Ok(t.token)
    }
}

async fn handle(State(app): State<Arc<App>>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let path = parts.uri.path().to_string();
    let result = if path == "/healthz" {
        Ok(ok(json!({ "ok": true })))
    } else if path.starts_with("/v1/") {
        app.machine(&parts.method, &parts.uri, &parts.headers, body).await
    } else {
        let user = parts.headers.get(app.user_header.as_str()).and_then(|v| v.to_str().ok()).map(str::trim).unwrap_or("");
        if user.is_empty() {
            Err(err(StatusCode::UNAUTHORIZED, "not signed in (no user header from the SSO proxy)"))
        } else {
            app.human(&parts.method, &parts.uri, &parts.headers, body, user).await
        }
    };
    let mut res = result.unwrap_or_else(IntoResponse::into_response);
    let h = res.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    res
}

pub fn router(app: Arc<App>) -> Router {
    Router::new().fallback(handle).with_state(app)
}
