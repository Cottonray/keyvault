//! End-to-end HTTP tests against the in-memory store.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use crate::app::{router, App};
use crate::store::Store;

const ORIGIN: &str = "https://vault.test";

fn app() -> Arc<App> {
    Arc::new(App { store: Store::memory(), master: [3u8; 32], origin: ORIGIN.into(), user_header: "x-keyvault-user".into() })
}

async fn call(app: &Arc<App>, req: Request<Body>) -> (StatusCode, String) {
    let res = router(app.clone()).oneshot(req).await.unwrap();
    let status = res.status();
    let body = res.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

fn ui(method: &str, uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("x-keyvault-user", "alice")
        .header("x-keyvault-request", "1")
        .header("origin", ORIGIN)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn machine(method: &str, uri: &str, token: &str, body: &str) -> Request<Body> {
    Request::builder().method(method).uri(uri).header("authorization", format!("Bearer {token}")).body(Body::from(body.to_string())).unwrap()
}

#[tokio::test]
async fn people_need_the_proxy_header() {
    let a = app();
    let (s, _) = call(&a, Request::get("/ui/api/paths").body(Body::empty()).unwrap()).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = call(&a, Request::get("/").header("x-keyvault-user", "alice").body(Body::empty()).unwrap()).await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn ui_writes_need_origin_and_custom_header() {
    let a = app();
    let mut req = ui("PUT", "/ui/api/secret", json!({ "path": "a/.env", "key": "K", "value": "v" }));
    req.headers_mut().remove("x-keyvault-request");
    assert_eq!(call(&a, req).await.0, StatusCode::FORBIDDEN);
    let mut req = ui("PUT", "/ui/api/secret", json!({ "path": "a/.env", "key": "K", "value": "v" }));
    req.headers_mut().insert("origin", "https://evil.test".parse().unwrap());
    assert_eq!(call(&a, req).await.0, StatusCode::FORBIDDEN);
    assert_eq!(call(&a, ui("PUT", "/ui/api/secret", json!({ "path": "a/.env", "key": "K", "value": "v" }))).await.0, StatusCode::OK);
}

#[tokio::test]
async fn full_flow_with_scoped_tokens() {
    let a = app();
    let (s, body) = call(&a, ui("POST", "/ui/api/import", json!({ "path": "deploy/x/.env", "text": "A=1\nB=\"two words\"\n" }))).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["created"], 2);

    // values never appear in listings
    let (_, list) = call(&a, ui("GET", "/ui/api/secrets?path=deploy/x/.env", Value::Null)).await;
    assert!(!list.contains("two words"));
    let (_, revealed) = call(&a, ui("POST", "/ui/api/reveal", json!({ "path": "deploy/x/.env", "key": "B" }))).await;
    assert_eq!(serde_json::from_str::<Value>(&revealed).unwrap()["value"], "two words");

    let (_, t) = call(&a, ui("POST", "/ui/api/tokens", json!({ "name": "ro", "scope": "deploy/", "can_write": false }))).await;
    let ro = serde_json::from_str::<Value>(&t).unwrap()["token"].as_str().unwrap().to_string();
    let (_, t) = call(&a, ui("POST", "/ui/api/tokens", json!({ "name": "rw", "scope": "other/.env", "can_write": true }))).await;
    let rw = serde_json::from_str::<Value>(&t).unwrap()["token"].as_str().unwrap().to_string();

    let (s, env) = call(&a, machine("GET", "/v1/env?path=deploy%2Fx%2F.env", &ro, "")).await;
    assert_eq!(s, StatusCode::OK);
    assert!(env.contains("A=1") && env.contains("B=\"two words\""));
    assert_eq!(call(&a, machine("PUT", "/v1/env?path=deploy/x/.env", &ro, "A=2")).await.0, StatusCode::FORBIDDEN, "read-only");
    assert_eq!(call(&a, machine("GET", "/v1/env?path=deploy/x/.env", &rw, "")).await.0, StatusCode::FORBIDDEN, "out of scope");

    let (s, r) = call(&a, machine("PUT", "/v1/env?path=other/.env", &rw, "X=1\n")).await;
    assert_eq!(s, StatusCode::OK, "{r}");
    let (_, r) = call(&a, machine("PUT", "/v1/env?path=other/.env&replace=1", &rw, "X=1\nY=2\n")).await;
    let r: Value = serde_json::from_str(&r).unwrap();
    assert_eq!((r["created"].as_i64(), r["unchanged"].as_i64()), (Some(1), Some(1)));

    // tokens cannot reach the UI, and the user header does nothing on /v1
    assert_eq!(call(&a, machine("GET", "/ui/api/paths", &rw, "")).await.0, StatusCode::UNAUTHORIZED);
    let req = Request::get("/v1/paths").header("x-keyvault-user", "alice").body(Body::empty()).unwrap();
    assert_eq!(call(&a, req).await.0, StatusCode::UNAUTHORIZED);

    // revoke
    let (_, toks) = call(&a, ui("GET", "/ui/api/tokens", Value::Null)).await;
    assert!(!toks.contains("hash"), "hash must not leak");
    let id = &ro[3..15];
    assert_eq!(call(&a, ui("DELETE", &format!("/ui/api/tokens/{id}"), json!({}))).await.0, StatusCode::OK);
    assert_eq!(call(&a, machine("GET", "/v1/env?path=deploy/x/.env", &ro, "")).await.0, StatusCode::UNAUTHORIZED);

    // audit records reads and reveals, never values
    let (_, audit) = call(&a, ui("GET", "/ui/api/audit", Value::Null)).await;
    assert!(audit.contains("\"reveal\"") && audit.contains("\"read\"") && !audit.contains("two words"));
}

#[tokio::test]
async fn bad_input_is_rejected() {
    let a = app();
    assert_eq!(call(&a, ui("PUT", "/ui/api/secret", json!({ "path": "../x", "key": "K", "value": "v" }))).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(call(&a, ui("PUT", "/ui/api/secret", json!({ "path": "a/.env", "key": "1K", "value": "v" }))).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(call(&a, machine("GET", "/v1/paths", "kv_nope", "")).await.0, StatusCode::UNAUTHORIZED);
}
