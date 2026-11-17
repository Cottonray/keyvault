//! keyvault — a small self-hosted store for `.env` secrets.
//!
//! ```text
//! keyvault serve                              # HTTP server (default)
//! keyvault token create NAME SCOPE [--write]  # print a new machine token once
//! keyvault fingerprint                        # fingerprint of the master key
//! keyvault keygen                             # print a fresh 64-hex master key
//! ```
//!
//! Configuration (environment):
//! * `DATABASE_URL`     Postgres URL (required except for `keygen`)
//! * `MASTER_KEY_FILE`  file holding the 32-byte master key (raw or hex) — required
//! * `PUBLIC_ORIGIN`    public origin of the UI, e.g. `https://secrets.example.com` — required for `serve`
//! * `USER_HEADER`      header the SSO proxy sets with the signed-in user (default `x-keyvault-user`)
//! * `BIND`             listen address (default `0.0.0.0:8080`)

mod app;
mod crypto;
mod envfile;
mod store;

#[cfg(test)]
mod tests;

use std::sync::Arc;

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| fail(&format!("{name} is not set")))
}

fn fail(msg: &str) -> ! {
    eprintln!("keyvault: {msg}");
    std::process::exit(1)
}

fn master() -> crypto::MasterKey {
    let path = env("MASTER_KEY_FILE");
    let raw = std::fs::read(&path).unwrap_or_else(|e| fail(&format!("cannot read {path}: {e}")));
    crypto::load_master_key(&raw).unwrap_or_else(|e| fail(&e))
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["keygen"] => println!("{}", crypto::random_master_key_hex()),
        ["fingerprint"] => println!("{}", crypto::fingerprint(&master())),
        ["token", "create", name, scope, rest @ ..] => {
            let app = app_from_env(false).await;
            match app.create_token(name, scope, rest.contains(&"--write"), "cli").await {
                Ok(t) => println!("{t}"),
                Err(_) => fail("could not create token (bad name/scope or duplicate name)"),
            }
        }
        ["health"] => health().await,
        [] | ["serve"] => serve().await,
        _ => fail("usage: keyvault [serve | token create NAME SCOPE [--write] | fingerprint | keygen | health]"),
    }
}

async fn app_from_env(need_origin: bool) -> app::App {
    let master = master();
    let store = store::Store::connect(&env("DATABASE_URL")).await.unwrap_or_else(|e| fail(&format!("database: {}", e.0)));
    app::App {
        store,
        master,
        origin: if need_origin { env("PUBLIC_ORIGIN").trim_end_matches('/').to_string() } else { String::new() },
        user_header: std::env::var("USER_HEADER").unwrap_or_else(|_| "x-keyvault-user".into()).to_ascii_lowercase(),
    }
}

/// Container health check without curl: plain HTTP/1.0 to the local listener.
async fn health() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let port = std::env::var("BIND").ok().and_then(|b| b.rsplit(':').next().map(str::to_string)).unwrap_or_else(|| "8080".into());
    let run = async {
        let mut s = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}")).await.ok()?;
        s.write_all(b"GET /healthz HTTP/1.0\r\n\r\n").await.ok()?;
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.ok()?;
        (buf.starts_with(b"HTTP/1.") && buf.get(9..12) == Some(b"200".as_slice())).then_some(())
    };
    match tokio::time::timeout(std::time::Duration::from_secs(3), run).await {
        Ok(Some(())) => {}
        _ => fail("unhealthy"),
    }
}

async fn serve() {
    let app = Arc::new(app_from_env(true).await);
    eprintln!("keyvault: master key {}", crypto::fingerprint(&app.master));
    let bind = std::env::var("BIND").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let listener = tokio::net::TcpListener::bind(&bind).await.unwrap_or_else(|e| fail(&format!("bind {bind}: {e}")));
    eprintln!("keyvault: listening on {bind}");
    axum::serve(listener, app::router(app))
        .with_graceful_shutdown(async {
            // `docker stop` sends SIGTERM; Ctrl+C sends SIGINT.
            let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("signal handler");
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
        })
        .await
        .unwrap_or_else(|e| fail(&e.to_string()));
}
