//! Storage. Postgres in production; an in-memory twin for tests. Only ciphertext is stored.
//! Every replace/delete keeps the previous ciphertext in `secret_history`, and reads of plain
//! values are written to `audit`.

use std::collections::BTreeMap;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;

use crate::crypto::Sealed;

#[derive(Clone, Debug)]
pub struct SecretRow {
    pub path: String,
    pub key: String,
    pub sealed: Sealed,
    pub version: i32,
    pub updated_at: DateTime<Utc>,
    pub updated_by: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct TokenRow {
    pub id: String,
    pub name: String,
    #[serde(skip)]
    pub hash: String,
    pub scope: String,
    pub can_write: bool,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AuditRow {
    pub at: DateTime<Utc>,
    pub actor: String,
    pub action: String,
    pub path: Option<String>,
    pub key: Option<String>,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PathInfo {
    pub path: String,
    pub keys: Vec<String>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize)]
pub struct HistoryRow {
    pub version: i32,
    pub action: String,
    pub changed_at: DateTime<Utc>,
    pub changed_by: String,
}

#[derive(Debug)]
pub struct StoreError(pub String);
impl From<sqlx::Error> for StoreError {
    fn from(e: sqlx::Error) -> Self {
        StoreError(e.to_string())
    }
}
type R<T> = Result<T, StoreError>;

#[derive(PartialEq, Debug)]
pub enum Put {
    Created,
    Updated,
}

#[derive(Default)]
pub struct Mem {
    secrets: BTreeMap<(String, String), SecretRow>,
    history: Vec<(String, String, HistoryRow)>,
    tokens: Vec<TokenRow>,
    audit: Vec<AuditRow>,
}

#[cfg_attr(not(test), allow(dead_code))]
pub enum Store {
    Pg(PgPool),
    Mem(Mutex<Mem>),
}

const SCHEMA: &str = r#"
create table if not exists secrets (
  path text not null, key text not null,
  iv bytea not null, data bytea not null,
  version int not null default 1,
  updated_at timestamptz not null default now(), updated_by text not null,
  primary key (path, key)
);
create table if not exists secret_history (
  id bigserial primary key, path text not null, key text not null,
  iv bytea, data bytea, version int not null,
  action text not null, changed_at timestamptz not null default now(), changed_by text not null
);
create index if not exists secret_history_lookup on secret_history (path, key, id desc);
create table if not exists tokens (
  id text primary key, name text not null unique, hash text not null,
  scope text not null, can_write boolean not null default false,
  created_at timestamptz not null default now(), created_by text not null,
  last_used_at timestamptz, revoked_at timestamptz
);
create table if not exists audit (
  id bigserial primary key, at timestamptz not null default now(),
  actor text not null, action text not null, path text, key text, detail text
);
create index if not exists audit_at on audit (at desc);
"#;

fn secret(r: &sqlx::postgres::PgRow) -> SecretRow {
    SecretRow {
        path: r.get("path"),
        key: r.get("key"),
        sealed: Sealed { iv: r.get("iv"), data: r.get("data") },
        version: r.get("version"),
        updated_at: r.get("updated_at"),
        updated_by: r.get("updated_by"),
    }
}

fn token(r: &sqlx::postgres::PgRow) -> TokenRow {
    TokenRow {
        id: r.get("id"),
        name: r.get("name"),
        hash: r.get("hash"),
        scope: r.get("scope"),
        can_write: r.get("can_write"),
        created_at: r.get("created_at"),
        created_by: r.get("created_by"),
        last_used_at: r.get("last_used_at"),
        revoked_at: r.get("revoked_at"),
    }
}

impl Store {
    pub async fn connect(url: &str) -> R<Self> {
        let pool = PgPoolOptions::new().max_connections(5).connect(url).await?;
        sqlx::raw_sql(SCHEMA).execute(&pool).await?;
        Ok(Store::Pg(pool))
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn memory() -> Self {
        Store::Mem(Mutex::new(Mem::default()))
    }

    pub async fn paths(&self) -> R<Vec<PathInfo>> {
        match self {
            Store::Pg(p) => Ok(sqlx::query("select path, array_agg(key order by key) as keys, max(updated_at) as updated_at from secrets group by path order by path")
                .fetch_all(p).await?
                .iter()
                .map(|r| PathInfo { path: r.get("path"), keys: r.get("keys"), updated_at: r.get("updated_at") })
                .collect()),
            Store::Mem(m) => {
                let m = m.lock().unwrap();
                let mut out: Vec<PathInfo> = Vec::new();
                for ((path, key), row) in &m.secrets {
                    match out.last_mut() {
                        Some(last) if &last.path == path => {
                            last.keys.push(key.clone());
                            last.updated_at = last.updated_at.max(row.updated_at);
                        }
                        _ => out.push(PathInfo { path: path.clone(), keys: vec![key.clone()], updated_at: row.updated_at }),
                    }
                }
                Ok(out)
            }
        }
    }

    pub async fn read(&self, path: &str) -> R<Vec<SecretRow>> {
        match self {
            Store::Pg(p) => Ok(sqlx::query("select * from secrets where path = $1 order by key").bind(path).fetch_all(p).await?.iter().map(secret).collect()),
            Store::Mem(m) => Ok(m.lock().unwrap().secrets.values().filter(|r| r.path == path).cloned().collect()),
        }
    }

    pub async fn read_one(&self, path: &str, key: &str) -> R<Option<SecretRow>> {
        match self {
            Store::Pg(p) => Ok(sqlx::query("select * from secrets where path = $1 and key = $2").bind(path).bind(key).fetch_optional(p).await?.as_ref().map(secret)),
            Store::Mem(m) => Ok(m.lock().unwrap().secrets.get(&(path.into(), key.into())).cloned()),
        }
    }

    pub async fn put(&self, path: &str, key: &str, s: &Sealed, actor: &str) -> R<Put> {
        match self {
            Store::Pg(p) => {
                let mut tx = p.begin().await?;
                let old = sqlx::query("select * from secrets where path = $1 and key = $2 for update").bind(path).bind(key).fetch_optional(&mut *tx).await?;
                let result = if let Some(old) = old.as_ref().map(secret) {
                    sqlx::query("insert into secret_history (path, key, iv, data, version, action, changed_by) values ($1,$2,$3,$4,$5,'replaced',$6)")
                        .bind(path).bind(key).bind(&old.sealed.iv).bind(&old.sealed.data).bind(old.version).bind(actor)
                        .execute(&mut *tx).await?;
                    sqlx::query("update secrets set iv = $3, data = $4, version = version + 1, updated_at = now(), updated_by = $5 where path = $1 and key = $2")
                        .bind(path).bind(key).bind(&s.iv).bind(&s.data).bind(actor)
                        .execute(&mut *tx).await?;
                    Put::Updated
                } else {
                    sqlx::query("insert into secrets (path, key, iv, data, updated_by) values ($1,$2,$3,$4,$5)")
                        .bind(path).bind(key).bind(&s.iv).bind(&s.data).bind(actor)
                        .execute(&mut *tx).await?;
                    Put::Created
                };
                tx.commit().await?;
                Ok(result)
            }
            Store::Mem(m) => {
                let mut m = m.lock().unwrap();
                let k = (path.to_string(), key.to_string());
                let now = Utc::now();
                if let Some(old) = m.secrets.get(&k).cloned() {
                    m.history.push((k.0.clone(), k.1.clone(), HistoryRow { version: old.version, action: "replaced".into(), changed_at: now, changed_by: actor.into() }));
                    m.secrets.insert(k, SecretRow { sealed: s.clone(), version: old.version + 1, updated_at: now, updated_by: actor.into(), ..old });
                    Ok(Put::Updated)
                } else {
                    m.secrets.insert(k, SecretRow { path: path.into(), key: key.into(), sealed: s.clone(), version: 1, updated_at: now, updated_by: actor.into() });
                    Ok(Put::Created)
                }
            }
        }
    }

    pub async fn remove(&self, path: &str, key: &str, actor: &str) -> R<bool> {
        match self {
            Store::Pg(p) => {
                let mut tx = p.begin().await?;
                let old = sqlx::query("delete from secrets where path = $1 and key = $2 returning *").bind(path).bind(key).fetch_optional(&mut *tx).await?;
                let Some(old) = old.as_ref().map(secret) else { return Ok(false) };
                sqlx::query("insert into secret_history (path, key, iv, data, version, action, changed_by) values ($1,$2,$3,$4,$5,'deleted',$6)")
                    .bind(path).bind(key).bind(&old.sealed.iv).bind(&old.sealed.data).bind(old.version).bind(actor)
                    .execute(&mut *tx).await?;
                tx.commit().await?;
                Ok(true)
            }
            Store::Mem(m) => {
                let mut m = m.lock().unwrap();
                match m.secrets.remove(&(path.into(), key.into())) {
                    Some(old) => {
                        m.history.push((path.into(), key.into(), HistoryRow { version: old.version, action: "deleted".into(), changed_at: Utc::now(), changed_by: actor.into() }));
                        Ok(true)
                    }
                    None => Ok(false),
                }
            }
        }
    }

    pub async fn history(&self, path: &str, key: &str) -> R<Vec<HistoryRow>> {
        match self {
            Store::Pg(p) => Ok(sqlx::query("select version, action, changed_at, changed_by from secret_history where path = $1 and key = $2 order by id desc limit 50")
                .bind(path).bind(key).fetch_all(p).await?
                .iter()
                .map(|r| HistoryRow { version: r.get("version"), action: r.get("action"), changed_at: r.get("changed_at"), changed_by: r.get("changed_by") })
                .collect()),
            Store::Mem(m) => Ok(m.lock().unwrap().history.iter().rev().filter(|(p, k, _)| p == path && k == key).map(|(_, _, h)| h.clone()).collect()),
        }
    }

    pub async fn tokens(&self) -> R<Vec<TokenRow>> {
        match self {
            Store::Pg(p) => Ok(sqlx::query("select * from tokens order by created_at desc").fetch_all(p).await?.iter().map(token).collect()),
            Store::Mem(m) => Ok(m.lock().unwrap().tokens.iter().rev().cloned().collect()),
        }
    }

    pub async fn token(&self, id: &str) -> R<Option<TokenRow>> {
        match self {
            Store::Pg(p) => Ok(sqlx::query("select * from tokens where id = $1").bind(id).fetch_optional(p).await?.as_ref().map(token)),
            Store::Mem(m) => Ok(m.lock().unwrap().tokens.iter().find(|t| t.id == id).cloned()),
        }
    }

    pub async fn add_token(&self, id: &str, name: &str, hash: &str, scope: &str, can_write: bool, by: &str) -> R<()> {
        match self {
            Store::Pg(p) => {
                sqlx::query("insert into tokens (id, name, hash, scope, can_write, created_by) values ($1,$2,$3,$4,$5,$6)")
                    .bind(id).bind(name).bind(hash).bind(scope).bind(can_write).bind(by)
                    .execute(p).await?;
                Ok(())
            }
            Store::Mem(m) => {
                let mut m = m.lock().unwrap();
                if m.tokens.iter().any(|t| t.name == name) {
                    return Err(StoreError("duplicate token name".into()));
                }
                m.tokens.push(TokenRow { id: id.into(), name: name.into(), hash: hash.into(), scope: scope.into(), can_write, created_at: Utc::now(), created_by: by.into(), last_used_at: None, revoked_at: None });
                Ok(())
            }
        }
    }

    pub async fn revoke_token(&self, id: &str) -> R<bool> {
        match self {
            Store::Pg(p) => Ok(sqlx::query("update tokens set revoked_at = now() where id = $1 and revoked_at is null").bind(id).execute(p).await?.rows_affected() > 0),
            Store::Mem(m) => {
                let mut m = m.lock().unwrap();
                match m.tokens.iter_mut().find(|t| t.id == id && t.revoked_at.is_none()) {
                    Some(t) => {
                        t.revoked_at = Some(Utc::now());
                        Ok(true)
                    }
                    None => Ok(false),
                }
            }
        }
    }

    pub async fn touch_token(&self, id: &str) -> R<()> {
        match self {
            Store::Pg(p) => {
                sqlx::query("update tokens set last_used_at = now() where id = $1").bind(id).execute(p).await?;
                Ok(())
            }
            Store::Mem(m) => {
                if let Some(t) = m.lock().unwrap().tokens.iter_mut().find(|t| t.id == id) {
                    t.last_used_at = Some(Utc::now());
                }
                Ok(())
            }
        }
    }

    pub async fn audit(&self, actor: &str, action: &str, path: Option<&str>, key: Option<&str>, detail: Option<&str>) -> R<()> {
        match self {
            Store::Pg(p) => {
                sqlx::query("insert into audit (actor, action, path, key, detail) values ($1,$2,$3,$4,$5)")
                    .bind(actor).bind(action).bind(path).bind(key).bind(detail)
                    .execute(p).await?;
                Ok(())
            }
            Store::Mem(m) => {
                m.lock().unwrap().audit.push(AuditRow { at: Utc::now(), actor: actor.into(), action: action.into(), path: path.map(Into::into), key: key.map(Into::into), detail: detail.map(Into::into) });
                Ok(())
            }
        }
    }

    pub async fn audit_log(&self, limit: i64) -> R<Vec<AuditRow>> {
        match self {
            Store::Pg(p) => Ok(sqlx::query("select at, actor, action, path, key, detail from audit order by id desc limit $1")
                .bind(limit).fetch_all(p).await?
                .iter()
                .map(|r| AuditRow { at: r.get("at"), actor: r.get("actor"), action: r.get("action"), path: r.get("path"), key: r.get("key"), detail: r.get("detail") })
                .collect()),
            Store::Mem(m) => Ok(m.lock().unwrap().audit.iter().rev().take(limit as usize).cloned().collect()),
        }
    }
}
