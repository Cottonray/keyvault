# keyvault

A small self-hosted store for `.env` secrets, written in Rust.

- **Encrypted at rest** — every value is sealed with AES-256-GCM under one 32-byte master key kept
  in a file, outside the database. The ciphertext is bound to its `path` and `key`, so rows cannot be
  swapped between entries. A database dump alone reveals nothing.
- **People sign in through your SSO reverse proxy** — keyvault has no passwords of its own. The proxy
  authenticates the user (for example oauth2-proxy in front of Keycloak) and passes the user name in a
  header. Every page and `/ui/api/*` call requires that header.
- **Machines use scoped bearer tokens** on `/v1/*` — read-only or read-write, limited to one path or a
  directory prefix. Only a SHA-256 of the token secret is stored; the token is shown once.
- **History and audit** — replaced and deleted values are kept (encrypted) as history; reveals,
  exports, reads and token changes are written to an audit log. Values never appear in the log.
- Postgres for storage. One static binary, distroless image, ~10 MB RAM.

## Paths

A path is the file's location inside its repository, e.g. `deploy/app/.env`. Store each `.env` file
under its own path and pull it back to the same place.

## Machine API

```sh
# read a file
curl -fsS -H "Authorization: Bearer $KEYVAULT_TOKEN" \
  "https://secrets.example.com/v1/env?path=deploy/app/.env" > deploy/app/.env

# write (merge); add &replace=1 to delete keys missing from the body
curl -fsS -X PUT -H "Authorization: Bearer $KEYVAULT_TOKEN" --data-binary @deploy/app/.env \
  "https://secrets.example.com/v1/env?path=deploy/app/.env"

# list paths and key names within the token's scope (no values)
curl -fsS -H "Authorization: Bearer $KEYVAULT_TOKEN" https://secrets.example.com/v1/paths
```

Token scope: `*` = everything, `deploy/` = everything below `deploy/`, `deploy/app/.env` = that path only.

## Running

```sh
docker build -t keyvault .
docker run --rm keyvault keygen > master.key && chmod 600 master.key
# fill .env with DB_PASSWORD and PUBLIC_ORIGIN, then
docker compose -f compose.example.yaml up -d
# first machine token (printed once)
docker compose -f compose.example.yaml exec keyvault keyvault token create my-laptop '*' --write
```

| Variable | Meaning |
|---|---|
| `DATABASE_URL` | Postgres URL. Tables are created on start. |
| `MASTER_KEY_FILE` | File with the master key: 32 raw bytes or 64 hex characters. |
| `PUBLIC_ORIGIN` | Origin of the UI, e.g. `https://secrets.example.com`. UI writes must carry this `Origin`. |
| `USER_HEADER` | Header your proxy sets with the signed-in user. Default `x-keyvault-user`. |
| `BIND` | Listen address. Default `0.0.0.0:8080`. |

### Reverse proxy contract

keyvault trusts `USER_HEADER`. Your proxy must:

1. require SSO on every path except `/v1/`, and set `USER_HEADER` from the authenticated identity;
2. pass `/v1/` without SSO and **remove** `USER_HEADER` there;
3. be the only thing that can reach keyvault's port.

nginx sketch (oauth2-proxy):

```nginx
location /v1/ {
    proxy_set_header X-Keyvault-User "";
    proxy_pass http://keyvault:8080;
}
location / {
    auth_request /oauth2/auth;
    auth_request_set $user $upstream_http_x_auth_request_preferred_username;
    proxy_set_header X-Keyvault-User $user;
    proxy_pass http://keyvault:8080;
}
```

## Backups

Back up **both** the Postgres database and the master key, separately. Without the master key the
database cannot be decrypted; without the database the key is useless. `keyvault fingerprint` prints a
short fingerprint so you can confirm a stored key copy matches the live one.

## Development

```sh
cargo test     # crypto, .env parsing, and HTTP flows against an in-memory store
```

## License

MIT
