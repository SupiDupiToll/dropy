# dropy

Self-hosted static HTML hosting with a small admin UI, versioning, access control, and an API.

Upload an HTML file or paste markup, choose a path, and publish it at `https://pages.example.com/<path>/`. Protect pages with a PIN, a password, or Pocket-ID. The admin interface lives on a separate hostname.

Built with Go, `net/http`, `html/template`, and SQLite. No Node.js, no database server, no external frontend build step.

## Features

- **Upload or paste HTML** — single `index.html` or optional ZIP bundles.
- **Path-based hosting** — `https://pages.example.com/demo/`, `.../reports/2026/`. No wildcard DNS or per-page subdomains.
- **Per-page access control** — public, PIN, password, or Pocket-ID.
- **Pocket-ID / OIDC login** — separate clients for the admin UI and protected pages.
- **Versions and rollback** — every deploy creates a version; download or restore older ones.
- **Expiring share links** — temporary access with optional usage limits, revocable at any time.
- **API tokens and CLI** — deploy from scripts or CI with `dropy deploy`.
- **Single binary** — embedded templates and static assets; SQLite in pure Go.
- **Small footprint** — typically ~20–40 MB RSS in normal use.

## How it works

```
Internet
  └── TLS-terminating reverse proxy (Caddy, nginx, Cloudflare Tunnel, …)
        ├── admin.example.com  → 127.0.0.1:8080  (admin UI)
        └── pages.example.com  → 127.0.0.1:8080  (published pages)
```

dropy binds to loopback by default. Your reverse proxy terminates TLS and forwards requests while preserving the original `Host` header.

Metadata is stored in SQLite. Published files are stored under:

```
/var/lib/dropy/
├── dropy.db
└── versions/<version-id>/
```

Admin and page cookies are host-only and use separate OIDC clients.

> **Path mode only.** This project intentionally does not create subdomains per page. Both hostnames route to the same process; the `Host` header decides whether a request is handled by the admin app or the page server.

## Requirements

- Go 1.26 or newer to build
- Linux with systemd for the recommended deployment
- A TLS-terminating reverse proxy or tunnel
- Optional: [Pocket-ID](https://pocket-id.org/) for authentication

## Quick start

```bash
git clone https://github.com/SupiDupiToll/dropy.git
cd dropy
make build
```

For a complete production walkthrough with systemd, reverse proxy, and Pocket-ID, see [SETUP.md](SETUP.md).

For local development without Pocket-ID:

```bash
make run
```

Open `http://localhost:8080` and use the development login. Pages can be previewed locally at `http://localhost:8080/__pages/<path>/`. This dev alias is only available when `DROPY_DEV=true`.

## Pocket-ID setup

Create **two OIDC applications** in Pocket-ID. Using two clients keeps admin access and page access independent.

### Admin application

| Field | Value |
|---|---|
| Name | `dropy admin` |
| Callback URL | `https://admin.example.com/auth/callback` |
| Scopes | `openid profile email` (add `groups` if you use group allowlists) |
| Allowed users/groups | your admin account or admin group |

Set:

```env
DROPY_ADMIN_OIDC_ISSUER=https://id.example.com
DROPY_ADMIN_OIDC_CLIENT_ID=...
DROPY_ADMIN_OIDC_CLIENT_SECRET=...
DROPY_ADMIN_OIDC_REDIRECT_URL=https://admin.example.com/auth/callback
```

### Pages application

| Field | Value |
|---|---|
| Name | `dropy pages` |
| Callback URL | `https://pages.example.com/__auth/callback` |
| Scopes | `openid profile email` (add `groups` if needed) |
| Allowed users/groups | everyone who may open Pocket-ID protected pages |

Set:

```env
DROPY_PAGES_OIDC_ISSUER=https://id.example.com
DROPY_PAGES_OIDC_CLIENT_ID=...
DROPY_PAGES_OIDC_CLIENT_SECRET=...
DROPY_PAGES_OIDC_REDIRECT_URL=https://pages.example.com/__auth/callback
```

Users allowed in the pages application may open **all** pages whose access mode is `pocketid`. To separate audiences per page, use multiple Pocket-ID applications and run multiple dropy instances.

Optional extra allowlists are available via `DROPY_ADMIN_EMAILS`, `DROPY_ADMIN_GROUPS`, `DROPY_PAGES_EMAILS`, and `DROPY_PAGES_GROUPS`. The primary access control should remain the Pocket-ID application configuration.

> If Pocket-ID itself is behind Cloudflare Access or another gateway, make sure the discovery document, JWKS endpoint, and token endpoint are reachable by the dropy server (service token or bypass). Server-to-server OIDC discovery and code exchange will otherwise fail.

## Reverse proxy

### Caddy

```caddyfile
admin.example.com {
    reverse_proxy 127.0.0.1:8080
}

pages.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

### Cloudflare Tunnel

```yaml
tunnel: <tunnel-id>
credentials-file: /etc/cloudflared/<tunnel-id>.json

ingress:
  - hostname: admin.example.com
    service: http://127.0.0.1:8080
  - hostname: pages.example.com
    service: http://127.0.0.1:8080
  - service: http_status:404
```

No wildcard hostname is required. Create one DNS record for each hostname.

If Cloudflare is in front of the app, keep its cache out of the way. dropy sets its own cache headers; protected pages send `private, no-store`. dropy trusts `CF-Connecting-IP`, `X-Forwarded-For`, and `X-Real-IP` only because it binds to loopback (`DROPY_TRUST_PROXY=true`). Set it to `false` if the app is not behind a trusted proxy.

## Installation

```bash
# Build a static binary
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o dropy ./cmd/dropy

# System user and directories
sudo useradd --system --home /var/lib/dropy --shell /usr/sbin/nologin dropy
sudo install -d -o dropy -g dropy -m 700 /var/lib/dropy
sudo install -d -m 700 /etc/dropy

# Binary and configuration
sudo install -m 755 dropy /usr/local/bin/dropy
sudo install -m 600 packaging/dropy.env.example /etc/dropy/dropy.env
sudo editor /etc/dropy/dropy.env

# systemd
sudo install -m 644 packaging/dropy.service /etc/systemd/system/dropy.service
sudo systemctl daemon-reload
sudo systemctl enable --now dropy
sudo systemctl status dropy
```

Logs:

```bash
journalctl -u dropy -f
```

The service is hardened with `ProtectSystem=strict`, `PrivateTmp`, `NoNewPrivileges`, and a memory limit. Adjust `MemoryMax` if you deploy very large ZIP bundles.

## Configuration

All values are provided through environment variables. See [`packaging/dropy.env.example`](packaging/dropy.env.example) for a complete example.

| Variable | Default | Description |
|---|---|---|
| `DROPY_LISTEN` | `127.0.0.1:8080` | HTTP listen address |
| `DROPY_DATA_DIR` | `./data` | SQLite database and version directories |
| `DROPY_ADMIN_HOST` | required | Hostname of the admin UI |
| `DROPY_PAGES_HOST` | required | Hostname of published pages |
| `DROPY_ADMIN_BASE_URL` | `https://$DROPY_ADMIN_HOST` | Public admin URL |
| `DROPY_PUBLIC_BASE_URL` | `https://$DROPY_PAGES_HOST` | Public page URL |
| `DROPY_ADMIN_OIDC_*` | – | Admin OIDC client |
| `DROPY_PAGES_OIDC_*` | – | Pages OIDC client |
| `DROPY_ADMIN_EMAILS/GROUPS` | empty | Optional admin allowlist |
| `DROPY_PAGES_EMAILS/GROUPS` | empty | Optional pages allowlist |
| `DROPY_OIDC_SCOPES` | `openid profile email` | Requested scopes |
| `DROPY_SECURE_COOKIES` | `true` | Set `Secure` on cookies |
| `DROPY_TRUST_PROXY` | `true` | Trust proxy client-IP headers |
| `DROPY_ENABLE_MULTI_FILE` | `false` | Allow ZIP uploads |
| `DROPY_KEEP_VERSIONS` | `10` | Versions kept per page |
| `DROPY_SESSION_DAYS` | `30` | Admin session lifetime |
| `DROPY_PAGE_SESSION_HOURS` | `24` | Protected-page session lifetime |
| `DROPY_MAX_HTML_BYTES` | `5242880` | Max pasted/uploaded HTML size |
| `DROPY_MAX_ZIP_BYTES` | `52428800` | Max uncompressed ZIP size |
| `DROPY_MAX_FILE_BYTES` | `10485760` | Max single file inside a ZIP |
| `DROPY_MAX_FILES` | `200` | Max files inside a ZIP |
| `DROPY_DEV` | `false` | Enable local dev host alias |
| `DROPY_DEV_AUTH` | `false` | Enable dev login (requires `DROPY_DEV=true`) |

**Never enable `DROPY_DEV_AUTH` on a public server.**

## Usage

1. Sign in at `https://admin.example.com`.
2. Upload an HTML file or paste markup.
3. Choose a path such as `demo` or `reports/2026/q1`.
4. Choose the access mode.
5. Deploy.

### Paths

- Allowed: lowercase `a-z`, `0-9`, `-`, up to 4 levels, max 200 characters.
- Not allowed: spaces, umlauts, `_`, `?`, `#`, `%`.
- Reserved: `api`, `auth`, `static`, `healthz`, `favicon.ico`, `robots.txt`, and any segment starting with `__`.
- Deploying to an existing path creates a new version and updates the page.

### Access modes

| Mode | Behaviour |
|---|---|
| Public | Anyone with the URL can open the page. |
| PIN | 6–12 digits, keypad-style unlock screen, rate limiting/lockout. |
| Password | At least 8 characters, stored as an Argon2id hash. |
| Pocket-ID | Login through the separate pages OIDC application. |

Protected pages send `Cache-Control: private, no-store`, `Pragma: no-cache`, and `X-Robots-Tag: noindex`. Access cookies are scoped to the page path (`Path=/<path>/`) and stored server-side. Changing the PIN, password, or access mode invalidates existing sessions for that page.

### Versions and rollback

Every deploy creates a version. The versions page lets you:

- inspect the active version,
- download an older version as a ZIP,
- roll back to an older version.

The active version is never pruned automatically. Older versions beyond `DROPY_KEEP_VERSIONS` are removed after a deploy or rollback.

### Share links

Create expiring links from the page editor:

```
https://pages.example.com/<path>/?share=<token>
```

Links support an expiry date (1–365 days) and an optional usage limit. Opening a link creates a page session and redirects to the clean URL. Revoking a link also invalidates sessions created by that link. The token is shown only once; store it somewhere safe if you need it later.

### Multi-file ZIP bundles

Disabled by default. Enable with:

```env
DROPY_ENABLE_MULTI_FILE=true
```

Upload a `.zip` containing `index.html` at the root, or exactly one top-level folder that contains `index.html`. Limits and protections:

- max 50 MB uncompressed,
- max 10 MB per file,
- max 200 files,
- no symlinks, absolute paths, `..`, `.git`, `.env`, or hidden files (except `.well-known`),
- `__MACOSX` and `.DS_Store` are ignored.

Since pages are served from a path, root-relative asset URLs such as `/style.css` will not point at your page. Use relative URLs (`./style.css`, `assets/app.js`) or a `<base href="./">` tag.

## API and CLI

Create an API token under **API & CLI** in the admin UI. The token is shown only once.

```bash
curl -X POST https://admin.example.com/api/sites \
  -H "Authorization: Bearer dropy_…" \
  -F file=@index.html \
  -F path=my-page \
  -F title="My page" \
  -F mode=public
```

Using the bundled CLI:

```bash
dropy deploy \
  --server https://admin.example.com \
  --token "$DROPY_TOKEN" \
  --file index.html \
  --path my-page \
  --title "My page" \
  --mode public
```

For protected pages:

```bash
dropy deploy --file index.html --path private --mode pin --pin 482913
```

### API endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/sites` | List pages |
| `POST` | `/api/sites` | Deploy or update by path |
| `PUT` | `/api/sites/{id}` | Update content or settings |
| `DELETE` | `/api/sites/{id}` | Delete a page and its versions |
| `GET` | `/api/sites/{id}/versions` | List versions |
| `POST` | `/api/sites/{id}/rollback/{vid}` | Roll back |

JSON deploy/update example:

```json
{
  "path": "demo",
  "title": "Demo",
  "mode": "password",
  "password": "at-least-8-characters",
  "html": "<!doctype html><h1>Hello</h1>"
}
```

For `PUT`, omitted fields keep their current values. Sending an empty `html` updates settings only.

## Security notes

- **Untrusted content:** Published pages are served with a sandboxing Content-Security-Policy. This limits top-level navigation, popups, and similar behaviour, but it is not a full isolation boundary. Only deploy content you trust.
- **Same-origin pages:** Public and protected pages share the same pages hostname. JavaScript from a public page could request protected pages in the browser of a signed-in viewer. This is appropriate for a single-owner deployment; if you need stronger isolation, use separate domains or instances.
- **Admin separation:** Never publish a page at the same hostname used for the admin interface. dropy routes by `Host` and rejects admin requests from the pages hostname.
- **Pocket-ID is the primary gate.** Optional email/group allowlists are an additional layer, not a replacement.
- **Secrets:** Change the PIN/password or access mode to invalidate existing page sessions. Revoke share links and API tokens when they are no longer needed.
- **Backups:** Back up the whole `DROPY_DATA_DIR`. For a consistent SQLite backup, stop the service briefly or use `sqlite3 dropy.db ".backup ..."`.

## Development

```bash
go test ./...
go vet ./...
make build
```

Local dev mode:

```bash
DROPY_DEV=true \
DROPY_DEV_AUTH=true \
DROPY_SECURE_COOKIES=false \
DROPY_DATA_DIR=./data \
go run ./cmd/dropy serve
```

The project intentionally keeps a small scope: no per-page subdomains, no multi-tenant teams, and one Pocket-ID pages client per instance.

## Project

- Author: [SupiDupiToll](https://github.com/SupiDupiToll)
- Repository: [github.com/SupiDupiToll/dropy](https://github.com/SupiDupiToll/dropy)

Issues and pull requests are welcome. Please keep changes focused and include tests for behaviour changes.
