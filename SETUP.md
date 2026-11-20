# Setup guide

A complete walkthrough for running dropy on a Linux server with systemd and a TLS-terminating reverse proxy.

The examples use:

- `admin.example.com` for the admin UI
- `pages.example.com` for published pages
- `id.example.com` for Pocket-ID
- `/var/lib/dropy` for data
- `/usr/local/bin/dropy` for the binary

Replace these with your own hostnames and paths.

## 1. Prerequisites

- Go 1.26 or newer (to build)
- Linux with systemd
- A reverse proxy that terminates TLS and forwards requests to `127.0.0.1:8080`
- Two DNS names pointing at your server or tunnel
- Optional: a Pocket-ID instance

The admin hostname and the pages hostname must be different. dropy uses the `Host` header to decide whether a request goes to the admin app or the page server.

## 2. Build and install the binary

```bash
git clone https://github.com/SupiDupiToll/dropy.git
cd dropy

CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o dropy ./cmd/dropy

sudo install -m 755 dropy /usr/local/bin/dropy
```

Verify:

```bash
dropy deploy --help
```

## 3. Create the service user and directories

```bash
sudo useradd --system --home /var/lib/dropy --shell /usr/sbin/nologin dropy
sudo install -d -o dropy -g dropy -m 700 /var/lib/dropy
sudo install -d -m 700 /etc/dropy
```

The service stores SQLite and published files in `/var/lib/dropy`. Do not run it as `root`.

## 4. Configure dropy

Copy the example configuration:

```bash
sudo install -m 600 packaging/dropy.env.example /etc/dropy/dropy.env
sudo editor /etc/dropy/dropy.env
```

At minimum, set:

```env
DROPY_ADMIN_HOST=admin.example.com
DROPY_PAGES_HOST=pages.example.com
DROPY_ADMIN_BASE_URL=https://admin.example.com
DROPY_PUBLIC_BASE_URL=https://pages.example.com

DROPY_ADMIN_OIDC_ISSUER=https://id.example.com
DROPY_ADMIN_OIDC_CLIENT_ID=...
DROPY_ADMIN_OIDC_CLIENT_SECRET=...
DROPY_ADMIN_OIDC_REDIRECT_URL=https://admin.example.com/auth/callback

DROPY_PAGES_OIDC_ISSUER=https://id.example.com
DROPY_PAGES_OIDC_CLIENT_ID=...
DROPY_PAGES_OIDC_CLIENT_SECRET=...
DROPY_PAGES_OIDC_REDIRECT_URL=https://pages.example.com/__auth/callback
```

Keep these defaults for production:

```env
DROPY_LISTEN=127.0.0.1:8080
DROPY_DATA_DIR=/var/lib/dropy
DROPY_SECURE_COOKIES=true
DROPY_TRUST_PROXY=true
```

`DROPY_TRUST_PROXY=true` is safe only because dropy listens on loopback behind a trusted proxy. If you expose it differently, set it to `false`.

## 5. Set up Pocket-ID

Create two OIDC applications.

### Admin application

| Setting | Value |
|---|---|
| Callback URL | `https://admin.example.com/auth/callback` |
| Scopes | `openid profile email` |
| Allowed users | your admin account |
| Allowed groups | optional |

Put its client ID and secret into:

```env
DROPY_ADMIN_OIDC_CLIENT_ID=...
DROPY_ADMIN_OIDC_CLIENT_SECRET=...
```

### Pages application

| Setting | Value |
|---|---|
| Callback URL | `https://pages.example.com/__auth/callback` |
| Scopes | `openid profile email` |
| Allowed users | everyone who may open Pocket-ID protected pages |

Put its client ID and secret into:

```env
DROPY_PAGES_OIDC_CLIENT_ID=...
DROPY_PAGES_OIDC_CLIENT_SECRET=...
```

Everyone allowed in the pages application can open every page with access mode `pocketid`. Use separate Pocket-ID applications and separate dropy instances if you need different audiences.

If you use group allowlists, add the `groups` scope:

```env
DROPY_OIDC_SCOPES=openid profile email groups
```

If Pocket-ID is behind Cloudflare Access or another gateway, allow the dropy server to reach OIDC discovery, JWKS, and token endpoints server-to-server. Otherwise login will fail during code exchange.

## 6. Configure the reverse proxy

### Caddy

```caddyfile
admin.example.com {
    reverse_proxy 127.0.0.1:8080
}

pages.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Reload Caddy:

```bash
sudo systemctl reload caddy
```

Caddy obtains TLS certificates automatically.

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

Create one DNS record for each hostname. No wildcard is needed.

Do not force Cloudflare caching for either hostname. dropy sets its own cache headers, and protected pages use `private, no-store`.

## 7. Install the systemd service

```bash
sudo install -m 644 packaging/dropy.service /etc/systemd/system/dropy.service
sudo systemctl daemon-reload
sudo systemctl enable --now dropy
```

Check the service:

```bash
sudo systemctl status dropy
journalctl -u dropy -f
```

Health check:

```bash
curl -fsS https://admin.example.com/healthz
# {"status":"ok"}
```

## 8. First login and test deploy

1. Open `https://admin.example.com`.
2. Sign in with Pocket-ID.
3. Create an API token only if you need the CLI.
4. Deploy a test page:

```bash
printf '<!doctype html><h1>Hello from dropy</h1>' > /tmp/index.html

dropy deploy \
  --server https://admin.example.com \
  --token "$DROPY_TOKEN" \
  --file /tmp/index.html \
  --path test \
  --mode public
```

Open `https://pages.example.com/test/`.

For a protected page:

```bash
dropy deploy \
  --server https://admin.example.com \
  --token "$DROPY_TOKEN" \
  --file /tmp/index.html \
  --path private \
  --mode pin \
  --pin 482913
```

## 9. Local development without Pocket-ID

```bash
DROPY_DEV=true \
DROPY_DEV_AUTH=true \
DROPY_SECURE_COOKIES=false \
DROPY_DATA_DIR=./data \
DROPY_LISTEN=127.0.0.1:8080 \
go run ./cmd/dropy serve
```

Open `http://localhost:8080` and use the development login. Preview a page locally at:

```
http://localhost:8080/__pages/<path>/
```

Never enable `DROPY_DEV_AUTH` on a public server.

## 10. Updating

```bash
cd dropy
git pull
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o dropy ./cmd/dropy
sudo install -m 755 dropy /usr/local/bin/dropy
sudo systemctl restart dropy
```

The SQLite schema is migrated automatically on startup.

## 11. Backup and restore

Stop the service for a simple, consistent backup:

```bash
sudo systemctl stop dropy
sudo tar -C /var/lib -czf dropy-backup-$(date +%F).tar.gz dropy
sudo systemctl start dropy
```

Alternative SQLite online backup:

```bash
sudo sqlite3 /var/lib/dropy/dropy.db ".backup '/tmp/dropy.db'"
sudo tar -C /var/lib/dropy -czf dropy-versions-$(date +%F).tar.gz versions
```

To restore, stop the service, replace `/var/lib/dropy`, then start it again.

## 12. Troubleshooting

| Symptom | Check |
|---|---|
| `admin OIDC is not configured` | Set `DROPY_ADMIN_OIDC_CLIENT_ID` and `_CLIENT_SECRET`, or use `DROPY_DEV_AUTH=true` locally. |
| Login redirects, then fails | Callback URLs in Pocket-ID must match exactly. |
| `OIDC-Discovery fehlgeschlagen` | The server itself cannot reach Pocket-ID discovery/JWKS/token endpoints. |
| Admin host returns pages or 404 | `DROPY_ADMIN_HOST` / `DROPY_PAGES_HOST` and the proxy `Host` header are wrong. |
| 404 on a published page | Path must match exactly; use the trailing slash. |
| Assets are missing | Use relative asset paths (`./style.css`, `assets/app.js`), not root-relative paths. |
| Cookies are not stored | Production requires HTTPS and `DROPY_SECURE_COOKIES=true`. |
| Upload returns `413` or too large | Raise the `DROPY_MAX_*` limits and check proxy body-size limits. |

## 13. Production checklist

- [ ] Admin and pages hostnames are different.
- [ ] Both hostnames have valid TLS.
- [ ] `DROPY_LISTEN` is loopback-only.
- [ ] `DROPY_SECURE_COOKIES=true`.
- [ ] Pocket-ID applications have exact callback URLs and restricted users/groups.
- [ ] Cloudflare/proxy caching is disabled for protected pages.
- [ ] Backups of `/var/lib/dropy` are scheduled.
- [ ] `DROPY_DEV` and `DROPY_DEV_AUTH` are both `false`.
- [ ] `systemctl status dropy` and `/healthz` are healthy.
