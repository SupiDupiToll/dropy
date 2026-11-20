# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

A single technical owner who self-hosts Dropy and works in the admin UI daily, with many published pages, frequent deploys, and routine version, share-link, and token housekeeping. Confirmed by the owner in this session. The same person also meets the protected-page gate as a viewer when a page is PIN-, password-, or Pocket-ID-protected.

## Product Purpose

Publish static HTML at a path on your own domain, with access control, versions, and an API, from one small self-hosted binary. Success means the owner can go from "I have an HTML file" to a live, correctly protected URL in seconds, and can later find, inspect, republish, or revoke any page without hunting.

## Positioning

Path-based hosting on one hostname, one binary, one SQLite file: no per-page subdomains, no database server, no Node build step, no external frontend toolchain. Both the admin UI and published pages route by `Host` through the same process.

## Operating Context

- Runs on Linux under systemd behind a TLS-terminating reverse proxy or tunnel (Caddy, nginx, Cloudflare Tunnel).
- Two hostnames: `admin.*` for the UI, `pages.*` for published pages; the admin UI is reachable only through Pocket-ID OIDC, with an optional email/group allowlist.
- The owner usually arrives with a file already on disk (single `index.html` or an optional ZIP bundle), or with markup on the clipboard.
- Repeat work is common: redeploying to an existing path (which creates a new version), rolling back, minting and revoking share links and API tokens, changing an access mode.
- A script or CI pipeline deploys through the same API with a bearer token, so the UI documents the exact equivalent call.
- Local development runs with `DROPY_DEV=true` and a dev login.

## Capabilities and Constraints

- Deploy by upload or pasted markup; ZIP bundles are optional and gated by `DROPY_ENABLE_MULTI_FILE`.
- Paths are lowercase `a-z`, `0-9`, `-`, up to four levels, max 200 characters; some segments are reserved.
- Four access modes: public, PIN (6–12 digits), password (≥8 characters, Argon2id), Pocket-ID.
- Every deploy creates a version; older versions can be downloaded as ZIP or rolled back to; the active version is never pruned.
- Expiring share links with an optional usage limit, revocable, token shown exactly once.
- API tokens, also shown exactly once, revocable.
- Server-rendered Go `html/template` with embedded templates and static assets; no frontend build step, so any styling must ship as plain CSS and small vanilla JS.
- UI copy is German; the codebase, README, and API are English.
- The interface must keep working with JavaScript unavailable for every core action (forms post normally); JS only enhances.
- Light and dark both ship today and are expected to keep working.

## Brand Commitments

- Name: `dropy`. Existing logo: a simple document glyph (a sheet with a folded corner and two text rules), used as the mark.
- Voice: plain, quiet, technical German — direct labels, no marketing language, no exclamation marks.
- No customer logos, testimonials, benchmarks, or pricing claims exist and none may be invented.
- Standing visual preference, chosen by the owner in this session: the admin UI is a **conventional admin, done properly**, not a themed world. Its craft bar is the Vercel and Cloudflare dashboards. New surface work should sit alongside those, without irony or smuggled quirk.
- The deploy composer belongs in the center of the dashboard; publishing is the page's primary action, and the register of existing pages follows it.

## Evidence on Hand

- Real product surface only: the running admin UI (`/`, `/sites/{id}/edit`, `/sites/{id}/versions`, login) and the protected-page gate.
- Real data shapes available to the UI: site path, title, access mode, current version size / file count / created date, version list with short SHA, share-link state (active / expired / revoked, uses vs max uses), token name and last-used date.
- No marketing site, screenshots, or brand guidelines exist in the repository.

## Product Principles

1. The deploy is the product: the path from file to live URL stays the shortest thing on the screen.
2. State is never hidden: what is live, which version, who can open it, and what expires must be readable at a glance.
3. Irreversible actions are explicit and never one stray click away.
4. The tool recedes behind the pages it publishes; craft shows as precision, not decoration.

## Accessibility & Inclusion

No product-specific standard was established. Treat WCAG 2.2 AA as the floor: visible focus, sufficient contrast in both schemes, real labels, keyboard-operable controls, and reduced-motion respect.
