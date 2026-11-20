# Design system

Scope: the dropy admin UI (`web/templates/*`, `web/static/admin.css`) and the protected-page gate. The published pages themselves are authored by users and are not part of this system.

## Commitment

Conventional admin, executed at the craft level of Vercel and Cloudflare: neutral surfaces, hairline rules, real tables, one black primary action, colour only where it carries state. No world metaphor, no gradient, no ornament. The deploy composer is the center of the dashboard, not a side rail.

## Ground and colour

Two schemes, both shipped, chosen by `prefers-color-scheme`.

| Token | Light | Dark | Job |
|---|---|---|---|
| `--bg` | `#f7f8f8` | `#0b0d0e` | app ground |
| `--surface` | `#ffffff` | `#121516` | top bar, panels, table rows |
| `--surface-2` | `#f2f4f4` | `#181c1e` | composer foot, tinted rows, code blocks |
| `--surface-3` | `#e9ecec` | `#212628` | hover fill for quiet controls |
| `--text` | `#0c0e0f` | `#eef1f2` | body and headings |
| `--muted` | `#5c666c` | `#a2acb2` | labels, meta, help, placeholders (5.3:1 on surface-2) |
| `--line` | `#e3e7e8` | `#262b2d` | hairline rules |
| `--line-strong` | `#cbd2d4` | `#363d40` | input and control borders |
| `--primary-bg` | `#111516` | `#f2f4f5` | primary button (inverts in dark) |
| `--live` | `#0b6b43` | `#4ecf95` | published, active, new-path state |
| `--danger` | `#b42318` | `#ff8f84` | destructive, invalid, expired |
| `--warn` | `#8a5300` | `#e3b26a` | expired share link |

Colour does real jobs only: access state (open lock in `--live`), version state (`Aktiv` dot), share-link life (active / expired / revoked), the deploy summary's new-vs-invalid state, and destructive actions. There is no brand accent hue.

## Type

System sans stack for UI; monospace for paths, hashes, tokens, and code.

| Role | Size / weight | Notes |
|---|---|---|
| Page title | 24px / 600, -0.021em | one per page |
| Section title (h2) | 16px / 600 | panels, register, composer |
| Sub-section (h3) | 14px / 600 | form groups |
| Body | 14px / 400, 1.5 | |
| Label | 12px / 500, muted | above inputs, not beside them |
| Meta / table | 12.5–13px | dates, sizes, hashes use `tabular-nums` |

Scale steps are 1.5× (title to section) and 1.14× (section to body), which is deliberate for a dense tool: the page title carries hierarchy, panels stay quiet.

## Layout

- Container 1120px, 24px gutters (16px under 760px). Top bar 56px, sticky, hairline bottom.
- Dashboard: page head → **centered composer (760px max)** → full-width register → API panel. The composer is the focal point; the register is the record.
- Edit: 1fr + 320px side column, collapsing at 960px. Versions: single register.
- Elevation is declared once: 1px border, no shadow. The only shadow in the system is `--shadow-sm` (1px offset) on the active segment.
- Radii: 12px panels, 8px controls, 6px small controls, 4px tag. No pills except 6px status dots.

## Components

- **Composer**: segmented input switch (Datei / HTML einfügen), drop zone, path field with a prefix strip showing the full base URL, title + access in two columns, secret field appearing per mode, foot with the deploy summary and the primary button.
- **Deploy summary** (the signature move): one live line under the form stating what will be written — `Neu` + URL for a fresh path, `Neue Version` for an existing one (label switches to "Neue Version deployen"), `Ungültig` with a red field border and the rule help hidden. `aria-live="polite"`.
- **Register**: real `<table>` with `th scope="col"`, columns Seite / Zugriff / Größe / Version / Aktualisiert / actions. Rows carry title (500) over a mono path; actions are text links plus an icon-only copy button. Under 760px the table becomes stacked rows with a dot-separated meta line.
- **Versions**: same table, Status column marks the active version with a green dot and tints its row.
- **Share links / tokens**: state dot + label, uses as a figure, destructive action as a quiet red ghost button.
- **Gate**: 396px card, brand mark, title, mono path, then PIN keypad / password / Pocket-ID. Standalone inline CSS; same tokens.
- **Flash**: 1px border + tinted fill + drawn icon. No left-edge accent bar.

## Motion

Only transitions on border, background, and color (120ms). The submit spinner is the single animation, disabled under `prefers-reduced-motion`. No entrance animations, no scroll effects.

## Accessibility

- Skip link to `#main`; focus-visible is a 2px `--text` outline at 2px offset, never removed.
- Every icon-only control carries `aria-label` and `title`; decorative SVG is `aria-hidden`.
- Segmented control is a real tablist with roving tabindex and Left/Right keys; panels are labelled by their tabs.
- The page filter updates the count (`n / total`) and swaps the table for an empty state.
- All forms post natively; JavaScript only enhances. Placeholders meet the same 4.5:1 bar as body text.
- `::selection`, caret colour, and tabular figures are themed from the palette.
