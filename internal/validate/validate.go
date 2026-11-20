package validate

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

var segmentRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

var reserved = map[string]bool{
	"api": true, "auth": true, "static": true, "healthz": true,
	"favicon.ico": true, "robots.txt": true,
}

// Path normalizes and validates a public site path such as "demo" or "reports/2026".
func Path(raw string) (string, error) {
	p := strings.ToLower(strings.TrimSpace(raw))
	p = strings.Trim(p, "/")
	if p == "" {
		return "", fmt.Errorf("Pfad fehlt")
	}
	if strings.ContainsAny(p, `\?#%`) {
		return "", fmt.Errorf("Pfad enthält ungültige Zeichen")
	}
	parts := strings.Split(p, "/")
	if len(parts) > 4 {
		return "", fmt.Errorf("maximal 4 Pfad-Ebenen erlaubt")
	}
	for _, part := range parts {
		if part == "" {
			return "", fmt.Errorf("Pfad enthält leere Segmente")
		}
		if strings.HasPrefix(part, "__") {
			return "", fmt.Errorf("Pfadsegmente dürfen nicht mit __ beginnen")
		}
		if reserved[part] {
			return "", fmt.Errorf("reservierter Pfad: %s", part)
		}
		if !segmentRE.MatchString(part) {
			return "", fmt.Errorf("ungültiges Pfadsegment %q (erlaubt: a-z, 0-9, Bindestrich)", part)
		}
	}
	if len(p) > 200 {
		return "", fmt.Errorf("Pfad ist zu lang")
	}
	return p, nil
}

// Title normalizes an optional page title.
func Title(raw string) string {
	t := strings.TrimSpace(raw)
	if len(t) > 120 {
		t = t[:120]
	}
	return t
}

// Secret validates a PIN or password for the given access mode.
func Secret(mode, secret string) (string, error) {
	secret = strings.TrimSpace(secret)
	switch mode {
	case "public", "pocketid":
		return "", nil
	case "pin":
		if len(secret) < 6 || len(secret) > 12 {
			return "", fmt.Errorf("PIN muss 6 bis 12 Ziffern haben")
		}
		for _, r := range secret {
			if r < '0' || r > '9' {
				return "", fmt.Errorf("PIN darf nur Ziffern enthalten")
			}
		}
		return secret, nil
	case "password":
		if len(secret) < 8 {
			return "", fmt.Errorf("Passwort muss mindestens 8 Zeichen haben")
		}
		if len(secret) > 200 {
			return "", fmt.Errorf("Passwort ist zu lang")
		}
		return secret, nil
	default:
		return "", fmt.Errorf("ungültiger Zugriffsmodus")
	}
}

// AccessMode validates the access mode.
func AccessMode(mode string) error {
	switch mode {
	case "public", "pin", "password", "pocketid":
		return nil
	default:
		return fmt.Errorf("ungültiger Zugriffsmodus")
	}
}

// RelPath validates a relative asset path inside a version directory.
func RelPath(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	if strings.ContainsRune(raw, 0) {
		return "", fmt.Errorf("ungültiger Pfad")
	}
	clean := path.Clean("/" + strings.ReplaceAll(raw, `\`, "/"))
	clean = strings.TrimPrefix(clean, "/")
	if clean == "" || clean == "." {
		return "", nil
	}
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("ungültiger Pfad")
	}
	for _, part := range strings.Split(clean, "/") {
		if part == ".." || part == "" {
			return "", fmt.Errorf("ungültiger Pfad")
		}
	}
	return clean, nil
}

// SlugFromFilename proposes a path based on an uploaded file name.
func SlugFromFilename(name string) string {
	name = strings.TrimSpace(name)
	if i := strings.LastIndexByte(name, '.'); i > 0 {
		name = name[:i]
	}
	name = strings.ToLower(name)
	var b strings.Builder
	lastDash := false
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
		} else if !lastDash && b.Len() > 0 {
			b.WriteByte('-')
			lastDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 63 {
		out = strings.Trim(out[:63], "-")
	}
	if out == "" {
		out = "seite"
	}
	return out
}
