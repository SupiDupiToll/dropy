package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type OIDC struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

func (o OIDC) Enabled() bool {
	return o.Issuer != "" && o.ClientID != "" && o.ClientSecret != "" && o.RedirectURL != ""
}

type Config struct {
	Listen    string
	DataDir   string
	AdminHost string
	PagesHost string

	AdminBaseURL  string
	PublicBaseURL string

	AdminOIDC OIDC
	PagesOIDC OIDC

	AdminEmails []string
	AdminGroups []string
	PagesEmails []string
	PagesGroups []string

	SecureCookies bool
	Dev           bool
	DevAuth       bool
	TrustProxy    bool

	EnableMultiFile bool
	MaxHTMLBytes    int64
	MaxZipBytes     int64
	MaxFileBytes    int64
	MaxFiles        int

	KeepVersions     int
	SessionDays      int
	PageSessionHours int
}

func Load() (*Config, error) {
	c := &Config{
		Listen:           env("DROPY_LISTEN", "127.0.0.1:8080"),
		DataDir:          env("DROPY_DATA_DIR", "./data"),
		AdminHost:        strings.ToLower(env("DROPY_ADMIN_HOST", "admin.example.com")),
		PagesHost:        strings.ToLower(env("DROPY_PAGES_HOST", "pages.example.com")),
		AdminBaseURL:     strings.TrimRight(env("DROPY_ADMIN_BASE_URL", ""), "/"),
		PublicBaseURL:    strings.TrimRight(env("DROPY_PUBLIC_BASE_URL", ""), "/"),
		SecureCookies:    envBool("DROPY_SECURE_COOKIES", true),
		Dev:              envBool("DROPY_DEV", false),
		DevAuth:          envBool("DROPY_DEV_AUTH", false),
		TrustProxy:       envBool("DROPY_TRUST_PROXY", true),
		EnableMultiFile:  envBool("DROPY_ENABLE_MULTI_FILE", false),
		MaxHTMLBytes:     envInt64("DROPY_MAX_HTML_BYTES", 5<<20),
		MaxZipBytes:      envInt64("DROPY_MAX_ZIP_BYTES", 50<<20),
		MaxFileBytes:     envInt64("DROPY_MAX_FILE_BYTES", 10<<20),
		MaxFiles:         envInt("DROPY_MAX_FILES", 200),
		KeepVersions:     envInt("DROPY_KEEP_VERSIONS", 10),
		SessionDays:      envInt("DROPY_SESSION_DAYS", 30),
		PageSessionHours: envInt("DROPY_PAGE_SESSION_HOURS", 24),
	}

	if c.AdminBaseURL == "" {
		c.AdminBaseURL = "https://" + c.AdminHost
	}
	if c.PublicBaseURL == "" {
		c.PublicBaseURL = "https://" + c.PagesHost
	}
	if c.AdminHost == "" || c.PagesHost == "" {
		return nil, fmt.Errorf("DROPY_ADMIN_HOST and DROPY_PAGES_HOST are required")
	}
	if c.AdminHost == c.PagesHost {
		return nil, fmt.Errorf("DROPY_ADMIN_HOST and DROPY_PAGES_HOST must be different")
	}
	if c.KeepVersions < 1 {
		c.KeepVersions = 1
	}
	if c.SessionDays < 1 {
		c.SessionDays = 1
	}
	if c.PageSessionHours < 1 {
		c.PageSessionHours = 1
	}
	if c.MaxHTMLBytes < 1 || c.MaxZipBytes < 1 || c.MaxFileBytes < 1 || c.MaxFiles < 1 {
		return nil, fmt.Errorf("upload limits must be positive")
	}

	scopes := strings.Fields(env("DROPY_OIDC_SCOPES", "openid profile email"))
	c.AdminOIDC = OIDC{
		Issuer:       strings.TrimRight(env("DROPY_ADMIN_OIDC_ISSUER", ""), "/"),
		ClientID:     env("DROPY_ADMIN_OIDC_CLIENT_ID", ""),
		ClientSecret: env("DROPY_ADMIN_OIDC_CLIENT_SECRET", ""),
		RedirectURL:  env("DROPY_ADMIN_OIDC_REDIRECT_URL", c.AdminBaseURL+"/auth/callback"),
		Scopes:       scopes,
	}
	pagesIssuer := env("DROPY_PAGES_OIDC_ISSUER", c.AdminOIDC.Issuer)
	c.PagesOIDC = OIDC{
		Issuer:       strings.TrimRight(pagesIssuer, "/"),
		ClientID:     env("DROPY_PAGES_OIDC_CLIENT_ID", ""),
		ClientSecret: env("DROPY_PAGES_OIDC_CLIENT_SECRET", ""),
		RedirectURL:  env("DROPY_PAGES_OIDC_REDIRECT_URL", c.PublicBaseURL+"/__auth/callback"),
		Scopes:       scopes,
	}

	c.AdminEmails = splitList(env("DROPY_ADMIN_EMAILS", ""))
	c.AdminGroups = splitList(env("DROPY_ADMIN_GROUPS", ""))
	c.PagesEmails = splitList(env("DROPY_PAGES_EMAILS", ""))
	c.PagesGroups = splitList(env("DROPY_PAGES_GROUPS", ""))

	if c.DevAuth && !c.Dev {
		return nil, fmt.Errorf("DROPY_DEV_AUTH requires DROPY_DEV=true")
	}
	if !c.AdminOIDC.Enabled() && !c.DevAuth {
		return nil, fmt.Errorf("admin OIDC is not configured (set DROPY_ADMIN_OIDC_CLIENT_ID/SECRET) or enable DROPY_DEV_AUTH")
	}
	return c, nil
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return strings.TrimSpace(v)
	}
	return def
}

func envBool(key string, def bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok {
		return def
	}
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return b
}

func envInt(key string, def int) int {
	v, ok := os.LookupEnv(key)
	if !ok {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return n
}

func envInt64(key string, def int64) int64 {
	v, ok := os.LookupEnv(key)
	if !ok {
		return def
	}
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil {
		return def
	}
	return n
}

func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
