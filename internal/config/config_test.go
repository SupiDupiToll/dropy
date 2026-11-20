package config

import "testing"

func TestLoadDevDefaults(t *testing.T) {
	t.Setenv("DROPY_DEV", "true")
	t.Setenv("DROPY_DEV_AUTH", "true")
	t.Setenv("DROPY_ADMIN_HOST", "admin.example")
	t.Setenv("DROPY_PAGES_HOST", "pages.example")
	t.Setenv("DROPY_ADMIN_BASE_URL", "")
	t.Setenv("DROPY_PUBLIC_BASE_URL", "")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.AdminBaseURL != "https://admin.example" || c.PublicBaseURL != "https://pages.example" {
		t.Fatalf("base urls: %q %q", c.AdminBaseURL, c.PublicBaseURL)
	}
	if c.KeepVersions != 10 || c.PageSessionHours != 24 {
		t.Fatalf("defaults: %+v", c)
	}
}

func TestLoadRejectsSameHosts(t *testing.T) {
	t.Setenv("DROPY_DEV", "true")
	t.Setenv("DROPY_DEV_AUTH", "true")
	t.Setenv("DROPY_ADMIN_HOST", "same.example")
	t.Setenv("DROPY_PAGES_HOST", "same.example")
	if _, err := Load(); err == nil {
		t.Fatal("same hosts accepted")
	}
}

func TestLoadRequiresAuth(t *testing.T) {
	t.Setenv("DROPY_ADMIN_HOST", "admin.example")
	t.Setenv("DROPY_PAGES_HOST", "pages.example")
	t.Setenv("DROPY_DEV", "false")
	t.Setenv("DROPY_DEV_AUTH", "false")
	if _, err := Load(); err == nil {
		t.Fatal("missing OIDC accepted")
	}
}

func TestLoadRejectsDevAuthWithoutDev(t *testing.T) {
	t.Setenv("DROPY_ADMIN_HOST", "admin.example")
	t.Setenv("DROPY_PAGES_HOST", "pages.example")
	t.Setenv("DROPY_DEV", "false")
	t.Setenv("DROPY_DEV_AUTH", "true")
	if _, err := Load(); err == nil {
		t.Fatal("dev auth without dev accepted")
	}
}
