package validate

import "testing"

func TestPath(t *testing.T) {
	valid := map[string]string{
		"demo":            "demo",
		" Demo ":          "demo",
		"/demo/":          "demo",
		"reports/2026/q1": "reports/2026/q1",
		"a-b-c":           "a-b-c",
		"Reports/2026":    "reports/2026",
	}
	for raw, want := range valid {
		got, err := Path(raw)
		if err != nil {
			t.Fatalf("Path(%q): %v", raw, err)
		}
		if got != want {
			t.Fatalf("Path(%q) = %q, want %q", raw, got, want)
		}
	}
	invalid := []string{
		"", "/", "a b", "a_b", "-a", "a-", "a//b", "a/../b", "a?b", "a#b",
		"__unlock", "api", "static", "a/b/c/d/e",
	}
	for _, raw := range invalid {
		if _, err := Path(raw); err == nil {
			t.Fatalf("Path(%q) unexpectedly succeeded", raw)
		}
	}
}

func TestSecret(t *testing.T) {
	if _, err := Secret("pin", "123456"); err != nil {
		t.Fatal(err)
	}
	if _, err := Secret("pin", "12345"); err == nil {
		t.Fatal("short pin accepted")
	}
	if _, err := Secret("pin", "12345a"); err == nil {
		t.Fatal("non-numeric pin accepted")
	}
	if _, err := Secret("password", "12345678"); err != nil {
		t.Fatal(err)
	}
	if _, err := Secret("password", "short"); err == nil {
		t.Fatal("short password accepted")
	}
	if _, err := Secret("public", "whatever"); err != nil {
		t.Fatal(err)
	}
}

func TestRelPath(t *testing.T) {
	good := map[string]string{
		"index.html":    "index.html",
		"assets/app.js": "assets/app.js",
		"./style.css":   "style.css",
		"a//b/../c.txt": "a/c.txt",
	}
	for raw, want := range good {
		got, err := RelPath(raw)
		if err != nil {
			t.Fatalf("RelPath(%q): %v", raw, err)
		}
		if got != want {
			t.Fatalf("RelPath(%q) = %q, want %q", raw, got, want)
		}
	}
	if _, err := RelPath("../../etc/passwd"); err != nil {
		t.Fatal("path traversal not rejected")
	}
	if _, err := RelPath("a\x00b"); err == nil {
		t.Fatal("NUL not rejected")
	}
}

func TestSlugFromFilename(t *testing.T) {
	cases := map[string]string{
		"My Page.html": "my-page",
		"über.html":    "ber",
		"a___b.html":   "a-b",
		"---.html":     "seite",
	}
	for in, want := range cases {
		if got := SlugFromFilename(in); got != want {
			t.Fatalf("SlugFromFilename(%q) = %q, want %q", in, got, want)
		}
	}
}
