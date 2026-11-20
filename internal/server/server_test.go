package server

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"dropy/internal/config"
	"dropy/internal/store"
)

type testClient struct {
	t       *testing.T
	srv     *Server
	st      *store.Store
	cookies map[string]*http.Cookie
}

func newTestClient(t *testing.T) *testClient {
	t.Helper()
	cfg := &config.Config{
		DataDir:          t.TempDir(),
		AdminHost:        "dropy.test",
		PagesHost:        "pages.test",
		AdminBaseURL:     "https://dropy.test",
		PublicBaseURL:    "https://pages.test",
		SecureCookies:    false,
		Dev:              true,
		DevAuth:          true,
		TrustProxy:       false,
		EnableMultiFile:  true,
		MaxHTMLBytes:     1 << 20,
		MaxZipBytes:      5 << 20,
		MaxFileBytes:     1 << 20,
		MaxFiles:         20,
		KeepVersions:     5,
		SessionDays:      1,
		PageSessionHours: 1,
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "dropy.db"))
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := New(cfg, st, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return &testClient{t: t, srv: srv, st: st, cookies: map[string]*http.Cookie{}}
}

func (c *testClient) do(method, host, target string, body io.Reader, contentType string) *httptest.ResponseRecorder {
	c.t.Helper()
	req := httptest.NewRequest(method, "http://"+host+target, body)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for _, ck := range c.cookies {
		req.AddCookie(ck)
	}
	rec := httptest.NewRecorder()
	c.srv.Handler().ServeHTTP(rec, req)
	for _, ck := range rec.Result().Cookies() {
		if ck.MaxAge < 0 {
			delete(c.cookies, ck.Name)
		} else {
			c.cookies[ck.Name] = ck
		}
	}
	return rec
}

func (c *testClient) login() string {
	c.t.Helper()
	resp := c.do(http.MethodGet, "dropy.test", "/dev-login", nil, "")
	if resp.Code != http.StatusSeeOther {
		c.t.Fatalf("dev login status = %d", resp.Code)
	}
	resp = c.do(http.MethodGet, "dropy.test", "/", nil, "")
	if resp.Code != http.StatusOK {
		c.t.Fatalf("dashboard status = %d body=%s", resp.Code, resp.Body.String())
	}
	m := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(resp.Body.String())
	if len(m) != 2 {
		c.t.Fatal("csrf token not found")
	}
	return m[1]
}

func formBody(values url.Values) (io.Reader, string) {
	return strings.NewReader(values.Encode()), "application/x-www-form-urlencoded"
}

func multipartBody(t *testing.T, fields map[string]string, filename, content string) (io.Reader, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if filename != "" {
		fw, err := mw.CreateFormFile("file", filename)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf, mw.FormDataContentType()
}

func TestAdminAuthAndPublicPage(t *testing.T) {
	c := newTestClient(t)
	resp := c.do(http.MethodGet, "dropy.test", "/", nil, "")
	if resp.Code != http.StatusSeeOther || !strings.HasPrefix(resp.Header().Get("Location"), "/login") {
		t.Fatalf("unauth root: %d %q", resp.Code, resp.Header().Get("Location"))
	}
	csrf := c.login()

	body, ct := multipartBody(t, map[string]string{
		"csrf": csrf, "path": "demo", "title": "Demo", "mode": "public",
	}, "index.html", "<!doctype html><h1>Hello</h1>")
	resp = c.do(http.MethodPost, "dropy.test", "/deploy", body, ct)
	if resp.Code != http.StatusSeeOther {
		t.Fatalf("deploy status = %d body=%s", resp.Code, resp.Body.String())
	}

	resp = c.do(http.MethodGet, "pages.test", "/demo/", nil, "")
	if resp.Code != http.StatusOK || !strings.Contains(resp.Body.String(), "Hello") {
		t.Fatalf("page: %d %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Header().Get("Content-Security-Policy"), "sandbox") {
		t.Fatal("missing CSP sandbox")
	}
	if !strings.HasPrefix(resp.Header().Get("Cache-Control"), "public") {
		t.Fatalf("cache = %q", resp.Header().Get("Cache-Control"))
	}
	etag := resp.Header().Get("ETag")
	if etag == "" {
		t.Fatal("missing etag")
	}
	req := httptest.NewRequest(http.MethodGet, "http://pages.test/demo/", nil)
	req.Header.Set("If-None-Match", etag)
	rec := httptest.NewRecorder()
	c.srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotModified {
		t.Fatalf("etag status = %d", rec.Code)
	}

	resp = c.do(http.MethodGet, "pages.test", "/demo", nil, "")
	if resp.Code != http.StatusMovedPermanently || resp.Header().Get("Location") != "/demo/" {
		t.Fatalf("canonical redirect: %d %q", resp.Code, resp.Header().Get("Location"))
	}
	resp = c.do(http.MethodGet, "pages.test", "/missing/", nil, "")
	if resp.Code != http.StatusNotFound {
		t.Fatalf("missing status = %d", resp.Code)
	}
}

func TestDeployRequiresCSRF(t *testing.T) {
	c := newTestClient(t)
	c.login()
	body, ct := multipartBody(t, map[string]string{"path": "x", "mode": "public"}, "index.html", "<h1>x</h1>")
	resp := c.do(http.MethodPost, "dropy.test", "/deploy", body, ct)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.Code)
	}
}

func TestPinGateAndShareLink(t *testing.T) {
	c := newTestClient(t)
	csrf := c.login()
	body, ct := multipartBody(t, map[string]string{
		"csrf": csrf, "path": "secret", "title": "Secret", "mode": "pin", "pin": "482913",
	}, "index.html", "<h1>TOP SECRET</h1>")
	resp := c.do(http.MethodPost, "dropy.test", "/deploy", body, ct)
	if resp.Code != http.StatusSeeOther {
		t.Fatalf("deploy: %d %s", resp.Code, resp.Body.String())
	}

	resp = c.do(http.MethodGet, "pages.test", "/secret/", nil, "")
	if resp.Code != http.StatusUnauthorized || !strings.Contains(resp.Body.String(), "Gib die PIN") {
		t.Fatalf("gate: %d %s", resp.Code, resp.Body.String())
	}

	wrong, wrongCT := formBody(url.Values{"pin": {"000000"}})
	resp = c.do(http.MethodPost, "pages.test", "/secret/__unlock", wrong, wrongCT)
	if resp.Code != http.StatusUnauthorized || !strings.Contains(resp.Body.String(), "nicht richtig") {
		t.Fatalf("wrong pin: %d", resp.Code)
	}

	right, rightCT := formBody(url.Values{"pin": {"482913"}})
	resp = c.do(http.MethodPost, "pages.test", "/secret/__unlock", right, rightCT)
	if resp.Code != http.StatusSeeOther || resp.Header().Get("Location") != "/secret/" {
		t.Fatalf("right pin: %d %q", resp.Code, resp.Header().Get("Location"))
	}
	resp = c.do(http.MethodGet, "pages.test", "/secret/", nil, "")
	if resp.Code != http.StatusOK || !strings.Contains(resp.Body.String(), "TOP SECRET") {
		t.Fatalf("protected access: %d", resp.Code)
	}
	if resp.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("cache = %q", resp.Header().Get("Cache-Control"))
	}

	site, err := c.st.GetSiteByPath(context.Background(), "secret")
	if err != nil {
		t.Fatal(err)
	}

	// Changing the PIN must invalidate existing page sessions.
	settingsBody, settingsCT := formBody(url.Values{
		"csrf": {csrf}, "mode": {"pin"}, "pin": {"999999"}, "title": {"Secret"},
	})
	resp = c.do(http.MethodPost, "dropy.test", "/sites/"+site.ID+"/update", settingsBody, settingsCT)
	if resp.Code != http.StatusSeeOther {
		t.Fatalf("settings update: %d %s", resp.Code, resp.Body.String())
	}
	resp = c.do(http.MethodGet, "pages.test", "/secret/", nil, "")
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("old session survived pin change: %d", resp.Code)
	}

	shareBody, shareCT := formBody(url.Values{"csrf": {csrf}, "days": {"1"}, "uses": {"0"}})
	resp = c.do(http.MethodPost, "dropy.test", "/sites/"+site.ID+"/share", shareBody, shareCT)
	if resp.Code != http.StatusOK {
		t.Fatalf("create share: %d %s", resp.Code, resp.Body.String())
	}
	m := regexp.MustCompile(`share=([A-Za-z0-9_-]+)`).FindStringSubmatch(resp.Body.String())
	if len(m) != 2 {
		t.Fatalf("share token not found in response: %s", resp.Body.String())
	}
	sm := regexp.MustCompile(`/shares/([a-f0-9]+)/revoke`).FindStringSubmatch(resp.Body.String())
	if len(sm) != 2 {
		t.Fatalf("share id not found in response: %s", resp.Body.String())
	}

	// New client without any page cookie.
	anon := &testClient{t: t, srv: c.srv, st: c.st, cookies: map[string]*http.Cookie{}}
	resp = anon.do(http.MethodGet, "pages.test", "/secret/?share="+m[1], nil, "")
	if resp.Code != http.StatusSeeOther || resp.Header().Get("Location") != "/secret/" {
		t.Fatalf("share redirect: %d %q", resp.Code, resp.Header().Get("Location"))
	}
	resp = anon.do(http.MethodGet, "pages.test", "/secret/", nil, "")
	if resp.Code != http.StatusOK || !strings.Contains(resp.Body.String(), "TOP SECRET") {
		t.Fatalf("share access: %d", resp.Code)
	}

	// Revoking the link must also invalidate sessions created by it.
	revokeBody, revokeCT := formBody(url.Values{"csrf": {csrf}, "site_id": {site.ID}})
	resp = c.do(http.MethodPost, "dropy.test", "/shares/"+sm[1]+"/revoke", revokeBody, revokeCT)
	if resp.Code != http.StatusSeeOther {
		t.Fatalf("revoke share: %d %s", resp.Code, resp.Body.String())
	}
	resp = anon.do(http.MethodGet, "pages.test", "/secret/", nil, "")
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("share session survived revocation: %d", resp.Code)
	}
}

func TestAPITokenVersionsAndRollback(t *testing.T) {
	c := newTestClient(t)
	csrf := c.login()
	tokenBody, tokenCT := formBody(url.Values{"csrf": {csrf}, "name": {"test"}})
	resp := c.do(http.MethodPost, "dropy.test", "/tokens", tokenBody, tokenCT)
	if resp.Code != http.StatusOK {
		t.Fatalf("create token: %d", resp.Code)
	}
	m := regexp.MustCompile(`dropy_[A-Za-z0-9_-]+`).FindString(resp.Body.String())
	if m == "" {
		t.Fatal("token not found")
	}
	bearer := func(req *http.Request) { req.Header.Set("Authorization", "Bearer "+m) }

	// API deploy v1.
	body, ct := multipartBody(t, map[string]string{"path": "api-demo", "title": "API", "mode": "public"}, "index.html", "<h1>v1</h1>")
	req := httptest.NewRequest(http.MethodPost, "http://dropy.test/api/sites", body)
	req.Header.Set("Content-Type", ct)
	bearer(req)
	rec := httptest.NewRecorder()
	c.srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("api deploy v1: %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Site apiSiteDTO `json:"site"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	// API deploy v2 (upsert).
	body, ct = multipartBody(t, map[string]string{"path": "api-demo", "mode": "public"}, "index.html", "<h1>v2</h1>")
	req = httptest.NewRequest(http.MethodPost, "http://dropy.test/api/sites", body)
	req.Header.Set("Content-Type", ct)
	bearer(req)
	rec = httptest.NewRecorder()
	c.srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("api deploy v2: %d %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "http://dropy.test/api/sites/"+created.Site.ID+"/versions", nil)
	bearer(req)
	rec = httptest.NewRecorder()
	c.srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("versions: %d %s", rec.Code, rec.Body.String())
	}
	var versions struct {
		Versions []apiVersionDTO `json:"versions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &versions); err != nil {
		t.Fatal(err)
	}
	if len(versions.Versions) != 2 {
		t.Fatalf("versions = %d", len(versions.Versions))
	}
	old := versions.Versions[1].ID

	req = httptest.NewRequest(http.MethodPost, "http://dropy.test/api/sites/"+created.Site.ID+"/rollback/"+old, nil)
	bearer(req)
	rec = httptest.NewRecorder()
	c.srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("rollback: %d %s", rec.Code, rec.Body.String())
	}
	resp = c.do(http.MethodGet, "pages.test", "/api-demo/", nil, "")
	if !strings.Contains(resp.Body.String(), "v1") {
		t.Fatalf("rollback content: %s", resp.Body.String())
	}
}

func TestZipBundle(t *testing.T) {
	c := newTestClient(t)
	csrf := c.login()
	z := makeTestZip(t, map[string]string{
		"site/index.html": "<!doctype html><link rel=stylesheet href=app.css><h1>zip</h1>",
		"site/app.css":    "h1{color:red}",
	})
	body, ct := multipartBody(t, map[string]string{"csrf": csrf, "path": "bundle", "mode": "public", "multi": "1"}, "bundle.zip", string(z))
	resp := c.do(http.MethodPost, "dropy.test", "/deploy", body, ct)
	if resp.Code != http.StatusSeeOther {
		t.Fatalf("zip deploy: %d %s", resp.Code, resp.Body.String())
	}
	resp = c.do(http.MethodGet, "pages.test", "/bundle/", nil, "")
	if resp.Code != http.StatusOK || !strings.Contains(resp.Body.String(), "zip") {
		t.Fatalf("zip page: %d %s", resp.Code, resp.Body.String())
	}
	resp = c.do(http.MethodGet, "pages.test", "/bundle/app.css", nil, "")
	if resp.Code != http.StatusOK || !strings.Contains(resp.Body.String(), "color:red") {
		t.Fatalf("zip asset: %d %s", resp.Code, resp.Body.String())
	}
	if ct := resp.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/css") {
		t.Fatalf("css content type = %q", ct)
	}
}

func TestAPIUpdateJSONPreservesAccess(t *testing.T) {
	c := newTestClient(t)
	csrf := c.login()
	tokenBody, tokenCT := formBody(url.Values{"csrf": {csrf}, "name": {"test"}})
	resp := c.do(http.MethodPost, "dropy.test", "/tokens", tokenBody, tokenCT)
	token := regexp.MustCompile(`dropy_[A-Za-z0-9_-]+`).FindString(resp.Body.String())
	if token == "" {
		t.Fatal("token not found")
	}
	bearer := func(req *http.Request) { req.Header.Set("Authorization", "Bearer "+token) }

	body, ct := multipartBody(t, map[string]string{"path": "p", "mode": "pin", "pin": "123456"}, "index.html", "<h1>p</h1>")
	req := httptest.NewRequest(http.MethodPost, "http://dropy.test/api/sites", body)
	req.Header.Set("Content-Type", ct)
	bearer(req)
	rec := httptest.NewRecorder()
	c.srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("deploy: %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Site apiSiteDTO `json:"site"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	req = httptest.NewRequest(http.MethodPut, "http://dropy.test/api/sites/"+created.Site.ID, strings.NewReader(`{"title":"Renamed"}`))
	req.Header.Set("Content-Type", "application/json")
	bearer(req)
	rec = httptest.NewRecorder()
	c.srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("update: %d %s", rec.Code, rec.Body.String())
	}
	var updated struct {
		Site apiSiteDTO `json:"site"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Site.AccessMode != "pin" || updated.Site.Title != "Renamed" {
		t.Fatalf("access mode/title not preserved: %+v", updated.Site)
	}
	resp = c.do(http.MethodGet, "pages.test", "/p/", nil, "")
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("page no longer protected: %d", resp.Code)
	}
}

func makeTestZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
