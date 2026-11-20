package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestDeploymentsAndSettings(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	v1 := &Version{ID: "v1", Dir: "/tmp/v1", Entrypoint: "index.html", SHA256: "aaa", Size: 3, FileCount: 1}
	site, created, err := s.CreateDeployment(ctx, "demo", "Demo", "public", "", v1)
	if err != nil {
		t.Fatal(err)
	}
	if !created || site.ID == "" || site.Current == nil || site.Current.ID != "v1" {
		t.Fatalf("unexpected site: %+v", site)
	}
	got, err := s.GetSiteByPath(ctx, "DEMO")
	if err != nil || got.ID != site.ID {
		t.Fatalf("GetSiteByPath: %+v %v", got, err)
	}

	if err := s.UpdateSettings(ctx, site.ID, "Neu", "pin", "hash", true); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetSiteByID(ctx, site.ID)
	if got.Title != "Neu" || got.AccessMode != "pin" || got.SecretHash != "hash" {
		t.Fatalf("settings not updated: %+v", got)
	}

	v2 := &Version{ID: "v2", Dir: "/tmp/v2", Entrypoint: "index.html", SHA256: "bbb", Size: 4, FileCount: 1}
	site, created, err = s.CreateDeployment(ctx, "demo", "Demo 2", "public", "", v2)
	if err != nil || created {
		t.Fatalf("update deployment: created=%v err=%v", created, err)
	}
	versions, err := s.ListVersions(ctx, site.ID)
	if err != nil || len(versions) != 2 {
		t.Fatalf("versions: %d %v", len(versions), err)
	}
	if versions[0].ID != "v2" {
		t.Fatalf("newest version = %s", versions[0].ID)
	}
	if err := s.SetCurrentVersion(ctx, site.ID, "v1"); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetSiteByID(ctx, site.ID)
	if got.CurrentVersionID != "v1" {
		t.Fatalf("rollback failed: %+v", got)
	}
	if err := s.DeleteSite(ctx, site.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSiteByID(ctx, site.ID); err == nil {
		t.Fatal("site still exists")
	}
}

func TestSessionsAndTokens(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	now := time.Now().Unix()

	as := &AdminSession{TokenHash: "ah", UserSub: "u", Email: "e@example.com", Name: "N", CSRFToken: "csrf", CreatedAt: now, ExpiresAt: now + 100}
	if err := s.CreateAdminSession(ctx, as); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetAdminSession(ctx, "ah")
	if err != nil || got == nil || got.Email != "e@example.com" {
		t.Fatalf("admin session: %+v %v", got, err)
	}
	if err := s.DeleteAdminSession(ctx, "ah"); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetAdminSession(ctx, "ah")
	if got != nil {
		t.Fatal("admin session not deleted")
	}

	ps := &PageSession{TokenHash: "ph", Method: "pin", CreatedAt: now, ExpiresAt: now + 100}
	v := &Version{ID: "v1", Dir: "/tmp/v1", Entrypoint: "index.html", SHA256: "a", Size: 1, FileCount: 1}
	if _, _, err := s.CreateDeployment(ctx, "demo", "", "public", "", v); err != nil {
		t.Fatal(err)
	}
	site, err := s.GetSiteByPath(ctx, "demo")
	if err != nil {
		t.Fatal(err)
	}
	ps.SiteID = site.ID
	if err := s.CreatePageSession(ctx, ps); err != nil {
		t.Fatal(err)
	}
	p, err := s.GetPageSession(ctx, "ph", site.ID)
	if err != nil || p == nil || p.Method != "pin" {
		t.Fatalf("page session: %+v %v", p, err)
	}
	if err := s.UpdateSettings(ctx, site.ID, "", "password", "newhash", true); err != nil {
		t.Fatal(err)
	}
	p, _ = s.GetPageSession(ctx, "ph", site.ID)
	if p != nil {
		t.Fatal("page session survived access-mode change")
	}

	if err := s.CreateOIDCState(ctx, &OIDCState{StateHash: "sh", Kind: "admin", ReturnTo: "/", Nonce: "n", CodeVerifier: "v", ExpiresAt: now + 100}); err != nil {
		t.Fatal(err)
	}
	st, err := s.ConsumeOIDCState(ctx, "sh")
	if err != nil || st.Nonce != "n" {
		t.Fatalf("oidc state: %+v %v", st, err)
	}
	if _, err := s.ConsumeOIDCState(ctx, "sh"); err == nil {
		t.Fatal("oidc state reusable")
	}

	if err := s.CreateAPIToken(ctx, "t1", "laptop", "th"); err != nil {
		t.Fatal(err)
	}
	tok, err := s.GetAPITokenByHash(ctx, "th")
	if err != nil || tok == nil || tok.Name != "laptop" {
		t.Fatalf("token: %+v %v", tok, err)
	}
	if err := s.RevokeAPIToken(ctx, "t1"); err != nil {
		t.Fatal(err)
	}
	tok, _ = s.GetAPITokenByHash(ctx, "th")
	if tok != nil {
		t.Fatal("revoked token returned")
	}
}

func TestShareLinks(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	v := &Version{ID: "v1", Dir: "/tmp/v1", Entrypoint: "index.html", SHA256: "a", Size: 1, FileCount: 1}
	site, _, err := s.CreateDeployment(ctx, "demo", "", "public", "", v)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if err := s.CreateShareLink(ctx, "l1", site.ID, "lh", now+100, 1); err != nil {
		t.Fatal(err)
	}
	l, err := s.GetShareLinkByHash(ctx, "lh")
	if err != nil || l == nil {
		t.Fatalf("share link: %+v %v", l, err)
	}
	if err := s.IncrementShareUse(ctx, "l1"); err != nil {
		t.Fatal(err)
	}
	l, _ = s.GetShareLinkByHash(ctx, "lh")
	if l != nil {
		t.Fatal("used-up share link still valid")
	}
	if err := s.CreateShareLink(ctx, "l2", site.ID, "lh2", now+100, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePageSession(ctx, &PageSession{TokenHash: "shareph", SiteID: site.ID, Method: "share", SourceID: "l2", CreatedAt: now, ExpiresAt: now + 100}); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeShareLink(ctx, "l2"); err != nil {
		t.Fatal(err)
	}
	l, _ = s.GetShareLinkByHash(ctx, "lh2")
	if l != nil {
		t.Fatal("revoked share link still valid")
	}
	if p, _ := s.GetPageSession(ctx, "shareph", site.ID); p != nil {
		t.Fatal("share session survived revocation")
	}
}
