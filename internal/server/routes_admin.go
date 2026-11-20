package server

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"dropy/internal/auth"
	"dropy/internal/deploy"
	"dropy/internal/store"
)

type dashboardData struct {
	baseData
	Sites    []*store.Site
	Tokens   []*store.APIToken
	Form     deployForm
	NewToken string
}

type editData struct {
	baseData
	Site        *store.Site
	Content     string
	IsBundle    bool
	Shares      []*store.ShareLink
	NewShareURL string
}

type versionsData struct {
	baseData
	Site     *store.Site
	Versions []*store.Version
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.adminSession(r) != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if !s.adminOIDC.Enabled() {
		s.render(w, "login", baseData{Title: "Anmelden", Page: "login", Err: "Admin-OIDC ist nicht konfiguriert.", DevAuth: s.cfg.DevAuth})
		return
	}
	state, err := randomToken(32)
	if err != nil {
		s.render(w, "login", baseData{Title: "Anmelden", Page: "login", Err: "Interner Fehler.", DevAuth: s.cfg.DevAuth})
		return
	}
	verifier, err := randomToken(32)
	if err != nil {
		s.render(w, "login", baseData{Title: "Anmelden", Page: "login", Err: "Interner Fehler.", DevAuth: s.cfg.DevAuth})
		return
	}
	nonce, err := randomToken(24)
	if err != nil {
		s.render(w, "login", baseData{Title: "Anmelden", Page: "login", Err: "Interner Fehler.", DevAuth: s.cfg.DevAuth})
		return
	}
	next := safeNext(r.URL.Query().Get("next"))
	err = s.st.CreateOIDCState(r.Context(), &store.OIDCState{
		StateHash: sha256Hex(state), Kind: "admin", ReturnTo: next,
		Nonce: nonce, CodeVerifier: verifier, ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
	})
	if err != nil {
		s.log.Error("create oidc state", "err", err)
		s.render(w, "login", baseData{Title: "Anmelden", Page: "login", Err: "Login konnte nicht gestartet werden.", DevAuth: s.cfg.DevAuth})
		return
	}
	authURL, err := s.adminOIDC.AuthCodeURL(r.Context(), state, nonce, verifier)
	if err != nil {
		s.log.Error("oidc auth url", "err", err)
		s.render(w, "login", baseData{Title: "Anmelden", Page: "login", Err: "Pocket-ID ist nicht erreichbar: " + err.Error(), DevAuth: s.cfg.DevAuth})
		return
	}
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

func (s *Server) handleAdminCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		desc := q.Get("error_description")
		if desc == "" {
			desc = e
		}
		s.render(w, "login", baseData{Title: "Anmelden", Page: "login", Err: "Login abgebrochen: " + desc, DevAuth: s.cfg.DevAuth})
		return
	}
	state := q.Get("state")
	code := q.Get("code")
	if state == "" || code == "" {
		s.render(w, "login", baseData{Title: "Anmelden", Page: "login", Err: "Ungültiger Login-Callback.", DevAuth: s.cfg.DevAuth})
		return
	}
	st, err := s.st.ConsumeOIDCState(r.Context(), sha256Hex(state))
	if err != nil {
		s.render(w, "login", baseData{Title: "Anmelden", Page: "login", Err: "Login ist abgelaufen. Bitte erneut versuchen.", DevAuth: s.cfg.DevAuth})
		return
	}
	if st.Kind != "admin" {
		s.render(w, "login", baseData{Title: "Anmelden", Page: "login", Err: "Ungültiger Login-Status.", DevAuth: s.cfg.DevAuth})
		return
	}
	ident, err := s.adminOIDC.Exchange(r.Context(), code, st.CodeVerifier, st.Nonce)
	if err != nil {
		s.log.Error("oidc exchange", "err", err)
		s.render(w, "login", baseData{Title: "Anmelden", Page: "login", Err: "Login fehlgeschlagen: " + err.Error(), DevAuth: s.cfg.DevAuth})
		return
	}
	if !allowed(ident, s.cfg.AdminEmails, s.cfg.AdminGroups) {
		s.render(w, "login", baseData{Title: "Anmelden", Page: "login", Err: "Dieses Konto ist nicht für dropy freigegeben.", DevAuth: s.cfg.DevAuth})
		return
	}
	if err := s.startAdminSession(w, r, ident); err != nil {
		s.log.Error("admin session", "err", err)
		s.render(w, "login", baseData{Title: "Anmelden", Page: "login", Err: "Session konnte nicht erstellt werden.", DevAuth: s.cfg.DevAuth})
		return
	}
	http.Redirect(w, r, safeNext(st.ReturnTo), http.StatusSeeOther)
}

func (s *Server) handleDevLogin(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.DevAuth {
		http.NotFound(w, r)
		return
	}
	ident := &auth.Identity{Sub: "dev", Email: "dev@localhost", Name: "Entwickler"}
	if err := s.startAdminSession(w, r, ident); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	http.Redirect(w, r, safeNext(r.URL.Query().Get("next")), http.StatusSeeOther)
}

func (s *Server) startAdminSession(w http.ResponseWriter, r *http.Request, ident *auth.Identity) error {
	token, err := randomToken(32)
	if err != nil {
		return err
	}
	csrf, err := randomToken(32)
	if err != nil {
		return err
	}
	now := time.Now()
	expires := now.Add(time.Duration(s.cfg.SessionDays) * 24 * time.Hour)
	err = s.st.CreateAdminSession(r.Context(), &store.AdminSession{
		TokenHash: sha256Hex(token), UserSub: ident.Sub, Email: ident.Email, Name: ident.Name,
		CSRFToken: csrf, CreatedAt: now.Unix(), ExpiresAt: expires.Unix(),
	})
	if err != nil {
		return err
	}
	s.setAdminCookie(w, token, int(time.Until(expires).Seconds()))
	return nil
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	sess := session(r)
	if !s.checkCSRF(r, sess) {
		http.Error(w, "invalid csrf", http.StatusForbidden)
		return
	}
	if c, err := r.Cookie(adminCookie); err == nil {
		_ = s.st.DeleteAdminSession(r.Context(), sha256Hex(c.Value))
	}
	s.setAdminCookie(w, "", -1)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	s.renderDashboard(w, r, session(r), deployForm{Mode: "public"}, "", "", "")
}

func (s *Server) renderDashboard(w http.ResponseWriter, r *http.Request, sess *store.AdminSession, form deployForm, newToken, msg, errMsg string) {
	sites, err := s.st.ListSites(r.Context())
	if err != nil {
		s.log.Error("list sites", "err", err)
		http.Error(w, "database error", 500)
		return
	}
	tokens, err := s.st.ListAPITokens(r.Context())
	if err != nil {
		s.log.Error("list tokens", "err", err)
		http.Error(w, "database error", 500)
		return
	}
	if form.Mode == "" {
		form.Mode = "public"
	}
	d := dashboardData{
		baseData: s.base(r, sess, "dashboard", "Seiten"),
		Sites:    sites, Tokens: tokens, Form: form, NewToken: newToken,
	}
	if msg != "" {
		d.Msg = msg
	}
	if errMsg != "" {
		d.Err = errMsg
	}
	s.render(w, "dashboard", d)
}

func (s *Server) handleDeploy(w http.ResponseWriter, r *http.Request) {
	sess := session(r)
	s.limitUploadBody(w, r)
	if !s.checkCSRF(r, sess) {
		http.Error(w, "invalid csrf", http.StatusForbidden)
		return
	}
	in, err := s.readDeploy(w, r, nil)
	if err != nil {
		s.renderDashboard(w, r, sess, deployFormFromRequest(r), "", "", err.Error())
		return
	}
	defer in.Close()
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	site, created, _, err := s.applyDeploy(ctx, nil, in)
	if err != nil {
		s.renderDashboard(w, r, sess, in.Form, "", "", err.Error())
		return
	}
	action := "Deployed"
	if !created {
		action = "Aktualisiert"
	}
	redirectFlash(w, r, "/", action+": "+siteURL(s.cfg.PublicBaseURL, site.Path), "")
}

func (s *Server) handleEdit(w http.ResponseWriter, r *http.Request) {
	sess := session(r)
	site, err := s.st.GetSiteByID(r.Context(), r.PathValue("id"))
	if err != nil {
		redirectFlash(w, r, "/", "", "Seite nicht gefunden")
		return
	}
	s.renderEdit(w, r, sess, site, "", "", "", "")
}

func (s *Server) renderEdit(w http.ResponseWriter, r *http.Request, sess *store.AdminSession, site *store.Site, contentOverride, newShare, msg, errMsg string) {
	content := contentOverride
	isBundle := site.Current != nil && site.Current.FileCount > 1
	if content == "" && site.Current != nil && !isBundle {
		f, err := os.Open(filepath.Join(site.Current.Dir, "index.html"))
		if err == nil {
			data, rerr := io.ReadAll(io.LimitReader(f, s.cfg.MaxHTMLBytes+1))
			f.Close()
			if rerr == nil {
				content = string(data)
			}
		}
	}
	shares, err := s.st.ListShareLinks(r.Context(), site.ID)
	if err != nil {
		s.log.Error("list shares", "err", err)
	}
	d := editData{
		baseData: s.base(r, sess, "edit", "Bearbeiten"),
		Site:     site, Content: content, IsBundle: isBundle, Shares: shares, NewShareURL: newShare,
	}
	if msg != "" {
		d.Msg = msg
	}
	if errMsg != "" {
		d.Err = errMsg
	}
	s.render(w, "edit", d)
}

func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	sess := session(r)
	s.limitUploadBody(w, r)
	if !s.checkCSRF(r, sess) {
		http.Error(w, "invalid csrf", http.StatusForbidden)
		return
	}
	site, err := s.st.GetSiteByID(r.Context(), r.PathValue("id"))
	if err != nil {
		redirectFlash(w, r, "/", "", "Seite nicht gefunden")
		return
	}
	in, err := s.readDeploy(w, r, site)
	if err != nil {
		s.renderEdit(w, r, sess, site, deployFormFromRequest(r).HTML, "", "", err.Error())
		return
	}
	defer in.Close()
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	if in.settingsOnly {
		if err := s.applySettings(ctx, site, in); err != nil {
			s.renderEdit(w, r, sess, site, "", "", "", err.Error())
			return
		}
		redirectFlash(w, r, "/sites/"+site.ID+"/edit", "Einstellungen gespeichert", "")
		return
	}
	if _, _, _, err := s.applyDeploy(ctx, site, in); err != nil {
		s.renderEdit(w, r, sess, site, string(in.html), "", "", err.Error())
		return
	}
	redirectFlash(w, r, "/sites/"+site.ID+"/edit", "Neue Version deployed", "")
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	sess := session(r)
	if !s.checkCSRF(r, sess) {
		http.Error(w, "invalid csrf", http.StatusForbidden)
		return
	}
	site, err := s.st.GetSiteByID(r.Context(), r.PathValue("id"))
	if err != nil {
		redirectFlash(w, r, "/", "", "Seite nicht gefunden")
		return
	}
	versions, _ := s.st.ListVersions(r.Context(), site.ID)
	if err := s.st.DeleteSite(r.Context(), site.ID); err != nil {
		redirectFlash(w, r, "/", "", "Löschen fehlgeschlagen: "+err.Error())
		return
	}
	for _, v := range versions {
		if err := deploy.RemoveVersion(s.cfg.DataDir, v.ID); err != nil {
			s.log.Warn("remove version", "id", v.ID, "err", err)
		}
	}
	redirectFlash(w, r, "/", "Seite gelöscht: "+site.Path, "")
}

func (s *Server) handleVersions(w http.ResponseWriter, r *http.Request) {
	sess := session(r)
	site, err := s.st.GetSiteByID(r.Context(), r.PathValue("id"))
	if err != nil {
		redirectFlash(w, r, "/", "", "Seite nicht gefunden")
		return
	}
	versions, err := s.st.ListVersions(r.Context(), site.ID)
	if err != nil {
		http.Error(w, "database error", 500)
		return
	}
	s.render(w, "versions", versionsData{baseData: s.base(r, sess, "versions", "Versionen"), Site: site, Versions: versions})
}

func (s *Server) handleRollback(w http.ResponseWriter, r *http.Request) {
	sess := session(r)
	if !s.checkCSRF(r, sess) {
		http.Error(w, "invalid csrf", http.StatusForbidden)
		return
	}
	site, err := s.st.GetSiteByID(r.Context(), r.PathValue("id"))
	if err != nil {
		redirectFlash(w, r, "/", "", "Seite nicht gefunden")
		return
	}
	vid := r.PathValue("vid")
	if _, err := s.st.GetVersion(r.Context(), site.ID, vid); err != nil {
		redirectFlash(w, r, "/sites/"+site.ID+"/versions", "", "Version nicht gefunden")
		return
	}
	if err := s.st.SetCurrentVersion(r.Context(), site.ID, vid); err != nil {
		redirectFlash(w, r, "/sites/"+site.ID+"/versions", "", "Rollback fehlgeschlagen")
		return
	}
	if site, err := s.st.GetSiteByID(r.Context(), site.ID); err == nil {
		s.pruneVersions(r.Context(), site)
	}
	redirectFlash(w, r, "/sites/"+site.ID+"/versions", "Rollback durchgeführt", "")
}

func (s *Server) handleDownloadVersion(w http.ResponseWriter, r *http.Request) {
	site, err := s.st.GetSiteByID(r.Context(), r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	v, err := s.st.GetVersion(r.Context(), site.ID, r.PathValue("vid"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-%s.zip"`, strings.ReplaceAll(site.Path, "/", "-"), short(v.ID, 8)))
	w.Header().Set("Cache-Control", "no-store")
	zw := zip.NewWriter(w)
	defer zw.Close()
	err = filepath.WalkDir(v.Dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(v.Dir, p)
		if err != nil {
			return err
		}
		hdr, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		hdr.Method = zip.Deflate
		fw, err := zw.CreateHeader(hdr)
		if err != nil {
			return err
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		_, err = io.Copy(fw, f)
		f.Close()
		return err
	})
	if err != nil {
		s.log.Warn("download version", "err", err)
	}
}

func (s *Server) handleCreateShare(w http.ResponseWriter, r *http.Request) {
	sess := session(r)
	if !s.checkCSRF(r, sess) {
		http.Error(w, "invalid csrf", http.StatusForbidden)
		return
	}
	site, err := s.st.GetSiteByID(r.Context(), r.PathValue("id"))
	if err != nil {
		redirectFlash(w, r, "/", "", "Seite nicht gefunden")
		return
	}
	days := parseInt(r.FormValue("days"), 7)
	if days < 1 {
		days = 1
	}
	if days > 365 {
		days = 365
	}
	uses := parseInt(r.FormValue("uses"), 0)
	if uses < 0 {
		uses = 0
	}
	token, err := randomToken(32)
	if err != nil {
		http.Error(w, "internal error", 500)
		return
	}
	id := store.NewID()
	err = s.st.CreateShareLink(r.Context(), id, site.ID, sha256Hex(token), time.Now().Add(time.Duration(days)*24*time.Hour).Unix(), uses)
	if err != nil {
		s.renderEdit(w, r, sess, site, "", "", "", "Share-Link konnte nicht erstellt werden")
		return
	}
	url := siteURL(s.cfg.PublicBaseURL, site.Path) + "?share=" + token
	s.renderEdit(w, r, sess, site, "", url, "Share-Link erstellt", "")
}

func (s *Server) handleRevokeShare(w http.ResponseWriter, r *http.Request) {
	sess := session(r)
	if !s.checkCSRF(r, sess) {
		http.Error(w, "invalid csrf", http.StatusForbidden)
		return
	}
	siteID := r.FormValue("site_id")
	if err := s.st.RevokeShareLink(r.Context(), r.PathValue("id")); err != nil {
		redirectFlash(w, r, "/sites/"+siteID+"/edit", "", "Widerrufen fehlgeschlagen")
		return
	}
	redirectFlash(w, r, "/sites/"+siteID+"/edit", "Share-Link widerrufen", "")
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	sess := session(r)
	if !s.checkCSRF(r, sess) {
		http.Error(w, "invalid csrf", http.StatusForbidden)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		s.renderDashboard(w, r, sess, deployForm{Mode: "public"}, "", "", "Bitte einen Namen für den Token angeben")
		return
	}
	raw, err := randomToken(32)
	if err != nil {
		http.Error(w, "internal error", 500)
		return
	}
	token := "dropy_" + raw
	if err := s.st.CreateAPIToken(r.Context(), store.NewID(), name, sha256Hex(token)); err != nil {
		s.renderDashboard(w, r, sess, deployForm{Mode: "public"}, "", "", "Token konnte nicht erstellt werden")
		return
	}
	s.renderDashboard(w, r, sess, deployForm{Mode: "public"}, token, "Token erstellt — jetzt kopieren", "")
}

func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	sess := session(r)
	if !s.checkCSRF(r, sess) {
		http.Error(w, "invalid csrf", http.StatusForbidden)
		return
	}
	if err := s.st.RevokeAPIToken(r.Context(), r.PathValue("id")); err != nil {
		redirectFlash(w, r, "/", "", "Token konnte nicht widerrufen werden")
		return
	}
	redirectFlash(w, r, "/", "Token widerrufen", "")
}

func deployFormFromRequest(r *http.Request) deployForm {
	return deployForm{
		Path:     r.FormValue("path"),
		Title:    r.FormValue("title"),
		Mode:     r.FormValue("mode"),
		PIN:      r.FormValue("pin"),
		Password: r.FormValue("password"),
		HTML:     r.FormValue("html"),
	}
}

func safeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		return "/"
	}
	return next
}

func allowed(ident *auth.Identity, emails, groups []string) bool {
	if len(emails) == 0 && len(groups) == 0 {
		return true
	}
	email := strings.ToLower(ident.Email)
	for _, e := range emails {
		if strings.EqualFold(e, email) {
			return true
		}
	}
	for _, g := range groups {
		for _, userGroup := range ident.Groups {
			if strings.EqualFold(g, userGroup) {
				return true
			}
		}
	}
	return false
}
