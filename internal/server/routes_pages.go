package server

import (
	"io"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"dropy/internal/secure"
	"dropy/internal/store"
	"dropy/internal/validate"
)

type gateData struct {
	Site        *store.Site
	PublicBase  string
	ActionURL   string
	PocketURL   string
	Error       string
	OIDCEnabled bool
}

func (s *Server) handlePages(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")

	if r.URL.Path == "/__auth/callback" {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handlePageCallback(w, r)
		return
	}
	if r.URL.Path == "/" || r.URL.Path == "" {
		s.pageNotFound(w, r)
		return
	}

	reqPath := path.Clean("/" + r.URL.Path)
	segs := strings.Split(strings.Trim(reqPath, "/"), "/")
	site, _ := s.resolveSite(r, segs)
	if site == nil {
		s.pageNotFound(w, r)
		return
	}
	canonical := siteURL("", site.Path)
	if r.URL.Path == "/"+site.Path {
		target := canonical
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		http.Redirect(w, r, target, http.StatusMovedPermanently)
		return
	}

	rest := strings.TrimPrefix(reqPath, "/"+site.Path)
	rest = strings.TrimPrefix(rest, "/")
	if strings.HasSuffix(r.URL.Path, "/") && rest == "" {
		rest = ""
	}
	rel := strings.TrimSuffix(rest, "/")

	// Share links work on any page within the site.
	if share := r.URL.Query().Get("share"); share != "" && rel != "__unlock" && rel != "__logout" && !strings.HasPrefix(rel, "__auth/") {
		if s.consumeShare(w, r, site, share) {
			return
		}
		if site.AccessMode != "public" {
			s.renderGate(w, http.StatusUnauthorized, s.gateData(site, "Share-Link ist ungültig oder abgelaufen."))
			return
		}
	}

	// Site-specific auth endpoints.
	switch rel {
	case "__unlock":
		s.handleUnlock(w, r, site, canonical)
		return
	case "__logout":
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.logoutPage(w, r, site)
		return
	case "__auth/pocketid":
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.startPageLogin(w, r, site, canonical)
		return
	}

	if site.AccessMode != "public" && !s.pageSessionValid(r, site) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.renderGate(w, http.StatusUnauthorized, s.gateData(site, ""))
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if site.Current == nil {
		s.pageNotFound(w, r)
		return
	}
	if rel == "" {
		rel = "index.html"
	}
	s.serveVersionFile(w, r, site, rel)
}

func (s *Server) resolveSite(r *http.Request, segs []string) (*store.Site, []string) {
	for i := len(segs); i >= 1; i-- {
		candidate := strings.Join(segs[:i], "/")
		site, err := s.st.GetSiteByPath(r.Context(), candidate)
		if err == nil && site != nil {
			return site, segs[:i]
		}
	}
	return nil, nil
}

func (s *Server) gateData(site *store.Site, errMsg string) gateData {
	canonical := siteURL("", site.Path)
	return gateData{
		Site:        site,
		PublicBase:  s.cfg.PublicBaseURL,
		ActionURL:   canonical + "__unlock",
		PocketURL:   canonical + "__auth/pocketid",
		Error:       errMsg,
		OIDCEnabled: s.pagesOIDC.Enabled(),
	}
}

func (s *Server) handleUnlock(w http.ResponseWriter, r *http.Request, site *store.Site, canonical string) {
	if site.AccessMode != "pin" && site.AccessMode != "password" {
		http.NotFound(w, r)
		return
	}
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		s.renderGate(w, http.StatusUnauthorized, s.gateData(site, ""))
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, HEAD, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if site.SecretHash == "" {
		s.renderGate(w, http.StatusForbidden, s.gateData(site, "Für diese Seite ist kein Geheimnis gesetzt."))
		return
	}
	key := "unlock|" + s.clientIP(r) + "|" + site.ID
	if !s.limiter.Allow(key) {
		w.Header().Set("Retry-After", "60")
		s.renderGate(w, http.StatusTooManyRequests, s.gateData(site, "Zu viele Versuche. Bitte kurz warten."))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	secret := r.FormValue("pin")
	if site.AccessMode == "password" {
		secret = r.FormValue("password")
	}
	if !secure.VerifySecret(site.SecretHash, strings.TrimSpace(secret)) {
		s.renderGate(w, http.StatusUnauthorized, s.gateData(site, "Das war nicht richtig. Bitte erneut versuchen."))
		return
	}
	s.limiter.Reset(key)
	if err := s.createPageSession(w, r, site, site.AccessMode, "", "", ""); err != nil {
		s.log.Error("create page session", "err", err)
		s.renderGate(w, http.StatusInternalServerError, s.gateData(site, "Session konnte nicht erstellt werden."))
		return
	}
	http.Redirect(w, r, canonical, http.StatusSeeOther)
}

func (s *Server) startPageLogin(w http.ResponseWriter, r *http.Request, site *store.Site, canonical string) {
	if site.AccessMode != "pocketid" || !s.pagesOIDC.Enabled() {
		http.NotFound(w, r)
		return
	}
	state, err := randomToken(32)
	if err != nil {
		http.Error(w, "internal error", 500)
		return
	}
	verifier, err := randomToken(32)
	if err != nil {
		http.Error(w, "internal error", 500)
		return
	}
	nonce, err := randomToken(24)
	if err != nil {
		http.Error(w, "internal error", 500)
		return
	}
	err = s.st.CreateOIDCState(r.Context(), &store.OIDCState{
		StateHash: sha256Hex(state), Kind: "page", SiteID: site.ID, ReturnTo: canonical,
		Nonce: nonce, CodeVerifier: verifier, ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
	})
	if err != nil {
		s.log.Error("page oidc state", "err", err)
		s.renderGate(w, http.StatusInternalServerError, s.gateData(site, "Login konnte nicht gestartet werden."))
		return
	}
	authURL, err := s.pagesOIDC.AuthCodeURL(r.Context(), state, nonce, verifier)
	if err != nil {
		s.log.Error("page oidc url", "err", err)
		s.renderGate(w, http.StatusBadGateway, s.gateData(site, "Pocket-ID ist nicht erreichbar."))
		return
	}
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

func (s *Server) handlePageCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		desc := q.Get("error_description")
		if desc == "" {
			desc = e
		}
		s.pageError(w, r, "Login abgebrochen: "+desc)
		return
	}
	state := q.Get("state")
	code := q.Get("code")
	if state == "" || code == "" {
		s.pageError(w, r, "Ungültiger Login-Callback.")
		return
	}
	st, err := s.st.ConsumeOIDCState(r.Context(), sha256Hex(state))
	if err != nil || st.Kind != "page" {
		s.pageError(w, r, "Login ist abgelaufen. Bitte erneut versuchen.")
		return
	}
	site, err := s.st.GetSiteByID(r.Context(), st.SiteID)
	if err != nil {
		s.pageError(w, r, "Seite nicht gefunden.")
		return
	}
	ident, err := s.pagesOIDC.Exchange(r.Context(), code, st.CodeVerifier, st.Nonce)
	if err != nil {
		s.log.Error("page oidc exchange", "err", err)
		s.renderGate(w, http.StatusUnauthorized, s.gateData(site, "Login fehlgeschlagen: "+err.Error()))
		return
	}
	if !allowed(ident, s.cfg.PagesEmails, s.cfg.PagesGroups) {
		s.renderGate(w, http.StatusForbidden, s.gateData(site, "Dieses Konto ist für diese Seite nicht freigegeben."))
		return
	}
	if err := s.createPageSession(w, r, site, "pocketid", ident.Sub, ident.Email, ""); err != nil {
		s.log.Error("page session", "err", err)
		s.renderGate(w, http.StatusInternalServerError, s.gateData(site, "Session konnte nicht erstellt werden."))
		return
	}
	target := st.ReturnTo
	if !strings.HasPrefix(target, "/"+site.Path) {
		target = siteURL("", site.Path)
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func (s *Server) consumeShare(w http.ResponseWriter, r *http.Request, site *store.Site, token string) bool {
	link, err := s.st.GetShareLinkByHash(r.Context(), sha256Hex(token))
	if err != nil || link == nil || link.SiteID != site.ID {
		return false
	}
	if err := s.st.IncrementShareUse(r.Context(), link.ID); err != nil {
		return false
	}
	expires := time.Now().Add(time.Duration(s.cfg.PageSessionHours) * time.Hour)
	if link.ExpiresAt < expires.Unix() {
		expires = time.Unix(link.ExpiresAt, 0)
	}
	if err := s.createPageSessionExpiring(w, r, site, "share", "", "", link.ID, expires); err != nil {
		return false
	}
	target := r.URL.Path
	if target == "/"+site.Path {
		target = siteURL("", site.Path)
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
	return true
}

func (s *Server) logoutPage(w http.ResponseWriter, r *http.Request, site *store.Site) {
	if c, err := r.Cookie(s.pageCookieName(site)); err == nil {
		_ = s.st.DeletePageSession(r.Context(), sha256Hex(c.Value))
	}
	s.setPageCookie(w, site, "", -1)
	http.Redirect(w, r, siteURL("", site.Path), http.StatusSeeOther)
}

func (s *Server) pageSessionValid(r *http.Request, site *store.Site) bool {
	c, err := r.Cookie(s.pageCookieName(site))
	if err != nil || c.Value == "" {
		return false
	}
	sess, err := s.st.GetPageSession(r.Context(), sha256Hex(c.Value), site.ID)
	return err == nil && sess != nil
}

func (s *Server) createPageSession(w http.ResponseWriter, r *http.Request, site *store.Site, method, sub, email, sourceID string) error {
	return s.createPageSessionExpiring(w, r, site, method, sub, email, sourceID, time.Now().Add(time.Duration(s.cfg.PageSessionHours)*time.Hour))
}

func (s *Server) createPageSessionExpiring(w http.ResponseWriter, r *http.Request, site *store.Site, method, sub, email, sourceID string, expires time.Time) error {
	token, err := randomToken(32)
	if err != nil {
		return err
	}
	now := time.Now()
	err = s.st.CreatePageSession(r.Context(), &store.PageSession{
		TokenHash: sha256Hex(token), SiteID: site.ID, Method: method,
		UserSub: sub, Email: email, SourceID: sourceID, CreatedAt: now.Unix(), ExpiresAt: expires.Unix(),
	})
	if err != nil {
		return err
	}
	s.setPageCookie(w, site, token, int(time.Until(expires).Seconds()))
	return nil
}

func (s *Server) pageCookieName(site *store.Site) string {
	return "dropy_s_" + site.ID
}

func (s *Server) setPageCookie(w http.ResponseWriter, site *store.Site, token string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.pageCookieName(site),
		Value:    token,
		Path:     siteURL("", site.Path),
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   s.cfg.SecureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) serveVersionFile(w http.ResponseWriter, r *http.Request, site *store.Site, rel string) {
	rel, err := validate.RelPath(rel)
	if err != nil {
		s.pageNotFound(w, r)
		return
	}
	if rel == "" {
		rel = "index.html"
	}
	full := filepath.Join(site.Current.Dir, filepath.FromSlash(rel))
	root, _ := filepath.Abs(site.Current.Dir)
	abs, err := filepath.Abs(full)
	if err != nil || (abs != root && !strings.HasPrefix(abs, root+string(filepath.Separator))) {
		s.pageNotFound(w, r)
		return
	}
	info, err := os.Stat(abs)
	if err != nil {
		s.pageNotFound(w, r)
		return
	}
	if info.IsDir() {
		if !strings.HasSuffix(r.URL.Path, "/") {
			http.Redirect(w, r, r.URL.Path+"/", http.StatusMovedPermanently)
			return
		}
		rel = strings.TrimSuffix(rel, "/") + "/index.html"
		full = filepath.Join(site.Current.Dir, filepath.FromSlash(rel))
		info, err = os.Stat(full)
		if err != nil || info.IsDir() {
			s.pageNotFound(w, r)
			return
		}
		abs = full
	}

	ct := contentType(abs)
	w.Header().Set("Content-Type", ct)
	w.Header().Set("ETag", `"`+site.Current.SHA256+"-"+short(sha256Hex(rel), 16)+`"`)
	if site.AccessMode == "public" {
		w.Header().Set("Cache-Control", "public, max-age=60, must-revalidate")
	} else {
		w.Header().Set("Cache-Control", "private, no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	}
	if strings.HasPrefix(ct, "text/html") {
		w.Header().Set("Content-Security-Policy", "sandbox allow-scripts allow-forms allow-popups allow-popups-to-escape-sandbox allow-modals allow-downloads allow-same-origin allow-top-navigation-by-user-activation")
	}
	if inm := r.Header.Get("If-None-Match"); inm != "" && inm == w.Header().Get("ETag") {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	f, err := os.Open(abs)
	if err != nil {
		s.pageNotFound(w, r)
		return
	}
	defer f.Close()
	http.ServeContent(w, r, info.Name(), info.ModTime(), f)
}

func contentType(name string) string {
	ext := strings.ToLower(filepath.Ext(name))
	ct := mime.TypeByExtension(ext)
	if ct == "" {
		switch ext {
		case ".wasm":
			ct = "application/wasm"
		case ".map", ".json":
			ct = "application/json"
		case ".md":
			ct = "text/markdown"
		case ".txt":
			ct = "text/plain"
		default:
			ct = "application/octet-stream"
		}
	}
	if strings.HasPrefix(ct, "text/") || ct == "application/javascript" || ct == "application/json" || ct == "image/svg+xml" || ct == "application/xml" {
		if !strings.Contains(ct, "charset=") {
			ct += "; charset=utf-8"
		}
	}
	return ct
}

func (s *Server) pageNotFound(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNotFound)
	io.WriteString(w, `<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>404 · dropy</title><style>body{margin:0;min-height:100svh;display:grid;place-items:center;background:#f7f8f8;color:#0c0e0f;font-family:ui-sans-serif,system-ui,sans-serif;padding:24px}.box{max-width:430px;text-align:center}.code{font-size:3.5rem;font-weight:600;letter-spacing:-.04em;color:#0c0e0f;line-height:1}.box p{color:#5c666c;line-height:1.55}.box a{display:inline-block;margin-top:10px;color:#0c0e0f;font-weight:500;text-decoration:underline;text-underline-offset:2px}@media(prefers-color-scheme:dark){body{background:#0b0d0e;color:#eef1f2}.code{color:#eef1f2}.box p{color:#a2acb2}.box a{color:#eef1f2}}</style></head><body><div class="box"><div class="code">404</div><p>Diese Seite gibt es nicht (oder noch nicht).</p><a href="/">dropy</a></div></body></html>`)
}

func (s *Server) pageError(w http.ResponseWriter, r *http.Request, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusBadRequest)
	io.WriteString(w, `<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Login fehlgeschlagen</title><style>body{margin:0;min-height:100svh;display:grid;place-items:center;background:#f7f8f8;color:#0c0e0f;font-family:ui-sans-serif,system-ui,sans-serif;padding:24px}.box{max-width:430px;background:#fff;border:1px solid #e3e7e8;border-radius:12px;padding:26px;text-align:center}.box h1{font-size:1.125rem;letter-spacing:-.02em}.box p{color:#5c666c}@media(prefers-color-scheme:dark){body{background:#0b0d0e;color:#eef1f2}.box{background:#121516;border-color:#262b2d}.box p{color:#a2acb2}}</style></head><body><div class="box"><h1>Login fehlgeschlagen</h1><p>`+htmlEscape(msg)+`</p></div></body></html>`)
}

func htmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;").Replace(s)
}
