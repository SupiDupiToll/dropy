package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"dropy/internal/auth"
	"dropy/internal/config"
	"dropy/internal/store"
	"dropy/web"
)

const adminCookie = "dropy_admin"

type Server struct {
	cfg       *config.Config
	st        *store.Store
	adminOIDC *auth.Manager
	pagesOIDC *auth.Manager
	tpl       map[string]*template.Template
	gate      *template.Template
	static    http.Handler
	log       *slog.Logger
	limiter   *limiter
	adminMux  http.Handler
	pagesMux  http.Handler
}

type baseData struct {
	Title      string
	Page       string
	User       *store.AdminSession
	CSRF       string
	Msg        string
	Err        string
	AdminBase  string
	PublicBase string
	Dev        bool
	DevAuth    bool
	MultiFile  bool
	PagesOIDC  bool
}

func New(cfg *config.Config, st *store.Store, log *slog.Logger) (*Server, error) {
	for _, d := range []string{"", "versions", "tmp"} {
		if err := os.MkdirAll(filepath.Join(cfg.DataDir, d), 0o700); err != nil {
			return nil, err
		}
	}
	s := &Server{
		cfg:       cfg,
		st:        st,
		adminOIDC: auth.New(auth.Config{Issuer: cfg.AdminOIDC.Issuer, ClientID: cfg.AdminOIDC.ClientID, ClientSecret: cfg.AdminOIDC.ClientSecret, RedirectURL: cfg.AdminOIDC.RedirectURL, Scopes: cfg.AdminOIDC.Scopes}),
		pagesOIDC: auth.New(auth.Config{Issuer: cfg.PagesOIDC.Issuer, ClientID: cfg.PagesOIDC.ClientID, ClientSecret: cfg.PagesOIDC.ClientSecret, RedirectURL: cfg.PagesOIDC.RedirectURL, Scopes: cfg.PagesOIDC.Scopes}),
		log:       log,
		limiter:   newLimiter(0.15, 8),
	}

	funcs := template.FuncMap{
		"date":      formatDate,
		"dateShort": formatDateShort,
		"bytes":     formatBytes,
		"modeLabel": modeLabel,
		"modeClass": modeClass,
		"siteURL":   siteURL,
		"short":     short,
		"now":       func() int64 { return time.Now().Unix() },
	}
	pages := []string{"login", "dashboard", "edit", "versions", "error"}
	tpl := make(map[string]*template.Template, len(pages))
	for _, name := range pages {
		t, err := template.New(name+".html").Funcs(funcs).ParseFS(web.FS,
			"templates/layout.html", "templates/"+name+".html")
		if err != nil {
			return nil, fmt.Errorf("template %s: %w", name, err)
		}
		tpl[name] = t
	}
	gate, err := template.New("gate.html").ParseFS(web.FS, "templates/gate.html")
	if err != nil {
		return nil, err
	}
	s.tpl = tpl
	s.gate = gate

	staticFS, err := fs.Sub(web.FS, "static")
	if err != nil {
		return nil, err
	}
	s.static = http.StripPrefix("/static/", http.FileServer(http.FS(staticFS)))

	s.adminMux = s.buildAdminMux()
	s.pagesMux = http.HandlerFunc(s.handlePages)
	return s, nil
}

func (s *Server) Handler() http.Handler {
	return s.recoverer(s.accessLog(http.HandlerFunc(s.route)))
}

func (s *Server) route(w http.ResponseWriter, r *http.Request) {
	host := stripPort(strings.ToLower(r.Host))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")

	switch {
	case host == s.cfg.AdminHost || (s.cfg.Dev && isLocalHost(host)):
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		s.adminMux.ServeHTTP(w, r)
	case host == s.cfg.PagesHost:
		s.pagesMux.ServeHTTP(w, r)
	case s.cfg.Dev && strings.HasPrefix(r.URL.Path, "/__pages/"):
		clone := r.Clone(r.Context())
		u := *r.URL
		u.Path = strings.TrimPrefix(r.URL.Path, "/__pages")
		if u.Path == "" {
			u.Path = "/"
		}
		clone.URL = &u
		s.pagesMux.ServeHTTP(w, clone)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) buildAdminMux() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /static/", s.static)
	mux.HandleFunc("GET /login", s.handleLogin)
	mux.HandleFunc("GET /dev-login", s.handleDevLogin)
	mux.HandleFunc("GET /auth/callback", s.handleAdminCallback)
	mux.HandleFunc("POST /logout", s.requireAdmin(s.handleLogout))
	mux.HandleFunc("GET /healthz", s.handleHealth)

	mux.HandleFunc("GET /{$}", s.requireAdmin(s.handleDashboard))
	mux.HandleFunc("POST /deploy", s.requireAdmin(s.handleDeploy))
	mux.HandleFunc("GET /sites/{id}/edit", s.requireAdmin(s.handleEdit))
	mux.HandleFunc("POST /sites/{id}/update", s.requireAdmin(s.handleUpdate))
	mux.HandleFunc("POST /sites/{id}/delete", s.requireAdmin(s.handleDelete))
	mux.HandleFunc("GET /sites/{id}/versions", s.requireAdmin(s.handleVersions))
	mux.HandleFunc("POST /sites/{id}/rollback/{vid}", s.requireAdmin(s.handleRollback))
	mux.HandleFunc("GET /sites/{id}/versions/{vid}/download", s.requireAdmin(s.handleDownloadVersion))
	mux.HandleFunc("POST /sites/{id}/share", s.requireAdmin(s.handleCreateShare))
	mux.HandleFunc("POST /shares/{id}/revoke", s.requireAdmin(s.handleRevokeShare))
	mux.HandleFunc("POST /tokens", s.requireAdmin(s.handleCreateToken))
	mux.HandleFunc("POST /tokens/{id}/revoke", s.requireAdmin(s.handleRevokeToken))

	mux.HandleFunc("GET /api/sites", s.requireAPI(s.handleAPISites))
	mux.HandleFunc("POST /api/sites", s.requireAPI(s.handleAPIDeploy))
	mux.HandleFunc("PUT /api/sites/{id}", s.requireAPI(s.handleAPIUpdate))
	mux.HandleFunc("DELETE /api/sites/{id}", s.requireAPI(s.handleAPIDelete))
	mux.HandleFunc("GET /api/sites/{id}/versions", s.requireAPI(s.handleAPIVersions))
	mux.HandleFunc("POST /api/sites/{id}/rollback/{vid}", s.requireAPI(s.handleAPIRollback))
	return mux
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	t, ok := s.tpl[name]
	if !ok {
		http.Error(w, "template not found", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "layout", data); err != nil {
		s.log.Error("render", "template", name, "err", err)
	}
}

func (s *Server) renderGate(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(status)
	if err := s.gate.ExecuteTemplate(w, "gate.html", data); err != nil {
		s.log.Error("render gate", "err", err)
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}
func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		if sw.status == 0 {
			sw.status = 200
		}
		s.log.Info("http",
			"host", stripPort(r.Host),
			"method", r.Method,
			"path", r.URL.Path,
			"status", sw.status,
			"bytes", sw.bytes,
			"ms", time.Since(start).Milliseconds(),
			"ip", s.clientIP(r),
		)
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("panic", "err", rec, "stack", string(debug.Stack()))
				http.Error(w, "internal server error", 500)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type ctxKey int

const adminSessionKey ctxKey = 1
const apiViaTokenKey ctxKey = 2

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := s.adminSession(r)
		if sess == nil {
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				next := r.URL.RequestURI()
				if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
					next = "/"
				}
				http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusSeeOther)
				return
			}
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), adminSessionKey, sess)
		next(w, r.WithContext(ctx))
	}
}

func (s *Server) adminSession(r *http.Request) *store.AdminSession {
	c, err := r.Cookie(adminCookie)
	if err != nil || c.Value == "" {
		return nil
	}
	sess, err := s.st.GetAdminSession(r.Context(), sha256Hex(c.Value))
	if err != nil {
		s.log.Error("admin session", "err", err)
		return nil
	}
	return sess
}

func session(r *http.Request) *store.AdminSession {
	v, _ := r.Context().Value(adminSessionKey).(*store.AdminSession)
	return v
}

func (s *Server) checkCSRF(r *http.Request, sess *store.AdminSession) bool {
	if sess == nil {
		return false
	}
	token := r.Header.Get("X-CSRF-Token")
	if token == "" {
		token = r.FormValue("csrf")
	}
	if token == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(sess.CSRFToken)) == 1
}

func (s *Server) base(r *http.Request, sess *store.AdminSession, page, title string) baseData {
	return baseData{
		Title:      title,
		Page:       page,
		User:       sess,
		CSRF:       csrfOf(sess),
		Msg:        r.URL.Query().Get("msg"),
		Err:        r.URL.Query().Get("err"),
		AdminBase:  s.cfg.AdminBaseURL,
		PublicBase: s.cfg.PublicBaseURL,
		Dev:        s.cfg.Dev,
		DevAuth:    s.cfg.DevAuth,
		MultiFile:  s.cfg.EnableMultiFile,
		PagesOIDC:  s.pagesOIDC.Enabled(),
	}
}

func csrfOf(sess *store.AdminSession) string {
	if sess == nil {
		return ""
	}
	return sess.CSRFToken
}

func (s *Server) setAdminCookie(w http.ResponseWriter, token string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     adminCookie,
		Value:    token,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   s.cfg.SecureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxy {
		if ip := firstValidIP(r.Header.Get("CF-Connecting-IP")); ip != "" {
			return ip
		}
		if ip := firstValidIP(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0]); ip != "" {
			return ip
		}
		if ip := firstValidIP(r.Header.Get("X-Real-IP")); ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func firstValidIP(raw string) string {
	ip := strings.TrimSpace(raw)
	if net.ParseIP(ip) != nil {
		return ip
	}
	return ""
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.st.Ping(ctx); err != nil {
		http.Error(w, `{"status":"error"}`, http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) Cleanup(ctx context.Context) {
	_ = s.st.DeleteExpired(ctx, time.Now().Unix())
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = s.st.DeleteExpired(ctx, time.Now().Unix())
		}
	}
}

func redirectFlash(w http.ResponseWriter, r *http.Request, to, msg, errMsg string) {
	q := url.Values{}
	if msg != "" {
		q.Set("msg", msg)
	}
	if errMsg != "" {
		q.Set("err", errMsg)
	}
	if enc := q.Encode(); enc != "" {
		to += "?" + enc
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return strings.Trim(h, "[]")
	}
	return strings.Trim(host, "[]")
}

func isLocalHost(h string) bool {
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

func formatDate(ts int64) string {
	if ts <= 0 {
		return "—"
	}
	return time.Unix(ts, 0).Local().Format("02.01.2006 15:04")
}

func formatDateShort(ts int64) string {
	if ts <= 0 {
		return "—"
	}
	return time.Unix(ts, 0).Local().Format("02.01.2006")
}

func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

func modeLabel(mode string) string {
	switch mode {
	case "public":
		return "Öffentlich"
	case "pin":
		return "PIN"
	case "password":
		return "Passwort"
	case "pocketid":
		return "Pocket-ID"
	default:
		return mode
	}
}

func modeClass(mode string) string {
	switch mode {
	case "public", "pin", "password", "pocketid":
		return mode
	default:
		return "public"
	}
}

func siteURL(base, p string) string {
	return strings.TrimRight(base, "/") + "/" + strings.Trim(p, "/") + "/"
}

func short(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func parseInt(s string, def int64) int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return def
	}
	return n
}
