package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"dropy/internal/deploy"
	"dropy/internal/store"
	"dropy/internal/validate"
)

type apiSiteDTO struct {
	ID         string         `json:"id"`
	Path       string         `json:"path"`
	Title      string         `json:"title"`
	AccessMode string         `json:"access_mode"`
	URL        string         `json:"url"`
	CreatedAt  int64          `json:"created_at"`
	UpdatedAt  int64          `json:"updated_at"`
	Current    *apiVersionDTO `json:"current,omitempty"`
}

type apiVersionDTO struct {
	ID        string `json:"id"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
	FileCount int    `json:"file_count"`
	CreatedAt int64  `json:"created_at"`
}

func (s *Server) requireAPI(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		if strings.HasPrefix(authz, "Bearer ") {
			raw := strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))
			if raw != "" {
				tok, err := s.st.GetAPITokenByHash(r.Context(), sha256Hex(raw))
				if err != nil {
					s.log.Error("api token lookup", "err", err)
				} else if tok != nil {
					s.st.TouchAPIToken(r.Context(), tok.ID)
					next(w, r)
					return
				}
			}
			writeAPIError(w, http.StatusUnauthorized, "invalid token")
			return
		}
		sess := s.adminSession(r)
		if sess == nil {
			writeAPIError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			token := r.Header.Get("X-CSRF-Token")
			if token == "" {
				token = r.FormValue("csrf")
			}
			if subtle.ConstantTimeCompare([]byte(token), []byte(sess.CSRFToken)) != 1 {
				writeAPIError(w, http.StatusForbidden, "invalid csrf token")
				return
			}
		}
		next(w, r)
	}
}

func (s *Server) handleAPISites(w http.ResponseWriter, r *http.Request) {
	sites, err := s.st.ListSites(r.Context())
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "database error")
		return
	}
	out := make([]apiSiteDTO, 0, len(sites))
	for _, site := range sites {
		out = append(out, s.apiSite(site))
	}
	writeJSON(w, http.StatusOK, map[string]any{"sites": out})
}

func (s *Server) handleAPIDeploy(w http.ResponseWriter, r *http.Request) {
	in, err := s.readAPIInput(w, r, nil)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	if in != nil && in.file != nil {
		defer in.Close()
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	site, created, _, err := s.applyDeploy(ctx, nil, in)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, map[string]any{"created": created, "site": s.apiSite(site)})
}

func (s *Server) handleAPIUpdate(w http.ResponseWriter, r *http.Request) {
	site, err := s.st.GetSiteByID(r.Context(), r.PathValue("id"))
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "site not found")
		return
	}
	in, err := s.readAPIInput(w, r, site)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	if in != nil && in.file != nil {
		defer in.Close()
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	if in.settingsOnly {
		if err := s.applySettings(ctx, site, in); err != nil {
			writeAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
	} else {
		if _, _, _, err := s.applyDeploy(ctx, site, in); err != nil {
			writeAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	site, err = s.st.GetSiteByID(r.Context(), site.ID)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"site": s.apiSite(site)})
}

func (s *Server) handleAPIDelete(w http.ResponseWriter, r *http.Request) {
	site, err := s.st.GetSiteByID(r.Context(), r.PathValue("id"))
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "site not found")
		return
	}
	versions, _ := s.st.ListVersions(r.Context(), site.ID)
	if err := s.st.DeleteSite(r.Context(), site.ID); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	for _, v := range versions {
		_ = deploy.RemoveVersion(s.cfg.DataDir, v.ID)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAPIVersions(w http.ResponseWriter, r *http.Request) {
	site, err := s.st.GetSiteByID(r.Context(), r.PathValue("id"))
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "site not found")
		return
	}
	versions, err := s.st.ListVersions(r.Context(), site.ID)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "database error")
		return
	}
	out := make([]apiVersionDTO, 0, len(versions))
	for _, v := range versions {
		out = append(out, apiVersionDTO{ID: v.ID, SHA256: v.SHA256, Size: v.Size, FileCount: v.FileCount, CreatedAt: v.CreatedAt})
	}
	writeJSON(w, http.StatusOK, map[string]any{"versions": out, "current_version_id": site.CurrentVersionID})
}

func (s *Server) handleAPIRollback(w http.ResponseWriter, r *http.Request) {
	site, err := s.st.GetSiteByID(r.Context(), r.PathValue("id"))
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "site not found")
		return
	}
	vid := r.PathValue("vid")
	if _, err := s.st.GetVersion(r.Context(), site.ID, vid); err != nil {
		writeAPIError(w, http.StatusNotFound, "version not found")
		return
	}
	if err := s.st.SetCurrentVersion(r.Context(), site.ID, vid); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "rollback failed")
		return
	}
	site, _ = s.st.GetSiteByID(r.Context(), site.ID)
	if site != nil {
		s.pruneVersions(r.Context(), site)
	}
	writeJSON(w, http.StatusOK, map[string]any{"site": s.apiSite(site)})
}

func (s *Server) readAPIInput(w http.ResponseWriter, r *http.Request, existing *store.Site) (*uploadInput, error) {
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/json") {
		r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxHTMLBytes+(1<<20))
		var body struct {
			Path     string  `json:"path"`
			Title    *string `json:"title"`
			Mode     string  `json:"mode"`
			Access   string  `json:"access_mode"`
			PIN      string  `json:"pin"`
			Password string  `json:"password"`
			HTML     string  `json:"html"`
		}
		dec := json.NewDecoder(io.LimitReader(r.Body, s.cfg.MaxHTMLBytes+(1<<20)))
		if err := dec.Decode(&body); err != nil {
			return nil, err
		}
		mode := body.Mode
		if mode == "" {
			mode = body.Access
		}
		if mode == "" {
			if existing != nil {
				mode = existing.AccessMode
			} else {
				mode = "public"
			}
		}
		title := ""
		if body.Title != nil {
			title = *body.Title
		} else if existing != nil {
			title = existing.Title
		}
		form := deployForm{Path: body.Path, Title: validate.Title(title), Mode: mode, PIN: body.PIN, Password: body.Password, HTML: body.HTML}
		if existing == nil {
			p, err := validate.Path(form.Path)
			if err != nil {
				return nil, err
			}
			form.Path = p
		} else {
			form.Path = existing.Path
		}
		if err := validate.AccessMode(mode); err != nil {
			return nil, err
		}
		if len(body.HTML) > int(s.cfg.MaxHTMLBytes) {
			return nil, errors.New("html too large")
		}
		in := &uploadInput{Form: form}
		if body.HTML == "" && existing != nil {
			in.settingsOnly = true
		} else {
			in.html = []byte(body.HTML)
		}
		return in, nil
	}
	return s.readDeploy(w, r, existing)
}

func (s *Server) apiSite(site *store.Site) apiSiteDTO {
	dto := apiSiteDTO{
		ID: site.ID, Path: site.Path, Title: site.Title, AccessMode: site.AccessMode,
		URL: siteURL(s.cfg.PublicBaseURL, site.Path), CreatedAt: site.CreatedAt, UpdatedAt: site.UpdatedAt,
	}
	if site.Current != nil {
		dto.Current = &apiVersionDTO{ID: site.Current.ID, SHA256: site.Current.SHA256, Size: site.Current.Size, FileCount: site.Current.FileCount, CreatedAt: site.Current.CreatedAt}
	}
	return dto
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeAPIError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
