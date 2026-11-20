package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"

	"dropy/internal/deploy"
	"dropy/internal/secure"
	"dropy/internal/store"
	"dropy/internal/validate"
)

type deployForm struct {
	Path     string
	Title    string
	Mode     string
	PIN      string
	Password string
	HTML     string
}

type uploadInput struct {
	Form         deployForm
	file         multipart.File
	header       *multipart.FileHeader
	zip          bool
	html         []byte
	settingsOnly bool
}

func (u *uploadInput) Close() {
	if u.file != nil {
		u.file.Close()
	}
}

func (s *Server) limitUploadBody(w http.ResponseWriter, r *http.Request) {
	max := s.cfg.MaxHTMLBytes
	if s.cfg.EnableMultiFile {
		max = s.cfg.MaxZipBytes
	}
	r.Body = http.MaxBytesReader(w, r.Body, max+(2<<20))
}

func (s *Server) readDeploy(w http.ResponseWriter, r *http.Request, existing *store.Site) (*uploadInput, error) {
	max := s.cfg.MaxHTMLBytes
	if s.cfg.EnableMultiFile {
		max = s.cfg.MaxZipBytes
	}
	r.Body = http.MaxBytesReader(w, r.Body, max+(2<<20))
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		if err := r.ParseMultipartForm(16 << 20); err != nil {
			return nil, fmt.Errorf("Upload konnte nicht gelesen werden: %w", err)
		}
	} else if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("Formular konnte nicht gelesen werden: %w", err)
	}
	in := &uploadInput{}
	rawMode := strings.TrimSpace(r.FormValue("mode"))
	in.Form = deployForm{
		Path:     r.FormValue("path"),
		Title:    validate.Title(r.FormValue("title")),
		Mode:     rawMode,
		PIN:      r.FormValue("pin"),
		Password: r.FormValue("password"),
		HTML:     r.FormValue("html"),
	}
	if in.Form.Mode == "" {
		if existing != nil {
			in.Form.Mode = existing.AccessMode
		} else {
			in.Form.Mode = "public"
		}
	}
	if err := validate.AccessMode(in.Form.Mode); err != nil {
		return nil, err
	}

	var f multipart.File
	var fh *multipart.FileHeader
	var err error
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		f, fh, err = r.FormFile("file")
	} else {
		err = http.ErrMissingFile
	}
	switch {
	case err == nil:
		in.file = f
		in.header = fh
	case errors.Is(err, http.ErrMissingFile):
	default:
		return nil, fmt.Errorf("Datei konnte nicht gelesen werden: %w", err)
	}

	if existing != nil {
		in.Form.Path = existing.Path
	} else if strings.TrimSpace(in.Form.Path) == "" && in.header != nil && !strings.HasSuffix(strings.ToLower(in.header.Filename), ".zip") {
		in.Form.Path = validate.SlugFromFilename(in.header.Filename)
	}

	if existing == nil {
		p, err := validate.Path(in.Form.Path)
		if err != nil {
			return nil, err
		}
		in.Form.Path = p
	}

	if in.header != nil {
		if in.header.Size > max {
			return nil, fmt.Errorf("Datei ist zu groß")
		}
		in.zip = strings.HasSuffix(strings.ToLower(in.header.Filename), ".zip")
		if in.zip {
			if !s.cfg.EnableMultiFile {
				return nil, fmt.Errorf("Multi-File ist deaktiviert")
			}
			if r.FormValue("multi") == "" {
				// ZIPs are still accepted; the checkbox only makes the intent visible.
			}
		} else {
			data, err := io.ReadAll(io.LimitReader(in.file, s.cfg.MaxHTMLBytes+1))
			if err != nil {
				return nil, err
			}
			if int64(len(data)) > s.cfg.MaxHTMLBytes {
				return nil, fmt.Errorf("HTML ist zu groß (max. %d MB)", s.cfg.MaxHTMLBytes>>20)
			}
			if len(data) == 0 {
				return nil, fmt.Errorf("HTML ist leer")
			}
			in.html = data
			in.file.Close()
			in.file = nil
		}
	} else {
		if strings.TrimSpace(in.Form.HTML) == "" {
			if existing != nil {
				in.settingsOnly = true
			} else {
				return nil, fmt.Errorf("Bitte HTML einfügen oder eine Datei auswählen")
			}
		} else if int64(len(in.Form.HTML)) > s.cfg.MaxHTMLBytes {
			return nil, fmt.Errorf("HTML ist zu groß (max. %d MB)", s.cfg.MaxHTMLBytes>>20)
		} else {
			in.html = []byte(in.Form.HTML)
		}
	}
	return in, nil
}

func (s *Server) applyDeploy(ctx context.Context, existing *store.Site, in *uploadInput) (*store.Site, bool, *store.Version, error) {
	if existing == nil {
		site, err := s.st.GetSiteByPath(ctx, in.Form.Path)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, false, nil, err
		}
		if err == nil {
			existing = site
		}
	}
	path := in.Form.Path
	if existing != nil {
		path = existing.Path
	}

	mode := in.Form.Mode
	if mode == "" {
		mode = "public"
	}
	if err := validate.AccessMode(mode); err != nil {
		return nil, false, nil, err
	}
	if mode == "pocketid" && !s.pagesOIDC.Enabled() {
		return nil, false, nil, fmt.Errorf("Pocket-ID für Seiten ist nicht konfiguriert")
	}

	var secretHash string
	if mode == "pin" || mode == "password" {
		secret := in.Form.PIN
		if mode == "password" {
			secret = in.Form.Password
		}
		if strings.TrimSpace(secret) == "" {
			if existing != nil && existing.AccessMode == mode && existing.SecretHash != "" {
				secretHash = existing.SecretHash
			} else {
				return nil, false, nil, fmt.Errorf("Bitte %s angeben", map[string]string{"pin": "eine PIN", "password": "ein Passwort"}[mode])
			}
		} else {
			clean, err := validate.Secret(mode, secret)
			if err != nil {
				return nil, false, nil, err
			}
			hash, err := secure.HashSecret(clean)
			if err != nil {
				return nil, false, nil, err
			}
			secretHash = hash
		}
	}

	versionID := store.NewID()
	var zipReader io.ReaderAt
	var zipSize int64
	if in.zip && in.file != nil {
		zipReader = in.file
		zipSize = in.header.Size
	}
	res, err := deploy.Build(s.cfg.DataDir, versionID, in.html, zipReader, zipSize, deploy.Limits{
		MaxTotal: s.cfg.MaxZipBytes,
		MaxFile:  s.cfg.MaxFileBytes,
		MaxFiles: s.cfg.MaxFiles,
	})
	if err != nil {
		return nil, false, nil, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = deploy.RemoveVersion(s.cfg.DataDir, versionID)
		}
	}()

	v := &store.Version{
		ID: versionID, Dir: res.Dir, Entrypoint: "index.html",
		SHA256: res.Digest, Size: res.Size, FileCount: res.FileCount,
	}
	site, created, err := s.st.CreateDeployment(ctx, path, in.Form.Title, mode, secretHash, v)
	if err != nil {
		return nil, false, nil, err
	}
	cleanup = false
	s.pruneVersions(ctx, site)
	return site, created, v, nil
}

func (s *Server) applySettings(ctx context.Context, site *store.Site, in *uploadInput) error {
	mode := in.Form.Mode
	if err := validate.AccessMode(mode); err != nil {
		return err
	}
	if mode == "pocketid" && !s.pagesOIDC.Enabled() {
		return fmt.Errorf("Pocket-ID für Seiten ist nicht konfiguriert")
	}
	var secretHash string
	if mode == "pin" || mode == "password" {
		secret := in.Form.PIN
		if mode == "password" {
			secret = in.Form.Password
		}
		if strings.TrimSpace(secret) == "" {
			if site.AccessMode != mode || site.SecretHash == "" {
				return fmt.Errorf("Bitte %s angeben", map[string]string{"pin": "eine PIN", "password": "ein Passwort"}[mode])
			}
			secretHash = site.SecretHash
		} else {
			clean, err := validate.Secret(mode, secret)
			if err != nil {
				return err
			}
			hash, err := secure.HashSecret(clean)
			if err != nil {
				return err
			}
			secretHash = hash
		}
	}
	return s.st.UpdateSettings(ctx, site.ID, in.Form.Title, mode, secretHash, true)
}

func (s *Server) pruneVersions(ctx context.Context, site *store.Site) {
	versions, err := s.st.ListVersions(ctx, site.ID)
	if err != nil {
		s.log.Warn("prune: list versions", "err", err)
		return
	}
	for i, v := range versions {
		if i < s.cfg.KeepVersions || v.ID == site.CurrentVersionID {
			continue
		}
		if err := s.st.DeleteVersion(ctx, v.ID); err != nil {
			s.log.Warn("prune: delete version", "id", v.ID, "err", err)
			continue
		}
		if err := deploy.RemoveVersion(s.cfg.DataDir, v.ID); err != nil {
			s.log.Warn("prune: remove files", "id", v.ID, "err", err)
		}
	}
}
