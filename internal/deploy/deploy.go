package deploy

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Limits struct {
	MaxTotal int64
	MaxFile  int64
	MaxFiles int
}

type Result struct {
	ID        string
	Dir       string
	Digest    string
	Size      int64
	FileCount int
}

func WriteHTML(root string, html []byte) error {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, "index.html"), html, 0o644)
}

// ExtractZip unpacks a zip archive with zip-slip and size protections.
func ExtractZip(root string, r io.ReaderAt, size int64, limits Limits) error {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return fmt.Errorf("ZIP konnte nicht gelesen werden: %w", err)
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	var total int64
	count := 0
	for _, f := range zr.File {
		name := strings.ReplaceAll(f.Name, `\`, "/")
		clean := filepath.ToSlash(filepath.Clean(name))
		if clean == "." {
			continue
		}
		if strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") || clean == ".." {
			return fmt.Errorf("unsicherer Pfad im ZIP: %s", f.Name)
		}
		if strings.HasPrefix(clean, "__MACOSX/") || clean == ".DS_Store" {
			continue
		}
		parts := strings.Split(clean, "/")
		for _, p := range parts {
			if p == "" || p == "." || p == ".." {
				return fmt.Errorf("unsicherer Pfad im ZIP: %s", f.Name)
			}
			if strings.HasPrefix(p, ".git") || p == ".env" || strings.HasPrefix(p, ".env.") {
				return fmt.Errorf("nicht erlaubte Datei im ZIP: %s", f.Name)
			}
			if strings.HasPrefix(p, ".") && p != ".well-known" {
				return fmt.Errorf("versteckte Datei im ZIP nicht erlaubt: %s", f.Name)
			}
		}
		mode := f.Mode()
		if mode&os.ModeSymlink != 0 {
			return fmt.Errorf("Symlinks sind im ZIP nicht erlaubt: %s", f.Name)
		}
		target := filepath.Join(root, filepath.FromSlash(clean))
		rel, err := filepath.Rel(root, target)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("unsicherer Pfad im ZIP: %s", f.Name)
		}
		if f.FileInfo().IsDir() || strings.HasSuffix(name, "/") {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		count++
		if count > limits.MaxFiles {
			return fmt.Errorf("zu viele Dateien im ZIP (max. %d)", limits.MaxFiles)
		}
		if f.UncompressedSize64 > uint64(limits.MaxFile) {
			return fmt.Errorf("Datei im ZIP ist zu groß: %s", f.Name)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			rc.Close()
			return err
		}
		n, copyErr := io.Copy(out, io.LimitReader(rc, limits.MaxFile+1))
		closeErr := out.Close()
		rc.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if n > limits.MaxFile {
			return fmt.Errorf("Datei im ZIP ist zu groß: %s", f.Name)
		}
		total += n
		if total > limits.MaxTotal {
			return fmt.Errorf("ZIP ist entpackt zu groß (max. %d MB)", limits.MaxTotal>>20)
		}
	}
	if err := ensureRootIndex(root); err != nil {
		return err
	}
	return nil
}

// ensureRootIndex supports ZIPs that contain a single top-level folder.
func ensureRootIndex(root string) error {
	if _, err := os.Stat(filepath.Join(root, "index.html")); err == nil {
		return nil
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	if len(entries) != 1 || !entries[0].IsDir() {
		return fmt.Errorf("index.html im ZIP-Root fehlt")
	}
	inner := filepath.Join(root, entries[0].Name())
	if _, err := os.Stat(filepath.Join(inner, "index.html")); err != nil {
		return fmt.Errorf("index.html im ZIP-Root fehlt")
	}
	children, err := os.ReadDir(inner)
	if err != nil {
		return err
	}
	for _, child := range children {
		if err := os.Rename(filepath.Join(inner, child.Name()), filepath.Join(root, child.Name())); err != nil {
			return err
		}
	}
	return os.Remove(inner)
}

// Digest computes a deterministic hash over all files in a version directory.
func Digest(root string) (string, int64, int, error) {
	type fileEntry struct {
		rel  string
		path string
	}
	var files []fileEntry
	var total int64
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		files = append(files, fileEntry{rel: filepath.ToSlash(rel), path: p})
		return nil
	})
	if err != nil {
		return "", 0, 0, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].rel < files[j].rel })
	h := sha256.New()
	for _, f := range files {
		fh, err := os.Open(f.path)
		if err != nil {
			return "", 0, 0, err
		}
		sh := sha256.New()
		n, err := io.Copy(sh, fh)
		fh.Close()
		if err != nil {
			return "", 0, 0, err
		}
		total += n
		fmt.Fprintf(h, "%s\x00%s\x00%d\n", f.rel, hex.EncodeToString(sh.Sum(nil)), n)
	}
	return hex.EncodeToString(h.Sum(nil)), total, len(files), nil
}

// Build writes content into a temp directory, then atomically moves it to its
// final version directory. The caller owns cleanup of the returned directory.
func Build(dataDir, versionID string, html []byte, zipReader io.ReaderAt, zipSize int64, limits Limits) (*Result, error) {
	tmp := filepath.Join(dataDir, "tmp", versionID)
	final := filepath.Join(dataDir, "versions", versionID)
	if err := os.RemoveAll(tmp); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(final), 0o755); err != nil {
		return nil, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			os.RemoveAll(tmp)
		}
	}()

	if zipReader != nil {
		if err := ExtractZip(tmp, zipReader, zipSize, limits); err != nil {
			return nil, err
		}
	} else {
		if len(html) == 0 {
			return nil, fmt.Errorf("HTML ist leer")
		}
		if int64(len(html)) > limits.MaxTotal {
			return nil, fmt.Errorf("HTML ist zu groß (max. %d MB)", limits.MaxTotal>>20)
		}
		if err := WriteHTML(tmp, html); err != nil {
			return nil, err
		}
	}
	digest, size, count, err := Digest(tmp)
	if err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, final); err != nil {
		return nil, err
	}
	cleanup = false
	return &Result{ID: versionID, Dir: final, Digest: digest, Size: size, FileCount: count}, nil
}

func RemoveVersion(dataDir, versionID string) error {
	if versionID == "" || strings.ContainsAny(versionID, `/\`) {
		return fmt.Errorf("ungültige Versions-ID")
	}
	return os.RemoveAll(filepath.Join(dataDir, "versions", versionID))
}

func CleanTemp(dataDir string) {
	tmp := filepath.Join(dataDir, "tmp")
	entries, err := os.ReadDir(tmp)
	if err != nil {
		return
	}
	for _, e := range entries {
		os.RemoveAll(filepath.Join(tmp, e.Name()))
	}
}
