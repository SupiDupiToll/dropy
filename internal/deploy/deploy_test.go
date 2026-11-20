package deploy

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

type testZipFile struct {
	name string
	body string
	mode os.FileMode
}

func makeZip(t *testing.T, files []testZipFile) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range files {
		h := &zip.FileHeader{Name: f.name, Method: zip.Deflate}
		if f.mode != 0 {
			h.SetMode(f.mode)
		}
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(f.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestBuildSingle(t *testing.T) {
	dir := t.TempDir()
	res, err := Build(dir, "v1", []byte("<h1>hi</h1>"), nil, 0, Limits{MaxTotal: 1 << 20, MaxFile: 1 << 20, MaxFiles: 10})
	if err != nil {
		t.Fatal(err)
	}
	if res.FileCount != 1 || res.Size == 0 || res.Digest == "" {
		t.Fatalf("unexpected result: %+v", res)
	}
	data, err := os.ReadFile(filepath.Join(res.Dir, "index.html"))
	if err != nil || string(data) != "<h1>hi</h1>" {
		t.Fatalf("index content: %q %v", data, err)
	}
}

func TestBuildZipStripsSingleRootFolder(t *testing.T) {
	dir := t.TempDir()
	z := makeZip(t, []testZipFile{
		{name: "site/index.html", body: "<h1>zip</h1>"},
		{name: "site/assets/app.js", body: "console.log(1)"},
	})
	res, err := Build(dir, "v1", nil, bytes.NewReader(z), int64(len(z)), Limits{MaxTotal: 1 << 20, MaxFile: 1 << 20, MaxFiles: 10})
	if err != nil {
		t.Fatal(err)
	}
	if res.FileCount != 2 {
		t.Fatalf("file count = %d, want 2", res.FileCount)
	}
	if _, err := os.Stat(filepath.Join(res.Dir, "index.html")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(res.Dir, "assets", "app.js")); err != nil {
		t.Fatal(err)
	}
}

func TestZipSlipRejected(t *testing.T) {
	dir := t.TempDir()
	z := makeZip(t, []testZipFile{{name: "../evil.txt", body: "x"}})
	_, err := Build(dir, "v1", nil, bytes.NewReader(z), int64(len(z)), Limits{MaxTotal: 1 << 20, MaxFile: 1 << 20, MaxFiles: 10})
	if err == nil {
		t.Fatal("zip slip accepted")
	}
}

func TestZipSymlinkRejected(t *testing.T) {
	dir := t.TempDir()
	z := makeZip(t, []testZipFile{{name: "index.html", body: "x"}, {name: "link", body: "/etc/passwd", mode: os.ModeSymlink | 0o777}})
	_, err := Build(dir, "v1", nil, bytes.NewReader(z), int64(len(z)), Limits{MaxTotal: 1 << 20, MaxFile: 1 << 20, MaxFiles: 10})
	if err == nil {
		t.Fatal("symlink accepted")
	}
}

func TestZipHiddenFilesRejected(t *testing.T) {
	dir := t.TempDir()
	z := makeZip(t, []testZipFile{{name: "index.html", body: "x"}, {name: ".env", body: "SECRET=1"}})
	_, err := Build(dir, "v1", nil, bytes.NewReader(z), int64(len(z)), Limits{MaxTotal: 1 << 20, MaxFile: 1 << 20, MaxFiles: 10})
	if err == nil {
		t.Fatal(".env accepted")
	}
}

func TestDigestStable(t *testing.T) {
	dir := t.TempDir()
	html := []byte("<h1>same</h1>")
	a, err := Build(dir, "a", html, nil, 0, Limits{MaxTotal: 1 << 20, MaxFile: 1 << 20, MaxFiles: 10})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Build(dir, "b", html, nil, 0, Limits{MaxTotal: 1 << 20, MaxFile: 1 << 20, MaxFiles: 10})
	if err != nil {
		t.Fatal(err)
	}
	if a.Digest != b.Digest {
		t.Fatalf("digest changed: %s != %s", a.Digest, b.Digest)
	}
}

func TestZipLimit(t *testing.T) {
	dir := t.TempDir()
	z := makeZip(t, []testZipFile{{name: "index.html", body: "0123456789"}})
	_, err := Build(dir, "v1", nil, bytes.NewReader(z), int64(len(z)), Limits{MaxTotal: 5, MaxFile: 100, MaxFiles: 10})
	if err == nil {
		t.Fatal("size limit not enforced")
	}
}
