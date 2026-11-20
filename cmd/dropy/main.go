package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"dropy/internal/config"
	"dropy/internal/deploy"
	"dropy/internal/server"
	"dropy/internal/store"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "deploy" {
		os.Exit(runDeploy(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "serve" {
		os.Args = append([]string{os.Args[0]}, os.Args[2:]...)
	}
	if err := runServer(); err != nil {
		fmt.Fprintln(os.Stderr, "dropy:", err)
		os.Exit(1)
	}
}

func runServer() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "dropy.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	deploy.CleanTemp(cfg.DataDir)

	srv, err := server.New(cfg, st, logger)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go srv.Cleanup(ctx)

	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	errCh := make(chan error, 1)
	go func() {
		logger.Info("dropy listening", "addr", cfg.Listen, "admin", cfg.AdminBaseURL, "pages", cfg.PublicBaseURL)
		errCh <- httpSrv.ListenAndServe()
	}()
	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return httpSrv.Shutdown(shutdownCtx)
}

func runDeploy(args []string) int {
	fs := flag.NewFlagSet("deploy", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	serverURL := fs.String("server", envOr("DROPY_SERVER", ""), "dropy base URL")
	token := fs.String("token", envOr("DROPY_TOKEN", ""), "API token")
	path := fs.String("path", "", "public path, e.g. demo or reports/2026")
	file := fs.String("file", "", "HTML or ZIP file to upload ('-' for stdin)")
	title := fs.String("title", "", "optional page title")
	mode := fs.String("mode", "public", "public, pin, password or pocketid")
	pin := fs.String("pin", "", "PIN for mode=pin")
	password := fs.String("password", "", "password for mode=password")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *serverURL == "" {
		fmt.Fprintln(os.Stderr, "missing --server (or DROPY_SERVER)")
		return 2
	}
	if *token == "" {
		fmt.Fprintln(os.Stderr, "missing --token (or DROPY_TOKEN)")
		return 2
	}
	if *file == "" {
		fmt.Fprintln(os.Stderr, "missing --file")
		return 2
	}
	if *path == "" {
		fmt.Fprintln(os.Stderr, "missing --path")
		return 2
	}

	var data []byte
	var filename string
	if *file == "-" {
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 60<<20))
		if err != nil {
			fmt.Fprintln(os.Stderr, "read stdin:", err)
			return 1
		}
		data = b
		filename = "stdin.html"
	} else {
		b, err := os.ReadFile(*file)
		if err != nil {
			fmt.Fprintln(os.Stderr, "read file:", err)
			return 1
		}
		data = b
		filename = filepath.Base(*file)
	}

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if _, err := fw.Write(data); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	_ = mw.WriteField("path", *path)
	_ = mw.WriteField("title", *title)
	_ = mw.WriteField("mode", *mode)
	if *pin != "" {
		_ = mw.WriteField("pin", *pin)
	}
	if *password != "" {
		_ = mw.WriteField("password", *password)
	}
	mw.Close()

	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(*serverURL, "/")+"/api/sites", &body)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	req.Header.Set("Authorization", "Bearer "+*token)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	client := &http.Client{Timeout: 90 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "request:", err)
		return 1
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "deploy failed (%d): %s\n", resp.StatusCode, strings.TrimSpace(string(raw)))
		return 1
	}
	var out struct {
		Site struct {
			URL string `json:"url"`
		} `json:"site"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		fmt.Fprintln(os.Stderr, string(raw))
		return 1
	}
	fmt.Println(out.Site.URL)
	return 0
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
