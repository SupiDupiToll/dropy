package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

func (c Config) Enabled() bool {
	return c.Issuer != "" && c.ClientID != "" && c.ClientSecret != "" && c.RedirectURL != ""
}

type Identity struct {
	Sub      string
	Email    string
	Name     string
	Username string
	Groups   []string
}

type Manager struct {
	cfg Config

	mu       sync.Mutex
	provider *oidc.Provider
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
	lastTry  time.Time
	lastErr  error
}

func New(cfg Config) *Manager {
	return &Manager{cfg: cfg}
}

func (m *Manager) Enabled() bool { return m.cfg.Enabled() }

func (m *Manager) ensure(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.provider != nil {
		return nil
	}
	if m.lastErr != nil && time.Since(m.lastTry) < 30*time.Second {
		return m.lastErr
	}
	m.lastTry = time.Now()
	p, err := oidc.NewProvider(ctx, m.cfg.Issuer)
	if err != nil {
		m.lastErr = fmt.Errorf("OIDC-Discovery fehlgeschlagen: %w", err)
		return m.lastErr
	}
	m.provider = p
	m.oauth = &oauth2.Config{
		ClientID:     m.cfg.ClientID,
		ClientSecret: m.cfg.ClientSecret,
		Endpoint:     p.Endpoint(),
		RedirectURL:  m.cfg.RedirectURL,
		Scopes:       m.cfg.Scopes,
	}
	m.verifier = p.Verifier(&oidc.Config{ClientID: m.cfg.ClientID})
	m.lastErr = nil
	return nil
}

func (m *Manager) AuthCodeURL(ctx context.Context, state, nonce, verifier string) (string, error) {
	if err := m.ensure(ctx); err != nil {
		return "", err
	}
	m.mu.Lock()
	o := m.oauth
	m.mu.Unlock()
	return o.AuthCodeURL(state,
		oauth2.S256ChallengeOption(verifier),
		oidc.Nonce(nonce),
	), nil
}

func (m *Manager) Exchange(ctx context.Context, code, verifier, expectedNonce string) (*Identity, error) {
	if err := m.ensure(ctx); err != nil {
		return nil, err
	}
	m.mu.Lock()
	o := m.oauth
	v := m.verifier
	m.mu.Unlock()

	token, err := o.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("Code-Austausch fehlgeschlagen: %w", err)
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || raw == "" {
		return nil, fmt.Errorf("ID-Token fehlt")
	}
	idToken, err := v.Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("ID-Token ungültig: %w", err)
	}
	if expectedNonce != "" && idToken.Nonce != expectedNonce {
		return nil, fmt.Errorf("Nonce stimmt nicht überein")
	}
	var claims struct {
		Sub               string      `json:"sub"`
		Email             string      `json:"email"`
		EmailVerified     *bool       `json:"email_verified"`
		Name              string      `json:"name"`
		PreferredUsername string      `json:"preferred_username"`
		Groups            flexStrings `json:"groups"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, err
	}
	if claims.EmailVerified != nil && !*claims.EmailVerified {
		return nil, fmt.Errorf("E-Mail-Adresse ist nicht verifiziert")
	}
	email := strings.ToLower(strings.TrimSpace(claims.Email))
	if email == "" {
		// Some providers only expose the email in the userinfo response.
		m.mu.Lock()
		p := m.provider
		m.mu.Unlock()
		if p != nil {
			if ui, uiErr := p.UserInfo(ctx, oauth2.StaticTokenSource(token)); uiErr == nil {
				email = strings.ToLower(strings.TrimSpace(ui.Email))
			}
		}
	}
	return &Identity{
		Sub:      idToken.Subject,
		Email:    email,
		Name:     claims.Name,
		Username: claims.PreferredUsername,
		Groups:   claims.Groups,
	}, nil
}

type flexStrings []string

func (f *flexStrings) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil {
		*f = arr
		return nil
	}
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		if one != "" {
			*f = []string{one}
		}
		return nil
	}
	return fmt.Errorf("groups claim has unsupported shape")
}
