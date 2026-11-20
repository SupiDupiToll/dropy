package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

type Site struct {
	ID               string
	Path             string
	Title            string
	AccessMode       string
	SecretHash       string
	CurrentVersionID string
	CreatedAt        int64
	UpdatedAt        int64
	Current          *Version
}

type Version struct {
	ID         string
	SiteID     string
	Dir        string
	Entrypoint string
	SHA256     string
	Size       int64
	FileCount  int
	CreatedAt  int64
}

type AdminSession struct {
	TokenHash string
	UserSub   string
	Email     string
	Name      string
	CSRFToken string
	CreatedAt int64
	ExpiresAt int64
}

type PageSession struct {
	TokenHash string
	SiteID    string
	Method    string
	UserSub   string
	Email     string
	SourceID  string
	CreatedAt int64
	ExpiresAt int64
}

type APIToken struct {
	ID         string
	Name       string
	TokenHash  string
	CreatedAt  int64
	LastUsedAt int64
	RevokedAt  int64
}

type ShareLink struct {
	ID        string
	SiteID    string
	TokenHash string
	ExpiresAt int64
	MaxUses   int64
	Uses      int64
	CreatedAt int64
	RevokedAt int64
}

type OIDCState struct {
	StateHash    string
	Kind         string
	SiteID       string
	ReturnTo     string
	Nonce        string
	CodeVerifier string
	ExpiresAt    int64
}

func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", filepath.ToSlash(path))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

const schema = `
CREATE TABLE IF NOT EXISTS sites (
	id TEXT PRIMARY KEY,
	path TEXT NOT NULL COLLATE NOCASE UNIQUE,
	title TEXT NOT NULL DEFAULT '',
	access_mode TEXT NOT NULL DEFAULT 'public',
	secret_hash TEXT NOT NULL DEFAULT '',
	current_version_id TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS versions (
	id TEXT PRIMARY KEY,
	site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
	dir TEXT NOT NULL,
	entrypoint TEXT NOT NULL DEFAULT 'index.html',
	sha256 TEXT NOT NULL,
	size INTEGER NOT NULL,
	file_count INTEGER NOT NULL DEFAULT 1,
	created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS versions_site_idx ON versions(site_id, created_at DESC);
CREATE TABLE IF NOT EXISTS admin_sessions (
	token_hash TEXT PRIMARY KEY,
	user_sub TEXT NOT NULL,
	email TEXT NOT NULL DEFAULT '',
	name TEXT NOT NULL DEFAULT '',
	csrf_token TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS page_sessions (
	token_hash TEXT PRIMARY KEY,
	site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
	method TEXT NOT NULL,
	user_sub TEXT NOT NULL DEFAULT '',
	email TEXT NOT NULL DEFAULT '',
	source_id TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS page_sessions_site_idx ON page_sessions(site_id);
CREATE TABLE IF NOT EXISTS api_tokens (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	token_hash TEXT NOT NULL UNIQUE,
	created_at INTEGER NOT NULL,
	last_used_at INTEGER NOT NULL DEFAULT 0,
	revoked_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS share_links (
	id TEXT PRIMARY KEY,
	site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
	token_hash TEXT NOT NULL UNIQUE,
	expires_at INTEGER NOT NULL,
	max_uses INTEGER NOT NULL DEFAULT 0,
	uses INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL,
	revoked_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS share_links_site_idx ON share_links(site_id);
CREATE TABLE IF NOT EXISTS oidc_states (
	state_hash TEXT PRIMARY KEY,
	kind TEXT NOT NULL,
	site_id TEXT NOT NULL DEFAULT '',
	return_to TEXT NOT NULL DEFAULT '',
	nonce TEXT NOT NULL,
	code_verifier TEXT NOT NULL,
	expires_at INTEGER NOT NULL
);
`

func (s *Store) migrate() error {
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}
	// Additive migration for databases created before share-link sessions.
	hasSource := false
	rows, err := s.db.Query(`PRAGMA table_info(page_sessions)`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var cid, notNull, pk int
		var name, typ string
		var dflt any
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		if name == "source_id" {
			hasSource = true
		}
	}
	rows.Close()
	if !hasSource {
		if _, err := s.db.Exec(`ALTER TABLE page_sessions ADD COLUMN source_id TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS page_sessions_source_idx ON page_sessions(source_id)`); err != nil {
		return err
	}
	_, err = s.db.Exec(`PRAGMA user_version = 1`)
	return err
}

func NewID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

type scanner interface {
	Scan(dest ...any) error
}

const siteSelect = `
SELECT s.id, s.path, s.title, s.access_mode, s.secret_hash, s.current_version_id, s.created_at, s.updated_at,
       v.id, v.site_id, v.dir, v.entrypoint, v.sha256, v.size, v.file_count, v.created_at
FROM sites s
LEFT JOIN versions v ON v.id = s.current_version_id`

func scanSite(row scanner) (*Site, error) {
	var s Site
	var vid, vsite, vdir, ventry, vsha sql.NullString
	var vsize, vfiles, vcreated sql.NullInt64
	err := row.Scan(&s.ID, &s.Path, &s.Title, &s.AccessMode, &s.SecretHash, &s.CurrentVersionID,
		&s.CreatedAt, &s.UpdatedAt, &vid, &vsite, &vdir, &ventry, &vsha, &vsize, &vfiles, &vcreated)
	if err != nil {
		return nil, err
	}
	if vid.Valid {
		s.Current = &Version{
			ID: vid.String, SiteID: vsite.String, Dir: vdir.String, Entrypoint: ventry.String,
			SHA256: vsha.String, Size: vsize.Int64, FileCount: int(vfiles.Int64), CreatedAt: vcreated.Int64,
		}
	}
	return &s, nil
}

func (s *Store) GetSiteByPath(ctx context.Context, p string) (*Site, error) {
	row := s.db.QueryRowContext(ctx, siteSelect+` WHERE s.path = ? COLLATE NOCASE`, p)
	return scanSite(row)
}

func (s *Store) GetSiteByID(ctx context.Context, id string) (*Site, error) {
	row := s.db.QueryRowContext(ctx, siteSelect+` WHERE s.id = ?`, id)
	return scanSite(row)
}

func (s *Store) ListSites(ctx context.Context) ([]*Site, error) {
	rows, err := s.db.QueryContext(ctx, siteSelect+` ORDER BY s.updated_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Site
	for rows.Next() {
		site, err := scanSite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, site)
	}
	return out, rows.Err()
}

// CreateDeployment creates a site or updates the existing site at path.
func (s *Store) CreateDeployment(ctx context.Context, path, title, mode, secretHash string, v *Version) (*Site, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	now := time.Now().Unix()

	var siteID string
	var oldMode, oldSecret string
	err = tx.QueryRowContext(ctx, `SELECT id, access_mode, secret_hash FROM sites WHERE path = ? COLLATE NOCASE`, path).
		Scan(&siteID, &oldMode, &oldSecret)
	created := false
	if errors.Is(err, sql.ErrNoRows) {
		siteID = NewID()
		created = true
		_, err = tx.ExecContext(ctx, `INSERT INTO sites(id,path,title,access_mode,secret_hash,current_version_id,created_at,updated_at)
			VALUES(?,?,?,?,?,?,?,?)`, siteID, path, title, mode, secretHash, v.ID, now, now)
		if err != nil {
			return nil, false, err
		}
	} else if err != nil {
		return nil, false, err
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE sites SET title=?, access_mode=?, secret_hash=?, current_version_id=?, updated_at=? WHERE id=?`,
			title, mode, secretHash, v.ID, now, siteID)
		if err != nil {
			return nil, false, err
		}
		if oldMode != mode || oldSecret != secretHash {
			if _, err := tx.ExecContext(ctx, `DELETE FROM page_sessions WHERE site_id=?`, siteID); err != nil {
				return nil, false, err
			}
		}
	}
	v.SiteID = siteID
	_, err = tx.ExecContext(ctx, `INSERT INTO versions(id,site_id,dir,entrypoint,sha256,size,file_count,created_at)
		VALUES(?,?,?,?,?,?,?,?)`, v.ID, v.SiteID, v.Dir, v.Entrypoint, v.SHA256, v.Size, v.FileCount, now)
	if err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	site, err := s.GetSiteByID(ctx, siteID)
	return site, created, err
}

func (s *Store) UpdateSettings(ctx context.Context, id, title, mode, secretHash string, updateSecret bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var oldMode, oldSecret string
	if err := tx.QueryRowContext(ctx, `SELECT access_mode, secret_hash FROM sites WHERE id=?`, id).Scan(&oldMode, &oldSecret); err != nil {
		return err
	}
	now := time.Now().Unix()
	if updateSecret {
		_, err = tx.ExecContext(ctx, `UPDATE sites SET title=?, access_mode=?, secret_hash=?, updated_at=? WHERE id=?`,
			title, mode, secretHash, now, id)
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE sites SET title=?, access_mode=?, updated_at=? WHERE id=?`, title, mode, now, id)
	}
	if err != nil {
		return err
	}
	if oldMode != mode || (updateSecret && oldSecret != secretHash) {
		if _, err := tx.ExecContext(ctx, `DELETE FROM page_sessions WHERE site_id=?`, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) SetCurrentVersion(ctx context.Context, siteID, versionID string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE sites SET current_version_id=?, updated_at=? WHERE id=?`, versionID, time.Now().Unix(), siteID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) DeleteSite(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sites WHERE id=?`, id)
	return err
}

func (s *Store) ListVersions(ctx context.Context, siteID string) ([]*Version, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,site_id,dir,entrypoint,sha256,size,file_count,created_at
		FROM versions WHERE site_id=? ORDER BY created_at DESC, rowid DESC`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Version
	for rows.Next() {
		v := &Version{}
		if err := rows.Scan(&v.ID, &v.SiteID, &v.Dir, &v.Entrypoint, &v.SHA256, &v.Size, &v.FileCount, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) GetVersion(ctx context.Context, siteID, versionID string) (*Version, error) {
	v := &Version{}
	err := s.db.QueryRowContext(ctx, `SELECT id,site_id,dir,entrypoint,sha256,size,file_count,created_at
		FROM versions WHERE id=? AND site_id=?`, versionID, siteID).
		Scan(&v.ID, &v.SiteID, &v.Dir, &v.Entrypoint, &v.SHA256, &v.Size, &v.FileCount, &v.CreatedAt)
	return v, err
}

func (s *Store) DeleteVersion(ctx context.Context, versionID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM versions WHERE id=?`, versionID)
	return err
}

func (s *Store) CreateAdminSession(ctx context.Context, sess *AdminSession) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO admin_sessions(token_hash,user_sub,email,name,csrf_token,created_at,expires_at)
		VALUES(?,?,?,?,?,?,?)`, sess.TokenHash, sess.UserSub, sess.Email, sess.Name, sess.CSRFToken, sess.CreatedAt, sess.ExpiresAt)
	return err
}

func (s *Store) GetAdminSession(ctx context.Context, tokenHash string) (*AdminSession, error) {
	sess := &AdminSession{}
	err := s.db.QueryRowContext(ctx, `SELECT token_hash,user_sub,email,name,csrf_token,created_at,expires_at
		FROM admin_sessions WHERE token_hash=? AND expires_at > ?`, tokenHash, time.Now().Unix()).
		Scan(&sess.TokenHash, &sess.UserSub, &sess.Email, &sess.Name, &sess.CSRFToken, &sess.CreatedAt, &sess.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return sess, err
}

func (s *Store) DeleteAdminSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM admin_sessions WHERE token_hash=?`, tokenHash)
	return err
}

func (s *Store) CreatePageSession(ctx context.Context, sess *PageSession) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO page_sessions(token_hash,site_id,method,user_sub,email,source_id,created_at,expires_at)
		VALUES(?,?,?,?,?,?,?,?)`, sess.TokenHash, sess.SiteID, sess.Method, sess.UserSub, sess.Email, sess.SourceID, sess.CreatedAt, sess.ExpiresAt)
	return err
}

func (s *Store) GetPageSession(ctx context.Context, tokenHash, siteID string) (*PageSession, error) {
	sess := &PageSession{}
	err := s.db.QueryRowContext(ctx, `SELECT token_hash,site_id,method,user_sub,email,source_id,created_at,expires_at
		FROM page_sessions WHERE token_hash=? AND site_id=? AND expires_at > ?`, tokenHash, siteID, time.Now().Unix()).
		Scan(&sess.TokenHash, &sess.SiteID, &sess.Method, &sess.UserSub, &sess.Email, &sess.SourceID, &sess.CreatedAt, &sess.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return sess, err
}

func (s *Store) DeletePageSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM page_sessions WHERE token_hash=?`, tokenHash)
	return err
}

func (s *Store) DeletePageSessionsForSite(ctx context.Context, siteID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM page_sessions WHERE site_id=?`, siteID)
	return err
}

func (s *Store) DeletePageSessionsBySource(ctx context.Context, sourceID string) error {
	if sourceID == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM page_sessions WHERE source_id=?`, sourceID)
	return err
}

func (s *Store) CreateOIDCState(ctx context.Context, st *OIDCState) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO oidc_states(state_hash,kind,site_id,return_to,nonce,code_verifier,expires_at)
		VALUES(?,?,?,?,?,?,?)`, st.StateHash, st.Kind, st.SiteID, st.ReturnTo, st.Nonce, st.CodeVerifier, st.ExpiresAt)
	return err
}

func (s *Store) ConsumeOIDCState(ctx context.Context, stateHash string) (*OIDCState, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	st := &OIDCState{}
	err = tx.QueryRowContext(ctx, `SELECT state_hash,kind,site_id,return_to,nonce,code_verifier,expires_at
		FROM oidc_states WHERE state_hash=? AND expires_at > ?`, stateHash, time.Now().Unix()).
		Scan(&st.StateHash, &st.Kind, &st.SiteID, &st.ReturnTo, &st.Nonce, &st.CodeVerifier, &st.ExpiresAt)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM oidc_states WHERE state_hash=?`, stateHash); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return st, nil
}

func (s *Store) CreateAPIToken(ctx context.Context, id, name, hash string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO api_tokens(id,name,token_hash,created_at) VALUES(?,?,?,?)`,
		id, name, hash, time.Now().Unix())
	return err
}

func (s *Store) GetAPITokenByHash(ctx context.Context, hash string) (*APIToken, error) {
	t := &APIToken{}
	err := s.db.QueryRowContext(ctx, `SELECT id,name,token_hash,created_at,last_used_at,revoked_at
		FROM api_tokens WHERE token_hash=? AND revoked_at=0`, hash).
		Scan(&t.ID, &t.Name, &t.TokenHash, &t.CreatedAt, &t.LastUsedAt, &t.RevokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return t, err
}

func (s *Store) TouchAPIToken(ctx context.Context, id string) {
	_, _ = s.db.ExecContext(ctx, `UPDATE api_tokens SET last_used_at=? WHERE id=?`, time.Now().Unix(), id)
}

func (s *Store) ListAPITokens(ctx context.Context) ([]*APIToken, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,token_hash,created_at,last_used_at,revoked_at
		FROM api_tokens WHERE revoked_at=0 ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*APIToken
	for rows.Next() {
		t := &APIToken{}
		if err := rows.Scan(&t.ID, &t.Name, &t.TokenHash, &t.CreatedAt, &t.LastUsedAt, &t.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) RevokeAPIToken(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE api_tokens SET revoked_at=? WHERE id=?`, time.Now().Unix(), id)
	return err
}

func (s *Store) CreateShareLink(ctx context.Context, id, siteID, hash string, expiresAt, maxUses int64) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO share_links(id,site_id,token_hash,expires_at,max_uses,created_at)
		VALUES(?,?,?,?,?,?)`, id, siteID, hash, expiresAt, maxUses, time.Now().Unix())
	return err
}

func (s *Store) GetShareLinkByHash(ctx context.Context, hash string) (*ShareLink, error) {
	l := &ShareLink{}
	err := s.db.QueryRowContext(ctx, `SELECT id,site_id,token_hash,expires_at,max_uses,uses,created_at,revoked_at
		FROM share_links WHERE token_hash=? AND revoked_at=0 AND expires_at>? AND (max_uses=0 OR uses<max_uses)`,
		hash, time.Now().Unix()).
		Scan(&l.ID, &l.SiteID, &l.TokenHash, &l.ExpiresAt, &l.MaxUses, &l.Uses, &l.CreatedAt, &l.RevokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return l, err
}

func (s *Store) IncrementShareUse(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE share_links SET uses=uses+1 WHERE id=?`, id)
	return err
}

func (s *Store) ListShareLinks(ctx context.Context, siteID string) ([]*ShareLink, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,site_id,token_hash,expires_at,max_uses,uses,created_at,revoked_at
		FROM share_links WHERE site_id=? ORDER BY created_at DESC`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ShareLink
	for rows.Next() {
		l := &ShareLink{}
		if err := rows.Scan(&l.ID, &l.SiteID, &l.TokenHash, &l.ExpiresAt, &l.MaxUses, &l.Uses, &l.CreatedAt, &l.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func (s *Store) RevokeShareLink(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE share_links SET revoked_at=? WHERE id=?`, time.Now().Unix(), id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM page_sessions WHERE source_id=?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DeleteExpired(ctx context.Context, now int64) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM admin_sessions WHERE expires_at<=?`, now); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM page_sessions WHERE expires_at<=?`, now); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM oidc_states WHERE expires_at<=?`, now)
	return err
}
