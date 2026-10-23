package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
	"modernc.org/sqlite"
)

const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

var (
	ErrUnauthorized   = errors.New("not authorized")
	ErrNotFound       = errors.New("not found")
	ErrConflict       = errors.New("already exists or conflicts with an existing record")
	ErrInitialized    = errors.New("setup is already complete")
	ErrLastAdmin      = errors.New("cannot remove the last enabled administrator")
	ErrAuthentication = errors.New("invalid credentials")
)

type User struct {
	ID          string    `json:"id"`
	Username    string    `json:"username"`
	Role        string    `json:"role"`
	Disabled    bool      `json:"disabled"`
	CreatedAt   time.Time `json:"created_at"`
	AuthVersion int64     `json:"-"`
}

type Key struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	Name        string    `json:"name"`
	PublicKey   string    `json:"public_key"`
	Fingerprint string    `json:"fingerprint"`
	CreatedAt   time.Time `json:"created_at"`
}

type Mapping struct {
	ID              string    `json:"id"`
	UserID          string    `json:"user_id"`
	KeyID           string    `json:"key_id"`
	Source          string    `json:"source"`
	Host            string    `json:"host"`
	RemoteUser      string    `json:"remote_user"`
	RemotePath      string    `json:"remote_path"`
	HostFingerprint string    `json:"host_fingerprint"`
	Port            int       `json:"port"`
	ReadOnly        bool      `json:"read_only"`
	CreatedAt       time.Time `json:"created_at"`
}

type Settings struct {
	Banner                string `json:"banner"`
	MaxSessionsPerUser    int    `json:"max_sessions_per_user"`
	SessionTimeoutMinutes int    `json:"session_timeout_minutes"`
}

type Store struct{ db *sql.DB }

func defaultSettings() Settings {
	return Settings{Banner: "Git Proxy", MaxSessionsPerUser: 8, SessionTimeoutMinutes: 120}
}

// Open opens a database in an existing, private parent directory. Every
// connection enables foreign keys and a busy timeout; immediate transactions
// also serialize permission checks and writes across separate Store instances.
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("database path is required")
	}
	var dsn string
	if path == ":memory:" {
		dsn = ":memory:?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_txlock=immediate"
	} else {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		file, err := os.OpenFile(absolute, os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			return nil, fmt.Errorf("open database file: %w", err)
		}
		if err := file.Close(); err != nil {
			return nil, err
		}
		// Some filesystems do not support Unix permissions. The parent directory
		// remains the caller's responsibility on those platforms.
		_ = os.Chmod(absolute, 0600)
		u := url.URL{Scheme: "file", Path: absolute}
		dsn = u.String() + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_txlock=immediate"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// A single connection avoids unnecessary lock contention and preserves an
	// in-memory database. SQLite's write lock protects independent processes.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err = db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	const schema = `
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('admin','user')), disabled INTEGER NOT NULL DEFAULT 0 CHECK(disabled IN (0,1)),
 created_at INTEGER NOT NULL, auth_version INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS ssh_keys (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 name TEXT NOT NULL, public_key TEXT NOT NULL, fingerprint TEXT NOT NULL UNIQUE,
 created_at INTEGER NOT NULL, UNIQUE(id,user_id)
);
CREATE TABLE IF NOT EXISTS mappings (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 key_id TEXT, source TEXT NOT NULL, host TEXT NOT NULL, remote_user TEXT NOT NULL,
 remote_path TEXT NOT NULL, host_fingerprint TEXT NOT NULL, port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
 read_only INTEGER NOT NULL CHECK(read_only IN (0,1)), created_at INTEGER NOT NULL,
 FOREIGN KEY(key_id,user_id) REFERENCES ssh_keys(id,user_id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS mappings_scope ON mappings(user_id,COALESCE(key_id,''),source);
CREATE INDEX IF NOT EXISTS ssh_keys_user ON ssh_keys(user_id);
CREATE TABLE IF NOT EXISTS settings (
 id INTEGER PRIMARY KEY CHECK(id=1), banner TEXT NOT NULL,
 max_sessions_per_user INTEGER NOT NULL CHECK(max_sessions_per_user>0),
 session_timeout_minutes INTEGER NOT NULL CHECK(session_timeout_minutes>0)
);
INSERT OR IGNORE INTO settings(id,banner,max_sessions_per_user,session_timeout_minutes) VALUES(1,'Git Proxy',8,120);
`
	tx, err := db.Begin()
	if err == nil {
		_, err = tx.Exec(schema)
		if err == nil {
			// Canonicalize existing routes atomically. Conflicting aliases fail the
			// transaction rather than silently choosing a different destination.
			_, err = tx.Exec(`UPDATE mappings SET
			 source=CASE WHEN substr(source,-4)='.git' THEN source ELSE source||'.git' END,
			 remote_path=CASE WHEN substr(remote_path,-4)='.git' THEN remote_path ELSE remote_path||'.git' END
			 WHERE substr(source,-4)!='.git' OR substr(remote_path,-4)!='.git'`)
		}
		if err == nil {
			err = tx.Commit()
		} else {
			_ = tx.Rollback()
		}
	}
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("initialize database: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Initialized() bool {
	var initialized bool
	return s.db.QueryRow("SELECT EXISTS(SELECT 1 FROM users)").Scan(&initialized) == nil && initialized
}

func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]{3,64}$`)
var remoteUserPattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)
var pathPattern = regexp.MustCompile(`^[a-zA-Z0-9_.\-/]+$`)
var hostLabelPattern = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$`)

func validateUsername(username string) error {
	if !usernamePattern.MatchString(username) {
		return errors.New("name must contain 3–64 letters, digits, dots, underscores or hyphens")
	}
	return nil
}

func validateRole(role string) error {
	if role != RoleAdmin && role != RoleUser {
		return errors.New("role must be admin or user")
	}
	return nil
}

func passwordInput(password string) []byte {
	// Bcrypt only accepts 72 bytes. Hash every password to the same bounded,
	// printable representation so the advertised 1024-byte limit is honored.
	digest := sha256.Sum256([]byte(password))
	return []byte(base64.StdEncoding.EncodeToString(digest[:]))
}

func hashPassword(password string) (string, error) {
	if len(password) < 12 || len(password) > 1024 {
		return "", errors.New("password must contain 12–1024 bytes")
	}
	hash, err := bcrypt.GenerateFromPassword(passwordInput(password), bcrypt.DefaultCost)
	return string(hash), err
}

func databaseError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	var sqliteErr *sqlite.Error
	if errors.As(err, &sqliteErr) && sqliteErr.Code()&255 == 19 {
		return ErrConflict
	}
	return fmt.Errorf("database operation failed: %w", err)
}

type scanner interface{ Scan(...any) error }

const userColumns = "id,username,role,disabled,created_at,auth_version"
const keyColumns = "id,user_id,name,public_key,fingerprint,created_at"
const mappingColumns = "id,user_id,COALESCE(key_id,''),source,host,remote_user,remote_path,host_fingerprint,port,read_only,created_at"

func scanUser(row scanner) (User, error) {
	var u User
	var created int64
	if err := row.Scan(&u.ID, &u.Username, &u.Role, &u.Disabled, &created, &u.AuthVersion); err != nil {
		return User{}, databaseError(err)
	}
	u.CreatedAt = time.Unix(0, created).UTC()
	return u, nil
}

func scanKey(row scanner) (Key, error) {
	var k Key
	var created int64
	if err := row.Scan(&k.ID, &k.UserID, &k.Name, &k.PublicKey, &k.Fingerprint, &created); err != nil {
		return Key{}, databaseError(err)
	}
	k.CreatedAt = time.Unix(0, created).UTC()
	return k, nil
}

func scanMapping(row scanner) (Mapping, error) {
	var m Mapping
	var created int64
	if err := row.Scan(&m.ID, &m.UserID, &m.KeyID, &m.Source, &m.Host, &m.RemoteUser, &m.RemotePath, &m.HostFingerprint, &m.Port, &m.ReadOnly, &created); err != nil {
		return Mapping{}, databaseError(err)
	}
	m.CreatedAt = time.Unix(0, created).UTC()
	return m, nil
}

func actor(tx *sql.Tx, id string, admin bool) (User, error) {
	u, err := scanUser(tx.QueryRow("SELECT "+userColumns+" FROM users WHERE id=?", id))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return User{}, ErrUnauthorized
		}
		return User{}, err
	}
	if u.Disabled || (admin && u.Role != RoleAdmin) {
		return User{}, ErrUnauthorized
	}
	return u, nil
}

func commit(tx *sql.Tx) error { return databaseError(tx.Commit()) }

func (s *Store) Bootstrap(username, password string) (User, error) {
	if err := validateUsername(username); err != nil {
		return User{}, err
	}
	hash, err := hashPassword(password)
	if err != nil {
		return User{}, err
	}
	id, err := newID()
	if err != nil {
		return User{}, err
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return User{}, databaseError(err)
	}
	defer tx.Rollback()
	var initialized bool
	if err = tx.QueryRow("SELECT EXISTS(SELECT 1 FROM users)").Scan(&initialized); err != nil {
		return User{}, databaseError(err)
	}
	if initialized {
		return User{}, ErrInitialized
	}
	u := User{ID: id, Username: username, Role: RoleAdmin, CreatedAt: time.Now().UTC(), AuthVersion: 1}
	_, err = tx.Exec("INSERT INTO users(id,username,password_hash,role,created_at) VALUES(?,?,?,?,?)", u.ID, u.Username, hash, u.Role, u.CreatedAt.UnixNano())
	if err != nil {
		return User{}, databaseError(err)
	}
	if err = commit(tx); err != nil {
		return User{}, err
	}
	return u, nil
}

func (s *Store) Authenticate(username, password string) (User, error) {
	// A real bcrypt hash keeps unknown-user and wrong-password work comparable.
	const dummyHash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
	if len(password) < 12 || len(password) > 1024 {
		return User{}, ErrAuthentication
	}
	var u User
	var hash string
	var created int64
	err := s.db.QueryRow("SELECT "+userColumns+",password_hash FROM users WHERE username=?", username).Scan(&u.ID, &u.Username, &u.Role, &u.Disabled, &created, &u.AuthVersion, &hash)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return User{}, databaseError(err)
		}
		hash = dummyHash
	}
	passwordErr := bcrypt.CompareHashAndPassword([]byte(hash), passwordInput(password))
	if err != nil || passwordErr != nil || u.Disabled {
		return User{}, ErrAuthentication
	}
	// Password verification is intentionally outside a write transaction. Recheck
	// the account afterward so a concurrent disable or password reset wins.
	current, lookupErr := s.User(u.ID)
	if lookupErr != nil {
		if errors.Is(lookupErr, ErrNotFound) {
			return User{}, ErrAuthentication
		}
		return User{}, lookupErr
	}
	if current.Disabled || current.AuthVersion != u.AuthVersion {
		return User{}, ErrAuthentication
	}
	return current, nil
}

func (s *Store) User(id string) (User, error) {
	return scanUser(s.db.QueryRow("SELECT "+userColumns+" FROM users WHERE id=?", id))
}

func (s *Store) Users(actorID string) ([]User, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, databaseError(err)
	}
	defer tx.Rollback()
	if _, err = actor(tx, actorID, true); err != nil {
		return nil, err
	}
	rows, err := tx.Query("SELECT " + userColumns + " FROM users ORDER BY username,id")
	if err != nil {
		return nil, databaseError(err)
	}
	defer rows.Close()
	users := make([]User, 0)
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	if err = rows.Err(); err != nil {
		return nil, databaseError(err)
	}
	return users, nil
}

func (s *Store) CreateUser(actorID, username, password, role string) (User, error) {
	if err := validateUsername(username); err != nil {
		return User{}, err
	}
	if err := validateRole(role); err != nil {
		return User{}, err
	}
	hash, err := hashPassword(password)
	if err != nil {
		return User{}, err
	}
	id, err := newID()
	if err != nil {
		return User{}, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return User{}, databaseError(err)
	}
	defer tx.Rollback()
	if _, err = actor(tx, actorID, true); err != nil {
		return User{}, err
	}
	u := User{ID: id, Username: username, Role: role, CreatedAt: time.Now().UTC(), AuthVersion: 1}
	_, err = tx.Exec("INSERT INTO users(id,username,password_hash,role,created_at) VALUES(?,?,?,?,?)", u.ID, u.Username, hash, u.Role, u.CreatedAt.UnixNano())
	if err != nil {
		return User{}, databaseError(err)
	}
	if err = commit(tx); err != nil {
		return User{}, err
	}
	return u, nil
}

func protectLastAdmin(tx *sql.Tx, u User) error {
	if u.Role != RoleAdmin || u.Disabled {
		return nil
	}
	var count int
	if err := tx.QueryRow("SELECT COUNT(*) FROM users WHERE role='admin' AND disabled=0").Scan(&count); err != nil {
		return databaseError(err)
	}
	if count <= 1 {
		return ErrLastAdmin
	}
	return nil
}

func (s *Store) UpdateUser(actorID, id, username, role string, disabled bool) error {
	tx, err := s.db.Begin()
	if err != nil {
		return databaseError(err)
	}
	defer tx.Rollback()
	if _, err = actor(tx, actorID, true); err != nil {
		return err
	}
	if err = validateUsername(username); err != nil {
		return err
	}
	if err = validateRole(role); err != nil {
		return err
	}
	u, err := scanUser(tx.QueryRow("SELECT "+userColumns+" FROM users WHERE id=?", id))
	if err != nil {
		return err
	}
	if disabled || role != RoleAdmin {
		if err = protectLastAdmin(tx, u); err != nil {
			return err
		}
	}
	if _, err = tx.Exec("UPDATE users SET username=?,role=?,disabled=? WHERE id=?", username, role, disabled, id); err != nil {
		return databaseError(err)
	}
	return commit(tx)
}

func (s *Store) SetPassword(actorID, targetID, password string) error {
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return databaseError(err)
	}
	defer tx.Rollback()
	u, err := actor(tx, actorID, false)
	if err != nil {
		return err
	}
	if targetID != u.ID && u.Role != RoleAdmin {
		return ErrNotFound
	}
	result, err := tx.Exec("UPDATE users SET password_hash=?,auth_version=auth_version+1 WHERE id=?", hash, targetID)
	if err != nil {
		return databaseError(err)
	}
	if err = requireAffected(result); err != nil {
		return err
	}
	return commit(tx)
}

func (s *Store) DeleteUser(actorID, id string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return databaseError(err)
	}
	defer tx.Rollback()
	if _, err = actor(tx, actorID, true); err != nil {
		return err
	}
	u, err := scanUser(tx.QueryRow("SELECT "+userColumns+" FROM users WHERE id=?", id))
	if err != nil {
		return err
	}
	if err = protectLastAdmin(tx, u); err != nil {
		return err
	}
	if _, err = tx.Exec("DELETE FROM users WHERE id=?", id); err != nil {
		return databaseError(err)
	}
	return commit(tx)
}

func requireAffected(result sql.Result) error {
	n, err := result.RowsAffected()
	if err != nil {
		return databaseError(err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) Keys(actorID string) ([]Key, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, databaseError(err)
	}
	defer tx.Rollback()
	u, err := actor(tx, actorID, false)
	if err != nil {
		return nil, err
	}
	query := "SELECT " + keyColumns + " FROM ssh_keys"
	var args []any
	if u.Role != RoleAdmin {
		query += " WHERE user_id=?"
		args = append(args, u.ID)
	}
	query += " ORDER BY created_at,id"
	rows, err := tx.Query(query, args...)
	if err != nil {
		return nil, databaseError(err)
	}
	defer rows.Close()
	keys := make([]Key, 0)
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	if err = rows.Err(); err != nil {
		return nil, databaseError(err)
	}
	return keys, nil
}

func parseKey(publicKey string) (ssh.PublicKey, string, error) {
	publicKey = strings.TrimSpace(publicKey)
	if strings.ContainsAny(publicKey, "\r\n") {
		return nil, "", errors.New("provide exactly one SSH public key")
	}
	pub, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(publicKey))
	if err != nil {
		return nil, "", errors.New("invalid SSH public key")
	}
	if len(options) != 0 || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, "", errors.New("provide one SSH public key without authorized_keys options")
	}
	if _, ok := pub.(*ssh.Certificate); ok {
		return nil, "", errors.New("SSH certificates are not supported")
	}
	return pub, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))), nil
}

func ownedUser(tx *sql.Tx, actor User, ownerID string) error {
	if actor.Role != RoleAdmin && ownerID != actor.ID {
		return ErrNotFound
	}
	var exists bool
	if err := tx.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE id=?)", ownerID).Scan(&exists); err != nil {
		return databaseError(err)
	}
	if !exists {
		return ErrNotFound
	}
	return nil
}

func (s *Store) AddKey(actorID, userID, name, publicKey string) (Key, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return Key{}, databaseError(err)
	}
	defer tx.Rollback()
	u, err := actor(tx, actorID, false)
	if err != nil {
		return Key{}, err
	}
	if err = ownedUser(tx, u, userID); err != nil {
		return Key{}, err
	}
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > 128 || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return Key{}, errors.New("key name must contain 1–128 printable characters")
	}
	pub, normalized, err := parseKey(publicKey)
	if err != nil {
		return Key{}, err
	}
	id, err := newID()
	if err != nil {
		return Key{}, err
	}
	k := Key{ID: id, UserID: userID, Name: name, PublicKey: normalized, Fingerprint: ssh.FingerprintSHA256(pub), CreatedAt: time.Now().UTC()}
	_, err = tx.Exec("INSERT INTO ssh_keys(id,user_id,name,public_key,fingerprint,created_at) VALUES(?,?,?,?,?,?)", k.ID, k.UserID, k.Name, k.PublicKey, k.Fingerprint, k.CreatedAt.UnixNano())
	if err != nil {
		return Key{}, databaseError(err)
	}
	if err = commit(tx); err != nil {
		return Key{}, err
	}
	return k, nil
}

func (s *Store) DeleteKey(actorID, id string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return databaseError(err)
	}
	defer tx.Rollback()
	u, err := actor(tx, actorID, false)
	if err != nil {
		return err
	}
	query := "DELETE FROM ssh_keys WHERE id=?"
	args := []any{id}
	if u.Role != RoleAdmin {
		query += " AND user_id=?"
		args = append(args, u.ID)
	}
	result, err := tx.Exec(query, args...)
	if err != nil {
		return databaseError(err)
	}
	if err = requireAffected(result); err != nil {
		return err
	}
	return commit(tx)
}

func (s *Store) AuthenticateKey(pub ssh.PublicKey) (User, Key, error) {
	if pub == nil {
		return User{}, Key{}, ErrAuthentication
	}
	if _, ok := pub.(*ssh.Certificate); ok {
		return User{}, Key{}, ErrAuthentication
	}
	tx, err := s.db.Begin()
	if err != nil {
		return User{}, Key{}, databaseError(err)
	}
	defer tx.Rollback()
	k, err := scanKey(tx.QueryRow("SELECT "+keyColumns+" FROM ssh_keys WHERE fingerprint=?", ssh.FingerprintSHA256(pub)))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return User{}, Key{}, ErrAuthentication
		}
		return User{}, Key{}, err
	}
	u, err := actor(tx, k.UserID, false)
	if err != nil {
		if errors.Is(err, ErrUnauthorized) {
			return User{}, Key{}, ErrAuthentication
		}
		return User{}, Key{}, err
	}
	return u, k, nil
}

// ValidateSource accepts a repository name with or without a .git suffix.
// Canonical segments prevent path traversal and shell metacharacters.
func ValidateSource(source string) error {
	if source == "" || strings.HasPrefix(source, "/") || !pathPattern.MatchString(source) {
		return errors.New("repository path must contain letters, digits, dots, underscores, hyphens and slashes without a leading slash")
	}
	for _, segment := range strings.Split(source, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return errors.New("repository path must not contain empty, dot or parent segments")
		}
	}
	return nil
}

// RepositoryPath appends the conventional Git suffix after path validation.
func RepositoryPath(path string) string {
	if strings.HasSuffix(path, ".git") {
		return path
	}
	return path + ".git"
}

// UpstreamHost supplies the default when no hostname was entered.
func UpstreamHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return "github.com"
	}
	return host
}

// ValidateDestination checks the upstream address used by routes and identity discovery.
func ValidateDestination(host string, port int) error {
	if host == "" || len(host) > 253 {
		return errors.New("invalid upstream host")
	}
	if net.ParseIP(host) == nil {
		for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
			if len(label) > 63 || !hostLabelPattern.MatchString(label) {
				return errors.New("upstream host must be a DNS name or an unbracketed IP address")
			}
		}
	}
	if port < 1 || port > 65535 {
		return errors.New("upstream port must be between 1 and 65535")
	}
	return nil
}

func validateMapping(m *Mapping) error {
	if err := ValidateSource(m.Source); err != nil {
		return err
	}
	if err := ValidateSource(strings.TrimPrefix(m.RemotePath, "/")); err != nil {
		return fmt.Errorf("remote path: %w", err)
	}
	if !remoteUserPattern.MatchString(m.RemoteUser) {
		return errors.New("remote user must contain only letters, digits, dots, underscores or hyphens")
	}
	m.Source = RepositoryPath(m.Source)
	m.RemotePath = RepositoryPath(m.RemotePath)
	m.Host = UpstreamHost(m.Host)
	if err := ValidateDestination(m.Host, m.Port); err != nil {
		return err
	}
	if !strings.HasPrefix(m.HostFingerprint, "SHA256:") {
		return errors.New("host fingerprint must be a SHA256 SSH fingerprint")
	}
	encoded := strings.TrimPrefix(m.HostFingerprint, "SHA256:")
	digest, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		digest, err = base64.StdEncoding.DecodeString(encoded)
	}
	if err != nil || len(digest) != sha256.Size {
		return errors.New("host fingerprint must contain a base64-encoded 32-byte SHA256 digest")
	}
	m.HostFingerprint = "SHA256:" + base64.RawStdEncoding.EncodeToString(digest)
	return nil
}

func (s *Store) Mappings(actorID string) ([]Mapping, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, databaseError(err)
	}
	defer tx.Rollback()
	u, err := actor(tx, actorID, false)
	if err != nil {
		return nil, err
	}
	query := "SELECT " + mappingColumns + " FROM mappings"
	var args []any
	if u.Role != RoleAdmin {
		query += " WHERE user_id=?"
		args = append(args, u.ID)
	}
	query += " ORDER BY source,key_id,id"
	rows, err := tx.Query(query, args...)
	if err != nil {
		return nil, databaseError(err)
	}
	defer rows.Close()
	mappings := make([]Mapping, 0)
	for rows.Next() {
		m, err := scanMapping(rows)
		if err != nil {
			return nil, err
		}
		mappings = append(mappings, m)
	}
	if err = rows.Err(); err != nil {
		return nil, databaseError(err)
	}
	return mappings, nil
}

func (s *Store) SaveMapping(actorID string, m Mapping) (Mapping, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return Mapping{}, databaseError(err)
	}
	defer tx.Rollback()
	u, err := actor(tx, actorID, false)
	if err != nil {
		return Mapping{}, err
	}
	// Check the existing owner before considering a new owner, so knowledge of
	// another user's identifier never grants permission to overwrite it.
	if m.ID != "" {
		old, err := scanMapping(tx.QueryRow("SELECT "+mappingColumns+" FROM mappings WHERE id=?", m.ID))
		if err != nil {
			return Mapping{}, err
		}
		if u.Role != RoleAdmin && old.UserID != u.ID {
			return Mapping{}, ErrNotFound
		}
		m.CreatedAt = old.CreatedAt
	}
	if err = ownedUser(tx, u, m.UserID); err != nil {
		return Mapping{}, err
	}
	if m.KeyID != "" {
		var belongs bool
		if err = tx.QueryRow("SELECT EXISTS(SELECT 1 FROM ssh_keys WHERE id=? AND user_id=?)", m.KeyID, m.UserID).Scan(&belongs); err != nil {
			return Mapping{}, databaseError(err)
		}
		if !belongs {
			return Mapping{}, ErrNotFound
		}
	}
	if err = validateMapping(&m); err != nil {
		return Mapping{}, err
	}
	var keyID any
	if m.KeyID != "" {
		keyID = m.KeyID
	}
	if m.ID == "" {
		m.ID, err = newID()
		if err != nil {
			return Mapping{}, err
		}
		m.CreatedAt = time.Now().UTC()
		_, err = tx.Exec("INSERT INTO mappings(id,user_id,key_id,source,host,remote_user,remote_path,host_fingerprint,port,read_only,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)", m.ID, m.UserID, keyID, m.Source, m.Host, m.RemoteUser, m.RemotePath, m.HostFingerprint, m.Port, m.ReadOnly, m.CreatedAt.UnixNano())
	} else {
		_, err = tx.Exec("UPDATE mappings SET user_id=?,key_id=?,source=?,host=?,remote_user=?,remote_path=?,host_fingerprint=?,port=?,read_only=? WHERE id=?", m.UserID, keyID, m.Source, m.Host, m.RemoteUser, m.RemotePath, m.HostFingerprint, m.Port, m.ReadOnly, m.ID)
	}
	if err != nil {
		return Mapping{}, databaseError(err)
	}
	if err = commit(tx); err != nil {
		return Mapping{}, err
	}
	return m, nil
}

func (s *Store) DeleteMapping(actorID, id string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return databaseError(err)
	}
	defer tx.Rollback()
	u, err := actor(tx, actorID, false)
	if err != nil {
		return err
	}
	query := "DELETE FROM mappings WHERE id=?"
	args := []any{id}
	if u.Role != RoleAdmin {
		query += " AND user_id=?"
		args = append(args, u.ID)
	}
	result, err := tx.Exec(query, args...)
	if err != nil {
		return databaseError(err)
	}
	if err = requireAffected(result); err != nil {
		return err
	}
	return commit(tx)
}

func (s *Store) Resolve(userID, keyID, source string) (Mapping, error) {
	if err := ValidateSource(source); err != nil {
		return Mapping{}, err
	}
	source = RepositoryPath(source)
	tx, err := s.db.Begin()
	if err != nil {
		return Mapping{}, databaseError(err)
	}
	defer tx.Rollback()
	if _, err = actor(tx, userID, false); err != nil {
		return Mapping{}, err
	}
	var belongs bool
	if err = tx.QueryRow("SELECT EXISTS(SELECT 1 FROM ssh_keys WHERE id=? AND user_id=?)", keyID, userID).Scan(&belongs); err != nil {
		return Mapping{}, databaseError(err)
	}
	if !belongs {
		return Mapping{}, ErrNotFound
	}
	return scanMapping(tx.QueryRow("SELECT "+mappingColumns+" FROM mappings WHERE user_id=? AND source=? AND (key_id=? OR key_id IS NULL) ORDER BY (key_id IS NOT NULL) DESC LIMIT 1", userID, source, keyID))
}

func (s *Store) GetSettings() Settings {
	settings := defaultSettings()
	var persisted Settings
	if s.db.QueryRow("SELECT banner,max_sessions_per_user,session_timeout_minutes FROM settings WHERE id=1").Scan(&persisted.Banner, &persisted.MaxSessionsPerUser, &persisted.SessionTimeoutMinutes) == nil {
		settings = persisted
	}
	return settings
}

func (s *Store) SaveSettings(actorID string, settings Settings) error {
	tx, err := s.db.Begin()
	if err != nil {
		return databaseError(err)
	}
	defer tx.Rollback()
	if _, err = actor(tx, actorID, true); err != nil {
		return err
	}
	if settings.MaxSessionsPerUser < 1 {
		return errors.New("maximum sessions per user must be positive")
	}
	if settings.SessionTimeoutMinutes < 1 || int64(settings.SessionTimeoutMinutes) > int64((time.Duration(1<<63-1))/time.Minute) {
		return errors.New("session timeout must be positive and fit within a Go duration")
	}
	_, err = tx.Exec("UPDATE settings SET banner=?,max_sessions_per_user=?,session_timeout_minutes=? WHERE id=1", settings.Banner, settings.MaxSessionsPerUser, settings.SessionTimeoutMinutes)
	if err != nil {
		return databaseError(err)
	}
	return commit(tx)
}
