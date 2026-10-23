package store_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/kirito/git-proxy/internal/store"
	"golang.org/x/crypto/ssh"
)

const password = "a sufficiently long password"

func openStore(t *testing.T) (*store.Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "proxy.db")
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, path
}

func bootstrap(t *testing.T, db *store.Store) store.User {
	t.Helper()
	u, err := db.Bootstrap("administrator", password)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func createUser(t *testing.T, db *store.Store, admin store.User, name, role string) store.User {
	t.Helper()
	u, err := db.CreateUser(admin.ID, name, password, role)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func publicKey(t *testing.T) (ssh.PublicKey, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return key, string(ssh.MarshalAuthorizedKey(key))
}

func addKey(t *testing.T, db *store.Store, user store.User, name string) (store.Key, ssh.PublicKey) {
	t.Helper()
	pub, text := publicKey(t)
	key, err := db.AddKey(user.ID, user.ID, name, text)
	if err != nil {
		t.Fatal(err)
	}
	return key, pub
}

func mapping(userID, keyID, source string) store.Mapping {
	return store.Mapping{UserID: userID, KeyID: keyID, Source: source, Host: "git.example.com", RemoteUser: "git", RemotePath: "/srv/git/repository.git", HostFingerprint: "SHA256:" + strings.Repeat("A", 43), Port: 22}
}

func saveMapping(t *testing.T, db *store.Store, actorID string, m store.Mapping) store.Mapping {
	t.Helper()
	saved, err := db.SaveMapping(actorID, m)
	if err != nil {
		t.Fatal(err)
	}
	return saved
}

func expectError(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}

func TestKeyScopedPrecedenceAndRevocation(t *testing.T) {
	db, _ := openStore(t)
	admin := bootstrap(t, db)
	owner := createUser(t, db, admin, "owner", store.RoleUser)
	keyA, pubA := addKey(t, db, owner, "laptop")
	keyB, _ := addKey(t, db, owner, "desktop")
	general := saveMapping(t, db, owner.ID, mapping(owner.ID, "", "team/repo.git"))
	specificInput := mapping(owner.ID, keyA.ID, "team/repo.git")
	specificInput.Host = "special.example.com"
	specific := saveMapping(t, db, owner.ID, specificInput)
	for _, tc := range []struct{ key, want string }{{keyA.ID, specific.ID}, {keyB.ID, general.ID}} {
		got, err := db.Resolve(owner.ID, tc.key, "team/repo.git")
		if err != nil {
			t.Fatal(err)
		}
		if got.ID != tc.want {
			t.Fatalf("key %s resolved %s, want %s", tc.key, got.ID, tc.want)
		}
	}
	_, err := db.Resolve(owner.ID, keyA.ID, "team/repo")
	expectError(t, err, store.ErrNotFound)
	_, err = db.Resolve(owner.ID, "", "team/repo.git")
	expectError(t, err, store.ErrNotFound)
	_, err = db.SaveMapping(owner.ID, mapping(owner.ID, "", "team/repo.git"))
	expectError(t, err, store.ErrConflict)
	if err = db.DeleteMapping(owner.ID, specific.ID); err != nil {
		t.Fatal(err)
	}
	got, err := db.Resolve(owner.ID, keyA.ID, "team/repo.git")
	if err != nil || got.ID != general.ID {
		t.Fatalf("fallback = %+v, %v", got, err)
	}
	_ = saveMapping(t, db, owner.ID, specificInput)
	if err = db.DeleteKey(owner.ID, keyA.ID); err != nil {
		t.Fatal(err)
	}
	_, _, err = db.AuthenticateKey(pubA)
	expectError(t, err, store.ErrAuthentication)
	_, err = db.Resolve(owner.ID, keyA.ID, "team/repo.git")
	expectError(t, err, store.ErrNotFound)
	mappings, err := db.Mappings(owner.ID)
	if err != nil || len(mappings) != 1 || mappings[0].ID != general.ID {
		t.Fatalf("key cascade = %+v, %v", mappings, err)
	}
	if err = db.UpdateUser(admin.ID, owner.ID, owner.Username, owner.Role, true); err != nil {
		t.Fatal(err)
	}
	_, err = db.Resolve(owner.ID, keyB.ID, "team/repo.git")
	expectError(t, err, store.ErrUnauthorized)
}

func TestCrossUserAuthorizationHidesRecords(t *testing.T) {
	db, _ := openStore(t)
	admin := bootstrap(t, db)
	alice := createUser(t, db, admin, "alice", store.RoleUser)
	bob := createUser(t, db, admin, "bobby", store.RoleUser)
	key, _ := addKey(t, db, bob, "workstation")
	bobMapping := saveMapping(t, db, bob.ID, mapping(bob.ID, key.ID, "private/repo"))
	for _, id := range []string{bobMapping.ID, "missing-mapping"} {
		err := db.DeleteMapping(alice.ID, id)
		expectError(t, err, store.ErrNotFound)
		attempt := bobMapping
		attempt.ID = id
		attempt.UserID = alice.ID
		attempt.KeyID = ""
		_, err = db.SaveMapping(alice.ID, attempt)
		expectError(t, err, store.ErrNotFound)
	}
	for _, id := range []string{key.ID, "missing-key"} {
		expectError(t, db.DeleteKey(alice.ID, id), store.ErrNotFound)
	}
	for _, id := range []string{bob.ID, "missing-user"} {
		expectError(t, db.SetPassword(alice.ID, id, password+" changed"), store.ErrNotFound)
		expectError(t, db.DeleteUser(alice.ID, id), store.ErrUnauthorized)
		expectError(t, db.UpdateUser(alice.ID, id, "renamed", store.RoleAdmin, false), store.ErrUnauthorized)
	}
	_, err := db.Users(alice.ID)
	expectError(t, err, store.ErrUnauthorized)
	_, err = db.CreateUser(alice.ID, "hacker", password, store.RoleAdmin)
	expectError(t, err, store.ErrUnauthorized)
	_, err = db.AddKey(alice.ID, bob.ID, "stolen", key.PublicKey)
	expectError(t, err, store.ErrNotFound)
	_, err = db.SaveMapping(alice.ID, mapping(alice.ID, key.ID, "stolen"))
	expectError(t, db.SaveSettings(alice.ID, db.GetSettings()), store.ErrUnauthorized)
	expectError(t, err, store.ErrNotFound)
	_, err = db.Resolve(alice.ID, key.ID, bobMapping.Source)
	expectError(t, err, store.ErrNotFound)
	keys, err := db.Keys(alice.ID)
	if err != nil || len(keys) != 0 {
		t.Fatalf("alice keys = %+v, %v", keys, err)
	}
	mappings, err := db.Mappings(alice.ID)
	if err != nil || len(mappings) != 0 {
		t.Fatalf("alice mappings = %+v, %v", mappings, err)
	}
	keys, err = db.Keys(admin.ID)
	if err != nil || len(keys) != 1 {
		t.Fatalf("admin keys = %+v, %v", keys, err)
	}
	_, err = db.SaveMapping(admin.ID, mapping(alice.ID, key.ID, "wrong-owner"))
	expectError(t, err, store.ErrNotFound)
	_, err = db.AddKey(admin.ID, alice.ID, "duplicate", key.PublicKey)
	expectError(t, err, store.ErrConflict)
	if err = db.DeleteUser(admin.ID, bob.ID); err != nil {
		t.Fatal(err)
	}
	keys, err = db.Keys(admin.ID)
	if err != nil || len(keys) != 0 {
		t.Fatalf("deleted user keys = %+v, %v", keys, err)
	}
	mappings, err = db.Mappings(admin.ID)
	if err != nil || len(mappings) != 0 {
		t.Fatalf("deleted user mappings = %+v, %v", mappings, err)
	}
}

func TestDisabledActorsAreRejected(t *testing.T) {
	db, _ := openStore(t)
	admin := bootstrap(t, db)
	user := createUser(t, db, admin, "disabled", store.RoleUser)
	key, pub := addKey(t, db, user, "laptop")
	m := saveMapping(t, db, user.ID, mapping(user.ID, "", "repo"))
	if err := db.UpdateUser(admin.ID, user.ID, user.Username, user.Role, true); err != nil {
		t.Fatal(err)
	}
	_, err := db.Authenticate(user.Username, password)
	expectError(t, err, store.ErrAuthentication)
	_, _, err = db.AuthenticateKey(pub)
	expectError(t, err, store.ErrAuthentication)
	_, err = db.Keys(user.ID)
	expectError(t, err, store.ErrUnauthorized)
	_, err = db.Mappings(user.ID)
	expectError(t, err, store.ErrUnauthorized)
	_, err = db.Users(user.ID)
	expectError(t, err, store.ErrUnauthorized)
	_, err = db.AddKey(user.ID, user.ID, "newkey", key.PublicKey)
	expectError(t, err, store.ErrUnauthorized)
	_, err = db.SaveMapping(user.ID, m)
	expectError(t, err, store.ErrUnauthorized)
	expectError(t, db.DeleteKey(user.ID, key.ID), store.ErrUnauthorized)
	expectError(t, db.DeleteMapping(user.ID, m.ID), store.ErrUnauthorized)
	expectError(t, db.SetPassword(user.ID, user.ID, password+" changed"), store.ErrUnauthorized)
	expectError(t, db.SaveSettings(user.ID, db.GetSettings()), store.ErrUnauthorized)
	_, err = db.Resolve(user.ID, key.ID, "repo")
	expectError(t, err, store.ErrUnauthorized)
	loaded, err := db.User(user.ID)
	if err != nil || !loaded.Disabled {
		t.Fatalf("raw lookup must preserve disabled flag: %+v, %v", loaded, err)
	}
}

func TestLastEnabledAdminProtection(t *testing.T) {
	db, _ := openStore(t)
	admin := bootstrap(t, db)
	expectError(t, db.DeleteUser(admin.ID, admin.ID), store.ErrLastAdmin)
	expectError(t, db.UpdateUser(admin.ID, admin.ID, admin.Username, store.RoleUser, false), store.ErrLastAdmin)
	expectError(t, db.UpdateUser(admin.ID, admin.ID, admin.Username, store.RoleAdmin, true), store.ErrLastAdmin)
	other := createUser(t, db, admin, "second-admin", store.RoleAdmin)
	if err := db.UpdateUser(admin.ID, other.ID, other.Username, other.Role, true); err != nil {
		t.Fatal(err)
	}
	expectError(t, db.DeleteUser(admin.ID, admin.ID), store.ErrLastAdmin)
	if err := db.UpdateUser(admin.ID, other.ID, other.Username, other.Role, false); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateUser(admin.ID, admin.ID, admin.Username, store.RoleUser, false); err != nil {
		t.Fatal(err)
	}
	expectError(t, db.DeleteUser(admin.ID, other.ID), store.ErrUnauthorized)
	if err := db.DeleteUser(other.ID, admin.ID); err != nil {
		t.Fatal(err)
	}
	expectError(t, db.DeleteUser(other.ID, other.ID), store.ErrLastAdmin)
}

func TestLastAdminConcurrentMutations(t *testing.T) {
	for _, operation := range []string{"delete", "disable", "demote"} {
		t.Run(operation, func(t *testing.T) {
			db, path := openStore(t)
			first := bootstrap(t, db)
			second := createUser(t, db, first, "second-admin", store.RoleAdmin)
			other, err := store.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = other.Close() })
			start := make(chan struct{})
			results := make(chan error, 2)
			for i, u := range []store.User{first, second} {
				connection := db
				if i == 1 {
					connection = other
				}
				go func(db *store.Store, u store.User) {
					<-start
					switch operation {
					case "delete":
						results <- db.DeleteUser(u.ID, u.ID)
					case "disable":
						results <- db.UpdateUser(u.ID, u.ID, u.Username, u.Role, true)
					case "demote":
						results <- db.UpdateUser(u.ID, u.ID, u.Username, store.RoleUser, false)
					}
				}(connection, u)
			}
			close(start)
			var succeeded, protected int
			for range 2 {
				err := <-results
				if err == nil {
					succeeded++
				} else if errors.Is(err, store.ErrLastAdmin) {
					protected++
				} else {
					t.Fatalf("unexpected concurrent result: %v", err)
				}
			}
			if succeeded != 1 || protected != 1 {
				t.Fatalf("successes = %d, protected = %d", succeeded, protected)
			}
			var remaining store.User
			for _, u := range []store.User{first, second} {
				current, err := db.User(u.ID)
				if err == nil && current.Role == store.RoleAdmin && !current.Disabled {
					remaining = current
				}
			}
			if remaining.ID == "" {
				t.Fatal("no enabled administrator survived")
			}
		})
	}
}

func TestBootstrapAtomicAcrossConnections(t *testing.T) {
	db, path := openStore(t)
	if db.Initialized() {
		t.Fatal("new store is initialized")
	}
	other, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Close() })
	start := make(chan struct{})
	results := make(chan error, 8)
	var workers sync.WaitGroup
	for i := range 8 {
		workers.Add(1)
		connection := db
		if i%2 == 1 {
			connection = other
		}
		go func(i int, db *store.Store) {
			defer workers.Done()
			<-start
			_, err := db.Bootstrap(fmt.Sprintf("admin-%d", i), password)
			results <- err
		}(i, connection)
	}
	close(start)
	workers.Wait()
	close(results)
	var succeeded int
	for err := range results {
		if err == nil {
			succeeded++
		} else {
			expectError(t, err, store.ErrInitialized)
		}
	}
	if succeeded != 1 {
		t.Fatalf("bootstrap winners = %d, want 1", succeeded)
	}
	if !db.Initialized() || !other.Initialized() {
		t.Fatal("bootstrap state not shared")
	}
	_, err = other.Bootstrap("another-admin", password)
	expectError(t, err, store.ErrInitialized)
}

func TestPasswordLimitsAndRevision(t *testing.T) {
	db, _ := openStore(t)
	admin := bootstrap(t, db)
	longPassword := strings.Repeat("x", 1000) + "suffix"
	user, err := db.CreateUser(admin.ID, "long-password", longPassword, store.RoleUser)
	if err != nil {
		t.Fatal(err)
	}
	if user.AuthVersion != 1 {
		t.Fatalf("initial auth version = %d", user.AuthVersion)
	}
	_, err = db.Authenticate(user.Username, longPassword)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Authenticate(user.Username, strings.Repeat("x", 1000)+"wrong!")
	expectError(t, err, store.ErrAuthentication)
	_, err = db.Authenticate("missing-user", longPassword)
	expectError(t, err, store.ErrAuthentication)
	for _, invalid := range []string{"short", strings.Repeat("x", 1025)} {
		if err := db.SetPassword(user.ID, user.ID, invalid); err == nil {
			t.Fatal("invalid password accepted")
		}
	}
	if err = db.SetPassword(user.ID, user.ID, password); err != nil {
		t.Fatal(err)
	}
	loaded, err := db.User(user.ID)
	if err != nil || loaded.AuthVersion != 2 {
		t.Fatalf("revised user = %+v, %v", loaded, err)
	}
	_, err = db.Authenticate(user.Username, longPassword)
	expectError(t, err, store.ErrAuthentication)
	authenticated, err := db.Authenticate(user.Username, password)
	if err != nil || authenticated.AuthVersion != 2 {
		t.Fatalf("authenticated = %+v, %v", authenticated, err)
	}
}

func TestValidationAndNormalization(t *testing.T) {
	db, _ := openStore(t)
	admin := bootstrap(t, db)
	for _, source := range []string{"", "/repo", "a//b", "a/./b", "a/../b", "repo/", "repo;id", "repo'", "repo\n"} {
		if err := store.ValidateSource(source); err == nil {
			t.Errorf("accepted source %q", source)
		}
	}
	for _, source := range []string{"repo", "team/repo.git", "A_1/a-b.c"} {
		if err := store.ValidateSource(source); err != nil {
			t.Errorf("rejected source %q: %v", source, err)
		}
	}
	pub, text := publicKey(t)
	for _, invalid := range []string{"command=\"id\" " + text, "restrict " + text, text + text, "# ignored\n" + text, "not a key"} {
		if _, err := db.AddKey(admin.ID, admin.ID, "invalid-key", invalid); err == nil {
			t.Errorf("accepted invalid key %q", invalid)
		}
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &ssh.Certificate{Key: pub, CertType: ssh.UserCert, KeyId: "test"}
	if err = certificate.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}
	if _, err = db.AddKey(admin.ID, admin.ID, "certificate", string(ssh.MarshalAuthorizedKey(certificate))); err == nil {
		t.Fatal("certificate accepted")
	}
	key, err := db.AddKey(admin.ID, admin.ID, "normalized", strings.TrimSpace(text)+" comment")
	if err != nil {
		t.Fatal(err)
	}
	if key.PublicKey != strings.TrimSpace(text) {
		t.Fatalf("key not normalized: %q", key.PublicKey)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*store.Mapping)
	}{
		{"shell-host", func(m *store.Mapping) { m.Host = "host;id" }},
		{"host-space", func(m *store.Mapping) { m.Host = "example.com " }},
		{"host-option", func(m *store.Mapping) { m.Host = "-oProxyCommand" }},
		{"host-port", func(m *store.Mapping) { m.Host = "host:22" }},
		{"bad-label", func(m *store.Mapping) { m.Host = "bad_.example" }},
		{"shell-user", func(m *store.Mapping) { m.RemoteUser = "git;id" }},
		{"remote-parent", func(m *store.Mapping) { m.RemotePath = "/srv/../repo" }},
		{"remote-root", func(m *store.Mapping) { m.RemotePath = "/" }},
		{"zero-port", func(m *store.Mapping) { m.Port = 0 }},
		{"large-port", func(m *store.Mapping) { m.Port = 65536 }},
		{"short-pin", func(m *store.Mapping) { m.HostFingerprint = "SHA256:AAAA" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := mapping(admin.ID, "", "repo")
			tc.mutate(&m)
			if _, err := db.SaveMapping(admin.ID, m); err == nil {
				t.Fatal("invalid mapping accepted")
			}
		})
	}
	m := mapping(admin.ID, "", "repo")
	m.Host = "2001:db8::1"
	m.HostFingerprint += "="
	m = saveMapping(t, db, admin.ID, m)
	if strings.HasSuffix(m.HostFingerprint, "=") {
		t.Fatal("fingerprint padding was not normalized")
	}
}

func TestPersistenceSettingsAndPermissions(t *testing.T) {
	db, path := openStore(t)
	admin := bootstrap(t, db)
	defaults := db.GetSettings()
	if defaults.Banner != "Git Proxy" || defaults.MaxSessionsPerUser != 8 || defaults.SessionTimeoutMinutes != 120 {
		t.Fatalf("defaults = %+v", defaults)
	}
	settings := store.Settings{Banner: "Company Git", MaxSessionsPerUser: 4, SessionTimeoutMinutes: 30}
	if err := db.SaveSettings(admin.ID, settings); err != nil {
		t.Fatal(err)
	}
	key, _ := addKey(t, db, admin, "persistent")
	original := saveMapping(t, db, admin.ID, mapping(admin.ID, key.ID, "persisted/repo.git"))
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if reopened.GetSettings() != settings {
		t.Fatalf("persisted settings = %+v", reopened.GetSettings())
	}
	resolved, err := reopened.Resolve(admin.ID, key.ID, original.Source)
	if err != nil || resolved.ID != original.ID || !resolved.CreatedAt.Equal(original.CreatedAt) {
		t.Fatalf("persisted mapping = %+v, %v", resolved, err)
	}
	loaded, err := reopened.Authenticate(admin.Username, password)
	if err != nil || loaded.ID != admin.ID {
		t.Fatalf("persisted login = %+v, %v", loaded, err)
	}
	stat, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if stat.Mode().Perm() != 0600 {
		t.Fatalf("database permissions = %o", stat.Mode().Perm())
	}
}

func TestKeyDisplayName(t *testing.T) {
	db, _ := openStore(t)
	u := bootstrap(t, db)
	_, pub := publicKey(t)
	key, err := db.AddKey(u.ID, u.ID, "  Work laptop 日本語  ", pub)
	if err != nil || key.Name != "Work laptop 日本語" {
		t.Fatalf("readable key label: %+v %v", key, err)
	}
	for _, name := range []string{"", "\x1b[31munsafe", "line\nbreak", strings.Repeat("界", 129)} {
		_, text := publicKey(t)
		if _, err := db.AddKey(u.ID, u.ID, name, text); err == nil {
			t.Errorf("accepted invalid label %q", name)
		}
	}
}
