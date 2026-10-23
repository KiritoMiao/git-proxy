package store_test

import (
	"database/sql"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/kirito/git-proxy/internal/store"
)

func catchAllDestination() store.DefaultDestination {
	return store.DefaultDestination{
		Enabled: true, Host: "fallback.example.com", Port: 2222, RemoteUser: "git-proxy",
		HostFingerprint: "SHA256:" + strings.Repeat("A", 43), ReadOnly: true,
	}
}

func TestDefaultDestinationAdminAuthorization(t *testing.T) {
	db, _ := openStore(t)
	admin := bootstrap(t, db)
	user := createUser(t, db, admin, "ordinary", store.RoleUser)
	otherAdmin := createUser(t, db, admin, "other-admin", store.RoleAdmin)
	destination := catchAllDestination()
	if err := db.SaveDefaultDestination(admin.ID, destination); err != nil {
		t.Fatal(err)
	}
	for _, actorID := range []string{"", "missing", user.ID} {
		_, err := db.GetDefaultDestination(actorID)
		expectError(t, err, store.ErrUnauthorized)
		expectError(t, db.SaveDefaultDestination(actorID, store.DefaultDestination{}), store.ErrUnauthorized)
	}
	if err := db.UpdateUser(admin.ID, otherAdmin.ID, otherAdmin.Username, store.RoleAdmin, true); err != nil {
		t.Fatal(err)
	}
	_, err := db.GetDefaultDestination(otherAdmin.ID)
	expectError(t, err, store.ErrUnauthorized)
	expectError(t, db.SaveDefaultDestination(otherAdmin.ID, destination), store.ErrUnauthorized)
	if err = db.UpdateUser(admin.ID, otherAdmin.ID, otherAdmin.Username, store.RoleUser, false); err != nil {
		t.Fatal(err)
	}
	_, err = db.GetDefaultDestination(otherAdmin.ID)
	expectError(t, err, store.ErrUnauthorized)
	expectError(t, db.SaveDefaultDestination(otherAdmin.ID, destination), store.ErrUnauthorized)
	got, err := db.GetDefaultDestination(admin.ID)
	if err != nil || got != destination {
		t.Fatalf("destination after rejected writes = %+v, %v", got, err)
	}
}

func TestDefaultDestinationDefaultsDisabledAndPersistence(t *testing.T) {
	db, path := openStore(t)
	admin := bootstrap(t, db)
	key, _ := addKey(t, db, admin, "laptop")
	settings := db.GetSettings()
	defaults := store.DefaultDestination{Host: "github.com", Port: 22, RemoteUser: "git"}
	got, err := db.GetDefaultDestination(admin.ID)
	if err != nil || got != defaults {
		t.Fatalf("missing singleton = %+v, %v", got, err)
	}
	_, err = db.Resolve(admin.ID, key.ID, "owner/repository")
	expectError(t, err, store.ErrNotFound)
	if err = db.SaveDefaultDestination(admin.ID, store.DefaultDestination{}); err != nil {
		t.Fatalf("disabled destination without pin: %v", err)
	}
	got, err = db.GetDefaultDestination(admin.ID)
	if err != nil || got != defaults {
		t.Fatalf("saved zero value defaults = %+v, %v", got, err)
	}
	_, err = db.Resolve(admin.ID, key.ID, "owner/repository")
	expectError(t, err, store.ErrNotFound)
	destination := catchAllDestination()
	if err = db.SaveDefaultDestination(admin.ID, destination); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	got, err = reopened.GetDefaultDestination(admin.ID)
	if err != nil || got != destination {
		t.Fatalf("persisted destination = %+v, %v", got, err)
	}
	if gotSettings := reopened.GetSettings(); gotSettings != settings {
		t.Fatalf("settings changed from %+v to %+v", settings, gotSettings)
	}
	resolved, err := reopened.Resolve(admin.ID, key.ID, "owner/repository")
	if err != nil || resolved.Host != destination.Host || !resolved.ReadOnly {
		t.Fatalf("persisted resolution = %+v, %v", resolved, err)
	}
	destination.Enabled = false
	if err = reopened.SaveDefaultDestination(admin.ID, destination); err != nil {
		t.Fatal(err)
	}
	_, err = reopened.Resolve(admin.ID, key.ID, "owner/repository")
	expectError(t, err, store.ErrNotFound)
}

func TestDefaultDestinationValidationAndNormalization(t *testing.T) {
	db, _ := openStore(t)
	admin := bootstrap(t, db)
	original := catchAllDestination()
	if err := db.SaveDefaultDestination(admin.ID, original); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*store.DefaultDestination)
	}{
		{"host shell", func(d *store.DefaultDestination) { d.Host = "host;id" }},
		{"host option", func(d *store.DefaultDestination) { d.Host = "-oProxyCommand=id" }},
		{"host newline", func(d *store.DefaultDestination) { d.Host = "git.example.com\nother" }},
		{"host user", func(d *store.DefaultDestination) { d.Host = "git@github.com" }},
		{"port low", func(d *store.DefaultDestination) { d.Port = -1 }},
		{"port high", func(d *store.DefaultDestination) { d.Port = 65536 }},
		{"user shell", func(d *store.DefaultDestination) { d.RemoteUser = "git;id" }},
		{"pin missing", func(d *store.DefaultDestination) { d.HostFingerprint = "" }},
		{"pin algorithm", func(d *store.DefaultDestination) { d.HostFingerprint = "MD5:00:00" }},
		{"pin bytes", func(d *store.DefaultDestination) { d.HostFingerprint = "SHA256:AAAA" }},
		{"pin malformed", func(d *store.DefaultDestination) { d.HostFingerprint = "SHA256:$(id)" }},
		{"disabled unsafe host", func(d *store.DefaultDestination) { d.Enabled = false; d.Host = "bad host" }},
		{"disabled unsafe user", func(d *store.DefaultDestination) { d.Enabled = false; d.RemoteUser = "git\nroot" }},
		{"disabled malformed pin", func(d *store.DefaultDestination) { d.Enabled = false; d.HostFingerprint = "SHA256:bad" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			invalid := original
			tc.change(&invalid)
			if err := db.SaveDefaultDestination(admin.ID, invalid); err == nil {
				t.Fatal("invalid destination accepted")
			}
			got, err := db.GetDefaultDestination(admin.ID)
			if err != nil || got != original {
				t.Fatalf("destination after failed validation = %+v, %v", got, err)
			}
		})
	}
	normalized := original
	normalized.Host = "  "
	normalized.HostFingerprint = "SHA256:" + base64.StdEncoding.EncodeToString(make([]byte, 32))
	if err := db.SaveDefaultDestination(admin.ID, normalized); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetDefaultDestination(admin.ID)
	if err != nil || got.Host != "github.com" || got.HostFingerprint != original.HostFingerprint {
		t.Fatalf("normalized destination = %+v, %v", got, err)
	}
}

func TestDefaultDestinationResolutionAndRoutePrecedence(t *testing.T) {
	db, _ := openStore(t)
	admin := bootstrap(t, db)
	alice := createUser(t, db, admin, "alice", store.RoleUser)
	bob := createUser(t, db, admin, "bob", store.RoleUser)
	keyA, _ := addKey(t, db, alice, "laptop")
	keyB, _ := addKey(t, db, alice, "desktop")
	bobKey, _ := addKey(t, db, bob, "laptop")
	destination := catchAllDestination()
	if err := db.SaveDefaultDestination(admin.ID, destination); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"owner/repository", "owner/repository.git"} {
		got, err := db.Resolve(alice.ID, keyA.ID, source)
		want := store.Mapping{
			UserID: alice.ID, KeyID: keyA.ID, Source: "owner/repository.git", RemotePath: "owner/repository.git",
			Host: destination.Host, Port: destination.Port, RemoteUser: destination.RemoteUser,
			HostFingerprint: destination.HostFingerprint, ReadOnly: true,
		}
		if err != nil || got != want {
			t.Fatalf("fallback for %q = %+v, %v; want %+v", source, got, err, want)
		}
	}
	generalInput := mapping(alice.ID, "", "owner/repository")
	generalInput.ReadOnly = false
	general := saveMapping(t, db, alice.ID, generalInput)
	specificInput := mapping(alice.ID, keyA.ID, "owner/repository.git")
	specificInput.Host = "specific.example.com"
	specific := saveMapping(t, db, alice.ID, specificInput)
	for _, tc := range []struct {
		userID   string
		keyID    string
		wantID   string
		wantHost string
		readOnly bool
	}{
		{alice.ID, keyA.ID, specific.ID, specific.Host, false},
		{alice.ID, keyB.ID, general.ID, general.Host, false},
		{bob.ID, bobKey.ID, "", destination.Host, true},
	} {
		got, err := db.Resolve(tc.userID, tc.keyID, "owner/repository")
		if err != nil || got.ID != tc.wantID || got.Host != tc.wantHost || got.ReadOnly != tc.readOnly || got.UserID != tc.userID {
			t.Fatalf("resolution for %s/%s = %+v, %v", tc.userID, tc.keyID, got, err)
		}
	}
	if err := db.DeleteMapping(alice.ID, specific.ID); err != nil {
		t.Fatal(err)
	}
	got, err := db.Resolve(alice.ID, keyA.ID, "owner/repository")
	if err != nil || got.ID != general.ID {
		t.Fatalf("key route removal = %+v, %v", got, err)
	}
	if err = db.DeleteMapping(alice.ID, general.ID); err != nil {
		t.Fatal(err)
	}
	destination.ReadOnly = false
	if err = db.SaveDefaultDestination(admin.ID, destination); err != nil {
		t.Fatal(err)
	}
	got, err = db.Resolve(alice.ID, keyA.ID, "owner/repository")
	if err != nil || got.ID != "" || got.Host != destination.Host || got.ReadOnly {
		t.Fatalf("explicit route removal and writable fallback = %+v, %v", got, err)
	}
}

func TestDefaultDestinationRequiresCurrentUserAndKey(t *testing.T) {
	db, _ := openStore(t)
	admin := bootstrap(t, db)
	alice := createUser(t, db, admin, "alice", store.RoleUser)
	bob := createUser(t, db, admin, "bob", store.RoleUser)
	aliceKey, _ := addKey(t, db, alice, "laptop")
	bobKey, _ := addKey(t, db, bob, "laptop")
	if err := db.SaveDefaultDestination(admin.ID, catchAllDestination()); err != nil {
		t.Fatal(err)
	}
	for _, keyID := range []string{"", "missing", bobKey.ID} {
		_, err := db.Resolve(alice.ID, keyID, "owner/repository")
		expectError(t, err, store.ErrNotFound)
	}
	for _, source := range []string{"", "/repository", "owner/../repository", "repository;id", "repository\n"} {
		if _, err := db.Resolve(alice.ID, aliceKey.ID, source); err == nil {
			t.Fatalf("unsafe fallback path %q accepted", source)
		}
	}
	if err := db.DeleteKey(alice.ID, aliceKey.ID); err != nil {
		t.Fatal(err)
	}
	_, err := db.Resolve(alice.ID, aliceKey.ID, "owner/repository")
	expectError(t, err, store.ErrNotFound)
	currentKey, _ := addKey(t, db, alice, "replacement")
	if err = db.UpdateUser(admin.ID, alice.ID, alice.Username, alice.Role, true); err != nil {
		t.Fatal(err)
	}
	_, err = db.Resolve(alice.ID, currentKey.ID, "owner/repository")
	expectError(t, err, store.ErrUnauthorized)
	if err = db.DeleteUser(admin.ID, bob.ID); err != nil {
		t.Fatal(err)
	}
	_, err = db.Resolve(bob.ID, bobKey.ID, "owner/repository")
	expectError(t, err, store.ErrUnauthorized)
}

func TestDefaultDestinationDoesNotMaskRouteQueryFailure(t *testing.T) {
	db, path := openStore(t)
	admin := bootstrap(t, db)
	key, _ := addKey(t, db, admin, "laptop")
	if err := db.SaveDefaultDestination(admin.ID, catchAllDestination()); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if _, err = raw.Exec("DROP TABLE mappings"); err != nil {
		t.Fatal(err)
	}
	if got, err := db.Resolve(admin.ID, key.ID, "owner/repository"); err == nil {
		t.Fatalf("route query failure returned fallback %+v", got)
	}
}
