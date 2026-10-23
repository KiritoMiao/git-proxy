package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kirito/git-proxy/internal/activity"
	"github.com/kirito/git-proxy/internal/store"
)

func testWeb(t *testing.T, initialized bool) (*store.Store, *server, store.User) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	var admin store.User
	if initialized {
		admin, err = db.Bootstrap("admin", "admin-password-1234")
		if err != nil {
			t.Fatal(err)
		}
	}
	s := New(db, activity.New(), "first-setup-token", false).(*server)
	return db, s, admin
}

func webPost(s *server, cookie *http.Cookie, path, origin string, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "http://proxy.test"+path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func testSession(s *server, user store.User) (*http.Cookie, session) {
	w := httptest.NewRecorder()
	_, sess := s.issueSession(w, user)
	return w.Result().Cookies()[0], sess
}

func TestBootstrapRequiresOriginAndSessionCSRF(t *testing.T) {
	db, s, _ := testWeb(t, false)
	cookie, sess := testSession(s, store.User{})
	base := url.Values{"username": {"first-admin"}, "password": {"first-password-1234"}, "bootstrap_token": {"first-setup-token"}, "csrf": {sess.CSRF}}
	for _, origin := range []string{"", "http://evil.test", "https://proxy.test"} {
		if got := webPost(s, cookie, "/setup", origin, base).Code; got != http.StatusForbidden {
			t.Fatalf("origin %q: status %d", origin, got)
		}
	}
	base.Set("csrf", "wrong-token")
	if got := webPost(s, cookie, "/setup", "http://proxy.test", base).Code; got != http.StatusForbidden {
		t.Fatalf("wrong CSRF: %d", got)
	}
	if db.Initialized() {
		t.Fatal("rejected requests initialized database")
	}
	base.Set("csrf", sess.CSRF)
	if got := webPost(s, nil, "/setup", "http://proxy.test", base).Code; got != http.StatusForbidden {
		t.Fatalf("missing session: %d", got)
	}
	base.Set("bootstrap_token", "wrong-token")
	if got := webPost(s, cookie, "/setup", "http://proxy.test", base).Code; got != http.StatusBadRequest {
		t.Fatalf("wrong bootstrap token: %d", got)
	}
	if db.Initialized() {
		t.Fatal("wrong bootstrap token initialized database")
	}
	base.Set("bootstrap_token", "first-setup-token")
	w := webPost(s, cookie, "/setup", "http://proxy.test", base)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("valid setup: %d %s", w.Code, w.Body.String())
	}
	user, err := db.Authenticate("first-admin", "first-password-1234")
	if err != nil || user.Role != "admin" {
		t.Fatalf("bootstrap did not create admin: %v", err)
	}
}

func TestMemberCannotAccessOtherOwnersOrAdminActions(t *testing.T) {
	db, s, admin := testWeb(t, true)
	alice, err := db.CreateUser(admin.ID, "alice", "alice-password-1234", "user")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := db.CreateUser(admin.ID, "bob", "bob-password-1234", "user")
	if err != nil {
		t.Fatal(err)
	}
	mapping, err := db.SaveMapping(admin.ID, store.Mapping{UserID: bob.ID, Source: "private/secret.git", Host: "git.example.com", Port: 22, RemoteUser: "git", RemotePath: "org/private.git", HostFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})
	if err != nil {
		t.Fatal(err)
	}
	cookie, sess := testSession(s, alice)
	for _, path := range []string{"/users", "/settings"} {
		r := httptest.NewRequest(http.MethodGet, "http://proxy.test"+path, nil)
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("member GET %s: %d", path, w.Code)
		}
	}
	// Alice's dashboard and API data must never include Bob's route or activity.
	d := s.data(alice, sess, "dashboard")
	if err := s.load(&d); err != nil {
		t.Fatal(err)
	}
	if len(d.Mappings) != 0 {
		t.Fatal("another owner's mapping visible")
	}
	eventID := s.hub.Begin(bob, mapping, "git-upload-pack")
	s.hub.Finish(eventID, nil)
	r := httptest.NewRequest(http.MethodGet, "http://proxy.test/api/activity", nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "private/secret.git") {
		t.Fatalf("activity leaked: %d %s", w.Code, w.Body.String())
	}
	form := url.Values{"action": {"mapping_delete"}, "id": {mapping.ID}, "csrf": {sess.CSRF}}
	if got := webPost(s, cookie, "/actions", "http://proxy.test", form).Code; got != http.StatusBadRequest {
		t.Fatalf("foreign route deletion: %d", got)
	}
	remaining, err := db.Mappings(bob.ID)
	if err != nil || len(remaining) != 1 {
		t.Fatalf("foreign route removed: %v", err)
	}
	form = url.Values{"action": {"user_create"}, "username": {"escalated"}, "password": {"escalated-password-1234"}, "role": {"admin"}, "csrf": {sess.CSRF}}
	if got := webPost(s, cookie, "/actions", "http://proxy.test", form).Code; got != http.StatusForbidden {
		t.Fatalf("admin mutation: %d", got)
	}
}

func TestExternalPasswordResetInvalidatesSession(t *testing.T) {
	db, s, admin := testWeb(t, true)
	cookie, _ := testSession(s, admin)
	if err := db.SetPassword(admin.ID, admin.ID, "replacement-password-1234"); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "http://proxy.test/api/activity", nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("stale session survived external password change: %d", w.Code)
	}
}

func TestSecureProxyOriginUsesConfiguredHTTPS(t *testing.T) {
	_, s, _ := testWeb(t, false)
	s.secureCookie = true
	r := httptest.NewRequest(http.MethodPost, "http://proxy.test/setup", nil)
	r.Header.Set("Origin", "https://proxy.test")
	if !s.sameOrigin(r) {
		t.Fatal("configured secure proxy rejected HTTPS origin")
	}
	r.Header.Set("Origin", "http://proxy.test")
	if s.sameOrigin(r) {
		t.Fatal("secure deployment accepted HTTP origin")
	}
}

func TestDefaultDestinationRequiresAdministrator(t *testing.T) {
	db, s, admin := testWeb(t, true)
	member, err := db.CreateUser(admin.ID, "member", "member-password-1234", "user")
	if err != nil {
		t.Fatal(err)
	}
	cookie, sess := testSession(s, member)
	r := httptest.NewRequest(http.MethodGet, "http://proxy.test/settings", nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "default_destination") {
		t.Fatalf("member settings: %d %s", w.Code, w.Body.String())
	}
	form := url.Values{"csrf": {sess.CSRF}, "action": {"default_destination"}, "enabled": {"on"}, "host": {"git.example.com"}, "port": {"2222"}, "remote_user": {"deploy"}, "host_fingerprint": {"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, "read_only": {"on"}}
	for _, port := range []string{"2222", "invalid"} {
		form.Set("port", port)
		w = webPost(s, cookie, "/actions", "http://proxy.test", form)
		if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "default_destination") {
			t.Fatalf("member mutation with port %q: %d %s", port, w.Code, w.Body.String())
		}
	}
	destination, err := db.GetDefaultDestination(admin.ID)
	if err != nil || destination.Enabled || destination.Host != "github.com" || destination.Port != 22 || destination.RemoteUser != "git" {
		t.Fatalf("rejected mutation changed default: %+v, %v", destination, err)
	}
	d := s.data(member, sess, "mappings")
	if err := s.load(&d); err != nil {
		t.Fatal(err)
	}
	if d.DefaultDestination != (store.DefaultDestination{}) {
		t.Fatalf("member page loaded global destination: %+v", d.DefaultDestination)
	}
}

func TestAdministratorDefaultDestinationPersistenceAndDisable(t *testing.T) {
	db, s, admin := testWeb(t, true)
	cookie, sess := testSession(s, admin)
	r := httptest.NewRequest(http.MethodGet, "http://proxy.test/settings", nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("administrator settings: %d %s", w.Code, w.Body.String())
	}
	for _, field := range []string{`name="action" value="default_destination"`, `name="host" value="github.com"`, `name="port" type="number" value="22"`, `name="remote_user" value="git"`, "data-host-form", "data-discover-host"} {
		if !strings.Contains(w.Body.String(), field) {
			t.Errorf("settings missing %q", field)
		}
	}
	originalSettings := db.GetSettings()
	form := url.Values{"csrf": {sess.CSRF}, "action": {"default_destination"}, "enabled": {"on"}, "host": {"git.example.com"}, "port": {"2222"}, "remote_user": {"deploy"}, "host_fingerprint": {"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, "read_only": {"on"}}
	w = webPost(s, cookie, "/actions", "http://proxy.test", form)
	if w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/settings?notice=") {
		t.Fatalf("save default: %d %s", w.Code, w.Body.String())
	}
	want := store.DefaultDestination{Enabled: true, Host: "git.example.com", Port: 2222, RemoteUser: "deploy", HostFingerprint: form.Get("host_fingerprint"), ReadOnly: true}
	destination, err := db.GetDefaultDestination(admin.ID)
	if err != nil || destination != want {
		t.Fatalf("saved default: %+v, %v; want %+v", destination, err, want)
	}
	d := s.data(admin, sess, "settings")
	if err := s.load(&d); err != nil {
		t.Fatal(err)
	}
	if d.DefaultDestination != want {
		t.Fatalf("settings loaded %+v; want %+v", d.DefaultDestination, want)
	}
	r = httptest.NewRequest(http.MethodGet, "http://proxy.test/settings", nil)
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `name="host_fingerprint" value="`+want.HostFingerprint+`"`) {
		t.Fatalf("saved fingerprint not displayed: %d %s", w.Code, w.Body.String())
	}
	form.Del("enabled")
	form.Del("host_fingerprint")
	form.Del("read_only")
	w = webPost(s, cookie, "/actions", "http://proxy.test", form)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("disable without fingerprint: %d %s", w.Code, w.Body.String())
	}
	want.Enabled, want.ReadOnly, want.HostFingerprint = false, false, ""
	destination, err = db.GetDefaultDestination(admin.ID)
	if err != nil || destination != want {
		t.Fatalf("disabled default: %+v, %v; want %+v", destination, err, want)
	}
	form.Set("host", "")
	w = webPost(s, cookie, "/actions", "http://proxy.test", form)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("save blank default host: %d %s", w.Code, w.Body.String())
	}
	destination, err = db.GetDefaultDestination(admin.ID)
	if err != nil || destination.Host != "github.com" {
		t.Fatalf("blank host default: %+v, %v", destination, err)
	}
	if settings := db.GetSettings(); settings != originalSettings {
		t.Fatalf("default action changed workspace settings: %+v", settings)
	}
}

func TestDefaultDestinationValidationPreservesInput(t *testing.T) {
	db, s, admin := testWeb(t, true)
	cookie, sess := testSession(s, admin)
	form := url.Values{"csrf": {sess.CSRF}, "action": {"default_destination"}, "enabled": {"on"}, "host": {"git.example.com"}, "remote_user": {"deploy"}, "host_fingerprint": {""}, "read_only": {"on"}}
	for _, port := range []string{"2222", "invalid"} {
		form.Set("port", port)
		w := webPost(s, cookie, "/actions", "http://proxy.test", form)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("invalid destination with port %q: %d %s", port, w.Code, w.Body.String())
		}
		for _, field := range []string{`name="enabled" checked`, `name="host" value="git.example.com"`, `name="port" type="number" value="` + port + `"`, `name="remote_user" value="deploy"`, `name="host_fingerprint" value=""`, `name="read_only" checked`} {
			if !strings.Contains(w.Body.String(), field) {
				t.Errorf("failed input with port %q missing %q", port, field)
			}
		}
	}
	destination, err := db.GetDefaultDestination(admin.ID)
	if err != nil || destination.Enabled || destination.Host != "github.com" {
		t.Fatalf("invalid destination was persisted: %+v, %v", destination, err)
	}
}
