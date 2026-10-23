package web

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kirito/git-proxy/internal/store"
	"golang.org/x/crypto/ssh"
)

func identityFixture(t *testing.T) (string, int, ssh.Signer, *atomic.Int32) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	var auth atomic.Int32
	cfg := &ssh.ServerConfig{NoClientAuth: true, NoClientAuthCallback: func(meta ssh.ConnMetadata) (*ssh.Permissions, error) { auth.Add(1); return nil, nil }}
	cfg.AddHostKey(signer)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				s, _, _, _ := ssh.NewServerConn(c, cfg)
				if s != nil {
					s.Close()
				}
			}()
		}
	}()
	return "127.0.0.1", l.Addr().(*net.TCPAddr).Port, signer, &auth
}

func TestHostIdentityDiscoveryAndExplicitSave(t *testing.T) {
	db, s, admin := testWeb(t, true)
	member, err := db.CreateUser(admin.ID, "member", "member-password-1234", "user")
	if err != nil {
		t.Fatal(err)
	}
	host, port, signer, auth := identityFixture(t)
	mapping, err := db.SaveMapping(member.ID, store.Mapping{UserID: member.ID, Source: "team/repo.git", Host: host, Port: port, RemoteUser: "git", RemotePath: "org/repo.git", HostFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})
	if err != nil {
		t.Fatal(err)
	}
	cookie, sess := testSession(s, member)
	form := url.Values{"csrf": {sess.CSRF}, "host": {host}, "port": {strconv.Itoa(port)}}
	response := webPost(s, cookie, "/api/host-identity", "http://proxy.test", form)
	if response.Code != http.StatusOK {
		t.Fatalf("discovery: %d %s", response.Code, response.Body.String())
	}
	var identity hostIdentity
	if err = json.Unmarshal(response.Body.Bytes(), &identity); err != nil {
		t.Fatal(err)
	}
	if identity.Host != host || identity.Port != port || identity.Algorithm != "ssh-ed25519" || identity.Fingerprint != ssh.FingerprintSHA256(signer.PublicKey()) || identity.PublicKey != strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))) {
		t.Fatalf("wrong identity: %+v", identity)
	}
	if auth.Load() != 0 {
		t.Fatal("discovery attempted upstream user authentication")
	}
	existing, err := db.Mappings(member.ID)
	if err != nil {
		t.Fatal(err)
	}
	if existing[0].HostFingerprint != mapping.HostFingerprint {
		t.Fatal("discovery changed saved trust")
	}
	save := url.Values{"csrf": {sess.CSRF}, "action": {"mapping_save"}, "id": {mapping.ID}, "user_id": {member.ID}, "source": {mapping.Source}, "host": {host}, "port": {strconv.Itoa(port)}, "remote_user": {"git"}, "remote_path": {mapping.RemotePath}, "host_fingerprint": {identity.Fingerprint}}
	if r := webPost(s, cookie, "/actions", "http://proxy.test", save); r.Code != http.StatusSeeOther {
		t.Fatalf("save: %d %s", r.Code, r.Body.String())
	}
	existing, err = db.Mappings(member.ID)
	if err != nil || existing[0].HostFingerprint != identity.Fingerprint {
		t.Fatalf("pin not updated: %+v %v", existing, err)
	}
}

func TestHostIdentityAccessAndValidation(t *testing.T) {
	_, s, admin := testWeb(t, true)
	cookie, sess := testSession(s, admin)
	form := url.Values{"csrf": {sess.CSRF}, "host": {"127.0.0.1"}, "port": {"0"}}
	for _, origin := range []string{"http://evil.test", ""} {
		if r := webPost(s, cookie, "/api/host-identity", origin, form); r.Code != http.StatusForbidden {
			t.Fatalf("origin accepted: %d", r.Code)
		}
	}
	for _, values := range []url.Values{
		{"host": {"host;id"}, "port": {"22"}}, {"host": {"127.0.0.1"}, "port": {"0"}}, {"host": {"127.0.0.1"}, "port": {"65536"}}, {"host": {"127.0.0.1"}, "port": {"bad"}},
	} {
		values.Set("csrf", sess.CSRF)
		if r := webPost(s, cookie, "/api/host-identity", "http://proxy.test", values); r.Code != http.StatusBadRequest {
			t.Fatalf("invalid destination: %d", r.Code)
		}
	}
	anonymous, anonSession := testSession(s, store.User{})
	form.Set("csrf", anonSession.CSRF)
	if r := webPost(s, anonymous, "/api/host-identity", "http://proxy.test", form); r.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous discovery: %d", r.Code)
	}
	r := httptest.NewRequest(http.MethodGet, "http://proxy.test/api/host-identity", nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET discovery: %d", w.Code)
	}
}

func TestHostIdentityCancellation(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan struct{})
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		close(accepted)
		var b [256]byte
		for {
			if _, err = c.Read(b[:]); err != nil {
				return
			}
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := discoverHostIdentity(ctx, "127.0.0.1", l.Addr().(*net.TCPAddr).Port); result <- err }()
	<-accepted
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("stalled handshake succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not stop stalled handshake")
	}
}
