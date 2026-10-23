package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kirito/git-proxy/internal/store"
	"golang.org/x/crypto/ssh"
)

type hostIdentity struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Algorithm   string `json:"algorithm"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"public_key"`
}

// discoverHostIdentity stops the SSH handshake before user authentication. Its
// observed key is untrusted until the operator verifies and saves the fingerprint.
func discoverHostIdentity(ctx context.Context, host string, port int) (hostIdentity, error) {
	if err := store.ValidateDestination(host, port); err != nil {
		return hostIdentity{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return hostIdentity{}, fmt.Errorf("connect to upstream: %w", err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	identity := hostIdentity{Host: host, Port: port}
	observed := errors.New("host identity captured")
	cfg := &ssh.ClientConfig{User: "git", HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
		identity.Algorithm = key.Type()
		identity.Fingerprint = ssh.FingerprintSHA256(key)
		identity.PublicKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
		return observed
	}}
	client, _, _, err := ssh.NewClientConn(conn, net.JoinHostPort(host, strconv.Itoa(port)), cfg)
	if client != nil {
		client.Close()
	}
	if !errors.Is(err, observed) {
		return hostIdentity{}, fmt.Errorf("read upstream SSH identity: %w", err)
	}
	return identity, nil
}

func (s *server) hostIdentity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	port, err := strconv.Atoi(r.PostForm.Get("port"))
	if err != nil {
		http.Error(w, "Enter a valid upstream port.", http.StatusBadRequest)
		return
	}
	host := store.UpstreamHost(r.PostForm.Get("host"))
	if err = store.ValidateDestination(host, port); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	identity, err := discoverHostIdentity(r.Context(), host, port)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(identity)
}
