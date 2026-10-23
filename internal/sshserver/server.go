package sshserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	ssh "github.com/gliderlabs/ssh"
	"github.com/kirito/git-proxy/internal/activity"
	"github.com/kirito/git-proxy/internal/store"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Only Git's wire-protocol programs are accepted. No shell is ever started locally.
var gitCommand = regexp.MustCompile(`^(git-upload-pack|git-receive-pack|git-upload-archive) (?:'([a-zA-Z0-9_./-]+)'|([a-zA-Z0-9_./-]+))$`)

func parseCommand(raw string) (string, string, error) {
	m := gitCommand.FindStringSubmatch(raw)
	if m == nil {
		return "", "", errors.New("only git-upload-pack, git-receive-pack and git-upload-archive are allowed")
	}
	path := m[2]
	if path == "" {
		path = m[3]
	}
	// Git's ssh:// URL syntax adds one leading slash to the virtual repository.
	path = strings.TrimPrefix(path, "/")
	if err := store.ValidateSource(path); err != nil {
		return "", "", err
	}
	return m[1], path, nil
}

type Server struct {
	SSH    *ssh.Server
	db     *store.Store
	hub    *activity.Hub
	mu     sync.Mutex
	active map[string]int
}

func New(db *store.Store, hub *activity.Hub, signer gossh.Signer) *Server {
	s := &Server{db: db, hub: hub, active: make(map[string]int)}
	s.SSH = &ssh.Server{HostSigners: []ssh.Signer{signer}, Version: "GitProxy", IdleTimeout: 10 * time.Minute, MaxTimeout: 24 * time.Hour,
		PublicKeyHandler: func(ctx ssh.Context, key ssh.PublicKey) bool { _, _, err := db.AuthenticateKey(key); return err == nil },
		Handler:          s.handle,
		// No direct-tcpip, reverse forwarding, SFTP or other subsystems.
		ChannelHandlers:   map[string]ssh.ChannelHandler{"session": ssh.DefaultSessionHandler},
		SubsystemHandlers: map[string]ssh.SubsystemHandler{},
		SessionRequestCallback: func(sess ssh.Session, requestType string) bool {
			if requestType == "subsystem" {
				return false
			}
			return true
		},
		PtyCallback: func(ctx ssh.Context, p ssh.Pty) bool { return p.Term != "" },
	}
	return s
}
func (s *Server) handle(sess ssh.Session) {
	u, k, err := s.db.AuthenticateKey(sess.PublicKey())
	if err != nil {
		s.fail(sess, err)
		return
	}
	settings := s.db.GetSettings()
	s.mu.Lock()
	if s.active[u.ID] >= settings.MaxSessionsPerUser {
		s.mu.Unlock()
		s.fail(sess, errors.New("concurrent session limit reached"))
		return
	}
	s.active[u.ID]++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.active[u.ID]--
		if s.active[u.ID] == 0 {
			delete(s.active, u.ID)
		}
		s.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(sess.Context(), time.Duration(settings.SessionTimeoutMinutes)*time.Minute)
	defer cancel()
	go func() { <-ctx.Done(); sess.Close() }()
	if sess.RawCommand() == "" {
		if _, _, ok := sess.Pty(); !ok {
			s.fail(sess, errors.New("management requires a terminal: ssh -t -p 2222 git@host"))
			return
		}
		s.tui(sess, u)
		return
	}
	if _, _, ok := sess.Pty(); ok {
		s.fail(sess, errors.New("Git protocol sessions must not allocate a PTY"))
		return
	}
	op, source, err := parseCommand(sess.RawCommand())
	if err != nil {
		s.fail(sess, err)
		return
	}
	m, err := s.db.Resolve(u.ID, k.ID, source)
	if err != nil {
		s.fail(sess, err)
		return
	}
	if op == "git-receive-pack" && m.ReadOnly {
		s.fail(sess, errors.New("mapping is read-only"))
		return
	}
	if !ssh.AgentRequested(sess) {
		s.fail(sess, errors.New("agent forwarding required; use ssh -A or ForwardAgent yes"))
		return
	}
	id := s.hub.Begin(u, m, op)
	var incoming, outgoing atomic.Int64
	defer func() { s.hub.Progress(id, incoming.Load(), outgoing.Load()); s.hub.Finish(id, err) }()
	err = s.proxy(ctx, sess, m, op, &incoming, &outgoing, id)
	if err != nil {
		code := 1
		var exitErr *gossh.ExitError
		if errors.As(err, &exitErr) {
			code = exitErr.ExitStatus()
		}
		fmt.Fprintln(sess.Stderr(), "git-proxy:", err)
		sess.Exit(code)
		return
	}
	sess.Exit(0)
}
func (s *Server) fail(sess ssh.Session, err error) {
	fmt.Fprintln(sess.Stderr(), "git-proxy:", err)
	sess.Exit(1)
}

type countReader struct {
	r io.Reader
	n *atomic.Int64
}

func (c countReader) Read(p []byte) (int, error) { n, e := c.r.Read(p); c.n.Add(int64(n)); return n, e }

type countWriter struct {
	w io.Writer
	n *atomic.Int64
}

func (c countWriter) Write(p []byte) (int, error) {
	n, e := c.w.Write(p)
	c.n.Add(int64(n))
	return n, e
}
func (s *Server) proxy(ctx context.Context, sess ssh.Session, m store.Mapping, op string, in, out *atomic.Int64, id string) error {
	conn, ok := sess.Context().Value(ssh.ContextKeyConn).(gossh.Conn)
	if !ok {
		return errors.New("SSH connection unavailable")
	}
	// Open the client's forwarded-agent channel directly; never create a local socket.
	ac, requests, err := conn.OpenChannel("auth-agent@openssh.com", nil)
	if err != nil {
		return fmt.Errorf("open forwarded agent: %w", err)
	}
	defer ac.Close()
	go gossh.DiscardRequests(requests)
	stopped := make(chan struct{})
	defer close(stopped)
	go func() {
		select {
		case <-ctx.Done():
			ac.Close()
		case <-stopped:
		}
	}()
	cfg := &gossh.ClientConfig{User: m.RemoteUser, Auth: []gossh.AuthMethod{gossh.PublicKeysCallback(agent.NewClient(ac).Signers)}, HostKeyCallback: func(hostname string, remote net.Addr, key gossh.PublicKey) error {
		if gossh.FingerprintSHA256(key) != m.HostFingerprint {
			return errors.New("upstream host key does not match the configured SHA256 fingerprint")
		}
		return nil
	}, Timeout: 15 * time.Second}
	dialer := net.Dialer{Timeout: 15 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(m.Host, fmt.Sprint(m.Port)))
	if err != nil {
		return fmt.Errorf("upstream dial: %w", err)
	}
	defer raw.Close()
	go func() {
		select {
		case <-ctx.Done():
			raw.Close()
		case <-stopped:
		}
	}()
	// Bound agent signing and handshake as well as the TCP dial.
	raw.SetDeadline(time.Now().Add(20 * time.Second))
	handshakeDone := make(chan struct{})
	go func() {
		timer := time.NewTimer(20 * time.Second)
		defer timer.Stop()
		select {
		case <-timer.C:
			ac.Close()
			raw.Close()
		case <-handshakeDone:
		}
	}()
	cc, chans, reqs, err := gossh.NewClientConn(raw, raw.RemoteAddr().String(), cfg)
	close(handshakeDone)
	if err != nil {
		return fmt.Errorf("upstream SSH: %w", err)
	}
	raw.SetDeadline(time.Time{})
	client := gossh.NewClient(cc, chans, reqs)
	defer client.Close()
	remote, err := client.NewSession()
	if err != nil {
		return err
	}
	defer remote.Close()
	for _, env := range sess.Environ() {
		if env == "GIT_PROTOCOL=version=2" || env == "GIT_PROTOCOL=version=1" {
			_ = remote.Setenv("GIT_PROTOCOL", strings.TrimPrefix(env, "GIT_PROTOCOL="))
		}
	}
	remote.Stdin = countReader{sess, in}
	remote.Stdout = countWriter{sess, out}
	remote.Stderr = countWriter{sess.Stderr(), out}
	// All interpolated values were validated by the store; repository path cannot contain quotes.
	if err := remote.Start(op + " '" + m.RemotePath + "'"); err != nil {
		return err
	}
	progressDone := make(chan struct{})
	defer close(progressDone)
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.hub.Progress(id, in.Load(), out.Load())
			case <-progressDone:
				return
			}
		}
	}()
	return remote.Wait()
}
