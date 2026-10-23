package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/kirito/git-proxy/internal/activity"
	"github.com/kirito/git-proxy/internal/sshserver"
	"github.com/kirito/git-proxy/internal/store"
	"github.com/kirito/git-proxy/internal/web"
	"golang.org/x/crypto/ssh"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
func run() error {
	data := flag.String("data", "./data", "private persistent data directory")
	sshAddr := flag.String("ssh", "0.0.0.0:2222", "SSH listen address")
	httpAddr := flag.String("http", "127.0.0.1:8080", "web listen address (use TLS reverse proxy for remote access)")
	secure := flag.Bool("secure-cookie", false, "require HTTPS for session cookies")
	cert := flag.String("tls-cert", "", "optional HTTPS certificate PEM")
	key := flag.String("tls-key", "", "optional HTTPS private key PEM")
	flag.Parse()
	if (*cert == "") != (*key == "") {
		return errors.New("tls-cert and tls-key must be provided together")
	}
	if err := os.MkdirAll(*data, 0700); err != nil {
		return err
	}
	if err := os.Chmod(*data, 0700); err != nil {
		return err
	}
	db, err := store.Open(filepath.Join(*data, "proxy.db"))
	if err != nil {
		return err
	}
	defer db.Close()
	signer, err := hostKey(filepath.Join(*data, "ssh_host_ed25519_key"))
	if err != nil {
		return err
	}
	tokenPath := filepath.Join(*data, "setup-token")
	token := ""
	if !db.Initialized() {
		token, err = setupToken(tokenPath)
		if err != nil {
			return err
		}
		log.Printf("First-login admin setup enabled; read the one-time token from %s", tokenPath)
	} else {
		_ = os.Remove(tokenPath)
	}
	hub := activity.New()
	sshServer := sshserver.New(db, hub, signer)
	webHandler := web.New(db, hub, token, *secure || *cert != "")
	// Remove the on-disk setup secret as soon as initialization completes.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webHandler.ServeHTTP(w, r)
		if token != "" && db.Initialized() {
			_ = os.Remove(tokenPath)
		}
	})
	httpServer := &http.Server{Addr: *httpAddr, Handler: handler, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 1 << 16}
	sl, err := net.Listen("tcp", *sshAddr)
	if err != nil {
		return err
	}
	defer sl.Close()
	hl, err := net.Listen("tcp", *httpAddr)
	if err != nil {
		return err
	}
	defer hl.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errs := make(chan error, 2)
	go func() { errs <- sshServer.SSH.Serve(sl) }()
	go func() {
		if *cert != "" {
			errs <- httpServer.ServeTLS(hl, *cert, *key)
		} else {
			errs <- httpServer.Serve(hl)
		}
	}()
	log.Printf("SSH listening on %s; host key %s", sl.Addr(), ssh.FingerprintSHA256(signer.PublicKey()))
	scheme := "http"
	if *cert != "" {
		scheme = "https"
	}
	log.Printf("Web listening at %s://%s", scheme, hl.Addr())
	select {
	case <-ctx.Done():
	case err = <-errs:
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = sshServer.SSH.Close()
	_ = httpServer.Shutdown(shutdown)
	return err
}
func hostKey(path string) (ssh.Signer, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		return ssh.ParsePrivateKey(b)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(private, "git-proxy host")
	if err != nil {
		return nil, err
	}
	b = pem.EncodeToMemory(block)
	if err = writeExclusive(path, b); err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(private)
}
func setupToken(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		token := strings.TrimSpace(string(b))
		if len(token) < 32 {
			return "", fmt.Errorf("invalid setup token in %s", path)
		}
		return token, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	b = make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	if err = writeExclusive(path, []byte(token+"\n")); err != nil {
		return "", err
	}
	return token, nil
}
func writeExclusive(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	n, err := f.Write(b)
	if err != nil {
		return err
	}
	if n != len(b) {
		return errors.New("short private file write")
	}
	return f.Sync()
}
