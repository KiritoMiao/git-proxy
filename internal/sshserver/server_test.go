package sshserver

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	ssh "github.com/gliderlabs/ssh"
	"github.com/kirito/git-proxy/internal/activity"
	"github.com/kirito/git-proxy/internal/store"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func testSigner(t *testing.T) (gossh.Signer, ed25519.PrivateKey) {
	t.Helper()
	_, k, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	s, e := gossh.NewSignerFromKey(k)
	if e != nil {
		t.Fatal(e)
	}
	return s, k
}
func TestCommandBoundary(t *testing.T) {
	for _, raw := range []string{"sh", "git-upload-pack 'team/repo.git'; id", "git-upload-pack '../secret'", "git-upload-pack '//absolute'", "git-upload-pack 'a//b'", "git-upload-pack $(id)", "git-upload-pack 'a' extra", "git-upload-pack 'a'\n"} {
		if _, _, e := parseCommand(raw); e == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	for _, op := range []string{"git-upload-pack", "git-receive-pack", "git-upload-archive"} {
		for _, path := range []string{"team/repo.git", "/team/repo.git"} {
			if _, p, e := parseCommand(op + " '" + path + "'"); e != nil || p != "team/repo.git" {
				t.Errorf("valid command: %s %v", p, e)
			}
		}
	}
}

// Exercise real Git clients, the forwarded-agent protocol, SSH host pins and a real
// upstream bare repository. Only this controlled upstream fixture starts programs.
func TestGitStreamingEndToEnd(t *testing.T) {
	if _, e := exec.LookPath("git"); e != nil {
		t.Skip("git unavailable")
	}
	if _, e := exec.LookPath("ssh"); e != nil {
		t.Skip("OpenSSH unavailable")
	}
	dir := t.TempDir()
	db, e := store.Open(filepath.Join(dir, "db"))
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	u, e := db.Bootstrap("admin", "correct horse battery staple")
	if e != nil {
		t.Fatal(e)
	}
	signer, private := testSigner(t)
	key, e := db.AddKey(u.ID, u.ID, "client", string(gossh.MarshalAuthorizedKey(signer.PublicKey())))
	if e != nil {
		t.Fatal(e)
	}
	identity := filepath.Join(dir, "id_ed25519")
	block, e := gossh.MarshalPrivateKey(private, "")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(identity, pem.EncodeToMemory(block), 0600); e != nil {
		t.Fatal(e)
	}
	// Keep the UNIX-domain path short enough on Darwin.
	sockDir, e := os.MkdirTemp("", "gpa-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(sockDir)
	sock := filepath.Join(sockDir, "agent")
	al, e := net.Listen("unix", sock)
	if e != nil {
		t.Fatal(e)
	}
	defer al.Close()
	ring := agent.NewKeyring()
	if e = ring.Add(agent.AddedKey{PrivateKey: private}); e != nil {
		t.Fatal(e)
	}
	go func() {
		for {
			c, e := al.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); _ = agent.ServeAgent(ring, c) }()
		}
	}()
	run := func(wd string, args ...string) string {
		t.Helper()
		c := exec.Command("git", args...)
		c.Dir = wd
		c.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0")
		b, e := c.CombinedOutput()
		if e != nil {
			t.Fatalf("git %v: %v\n%s", args, e, b)
		}
		return string(b)
	}
	bare := filepath.Join(dir, "remote.git")
	run(dir, "init", "--bare", "--initial-branch=main", bare)
	upstreamSigner, _ := testSigner(t)
	upstream := &ssh.Server{HostSigners: []ssh.Signer{upstreamSigner}, PublicKeyHandler: func(ctx ssh.Context, k ssh.PublicKey) bool {
		return bytes.Equal(k.Marshal(), signer.PublicKey().Marshal())
	}, Handler: func(sess ssh.Session) {
		args := sess.Command()
		if len(args) != 2 || args[1] != bare || (args[0] != "git-upload-pack" && args[0] != "git-receive-pack" && args[0] != "git-upload-archive") {
			sess.Exit(1)
			return
		}
		c := exec.Command(args[0], args[1])
		c.Stdout = sess
		c.Stderr = sess.Stderr()
		for _, v := range sess.Environ() {
			if strings.HasPrefix(v, "GIT_PROTOCOL=") {
				c.Env = append(os.Environ(), v)
			}
		}
		input, e := c.StdinPipe()
		if e != nil {
			sess.Exit(1)
			return
		}
		if e = c.Start(); e != nil {
			input.Close()
			sess.Exit(1)
			return
		}
		go func() { io.Copy(input, sess); input.Close() }()
		if e = c.Wait(); e != nil {
			sess.Exit(1)
		} else {
			sess.Exit(0)
		}
	}}
	ul, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer upstream.Close()
	go upstream.Serve(ul)
	m, e := db.SaveMapping(u.ID, store.Mapping{UserID: u.ID, KeyID: key.ID, Source: "team/repo.git", Host: "127.0.0.1", Port: ul.Addr().(*net.TCPAddr).Port, RemoteUser: "git", RemotePath: bare, HostFingerprint: gossh.FingerprintSHA256(upstreamSigner.PublicKey())})
	if e != nil {
		t.Fatal(e)
	}
	proxySigner, _ := testSigner(t)
	hub := activity.New()
	proxy := New(db, hub, proxySigner)
	pl, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer proxy.SSH.Close()
	go proxy.SSH.Serve(pl)
	port := pl.Addr().(*net.TCPAddr).Port
	url := fmt.Sprintf("ssh://git@127.0.0.1:%d/team/repo.git", port)
	sshCmd := fmt.Sprintf("ssh -F /dev/null -A -i %s -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes", identity)
	git := func(wd string, success bool, args ...string) []byte {
		t.Helper()
		c := exec.Command("git", args...)
		c.Dir = wd
		c.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0", "SSH_AUTH_SOCK="+sock, "GIT_SSH_COMMAND="+sshCmd)
		b, e := c.CombinedOutput()
		if success && e != nil {
			t.Fatalf("git %v: %v\n%s", args, e, b)
		}
		if !success && e == nil {
			t.Fatalf("git %v unexpectedly succeeded: %s", args, b)
		}
		return b
	}
	work := filepath.Join(dir, "work")
	run(dir, "init", "--initial-branch=main", work)
	run(work, "config", "user.name", "Smoke")
	run(work, "config", "user.email", "smoke@example.test")
	if e = os.WriteFile(filepath.Join(work, "hello.txt"), []byte("streamed through forwarded SSH agent\n"), 0600); e != nil {
		t.Fatal(e)
	}
	run(work, "add", ".")
	run(work, "commit", "-m", "initial")
	git(work, true, "push", url, "main")
	clone := filepath.Join(dir, "clone")
	git(dir, true, "clone", url, clone)
	content, e := os.ReadFile(filepath.Join(clone, "hello.txt"))
	if e != nil || string(content) != "streamed through forwarded SSH agent\n" {
		t.Fatalf("clone content %q: %v", content, e)
	}
	if e = os.WriteFile(filepath.Join(work, "hello.txt"), []byte("second revision\n"), 0600); e != nil {
		t.Fatal(e)
	}
	run(work, "commit", "-am", "second")
	git(work, true, "push", url, "main")
	git(clone, true, "pull", "--ff-only")
	git(work, true, "ls-remote", url)
	// Archive bytes are written separately from SSH warning stderr.
	c := exec.Command("git", "archive", "--remote="+url, "HEAD", "hello.txt")
	c.Env = append(os.Environ(), "SSH_AUTH_SOCK="+sock, "GIT_SSH_COMMAND="+sshCmd)
	archive, e := c.Output()
	if e != nil || !bytes.Contains(archive, []byte("second revision")) {
		t.Fatalf("archive failed: %v", e)
	}
	m.ReadOnly = true
	if m, e = db.SaveMapping(u.ID, m); e != nil {
		t.Fatal(e)
	}
	if b := git(work, false, "push", url, "main"); !bytes.Contains(b, []byte("read-only")) {
		t.Fatalf("read-only rejection: %s", b)
	}
	m.HostFingerprint = gossh.FingerprintSHA256(proxySigner.PublicKey())
	if _, e = db.SaveMapping(u.ID, m); e != nil {
		t.Fatal(e)
	}
	if b := git(work, false, "ls-remote", url); !bytes.Contains(b, []byte("host key")) {
		t.Fatalf("pin rejection: %s", b)
	}
	// Unknown keys never complete authentication; registered keys cannot execute a shell.
	unknown, _ := testSigner(t)
	if c, e := gossh.Dial("tcp", pl.Addr().String(), &gossh.ClientConfig{User: "git", Auth: []gossh.AuthMethod{gossh.PublicKeys(unknown)}, HostKeyCallback: gossh.InsecureIgnoreHostKey()}); e == nil {
		c.Close()
		t.Fatal("unregistered key authenticated")
	}
	client, e := gossh.Dial("tcp", pl.Addr().String(), &gossh.ClientConfig{User: "git", Auth: []gossh.AuthMethod{gossh.PublicKeys(signer)}, HostKeyCallback: gossh.InsecureIgnoreHostKey()})
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	sess, e := client.NewSession()
	if e != nil {
		t.Fatal(e)
	}
	if b, e := sess.CombinedOutput("echo unsafe"); e == nil || !bytes.Contains(b, []byte("only git-")) {
		t.Fatalf("exec boundary: %s %v", b, e)
	}
	sess.Close()
	missingAgent, e := client.NewSession()
	if e != nil {
		t.Fatal(e)
	}
	if b, e := missingAgent.CombinedOutput("git-upload-pack 'team/repo.git'"); e == nil || !bytes.Contains(b, []byte("agent forwarding required")) {
		t.Fatalf("missing agent: %s %v", b, e)
	}
	missingAgent.Close()
	subsystem, e := client.NewSession()
	if e != nil {
		t.Fatal(e)
	}
	if e = subsystem.RequestSubsystem("sftp"); e == nil {
		t.Fatal("SFTP accepted")
	}
	subsystem.Close()
	if forwarded, e := client.Dial("tcp", "127.0.0.1:80"); e == nil {
		forwarded.Close()
		t.Fatal("port forwarding accepted")
	}
	// A real PTY reaches the restricted console and exits without a shell.
	terminal, e := client.NewSession()
	if e != nil {
		t.Fatal(e)
	}
	defer terminal.Close()
	if e = terminal.RequestPty("xterm", 24, 80, gossh.TerminalModes{}); e != nil {
		t.Fatal(e)
	}
	stdin, e := terminal.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	stdout, e := terminal.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = terminal.Shell(); e != nil {
		t.Fatal(e)
	}
	go func() { io.WriteString(stdin, "help\rquit\r") }()
	b, e := io.ReadAll(stdout)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Contains(b, []byte("Restricted management console")) || !bytes.Contains(b, []byte("mapping add")) {
		t.Fatalf("TUI output: %s", b)
	}
	if e = terminal.Wait(); e != nil {
		t.Fatal(e)
	}
	events := hub.Snapshot(u.ID, true)
	if len(events) == 0 {
		t.Fatal("no activity recorded")
	}
	found := false
	for _, v := range events {
		if v.Operation == "git-receive-pack" && v.Status == "completed" && v.BytesIn > 0 && v.BytesOut > 0 {
			found = true
		}
	}
	if !found {
		t.Fatalf("no completed streamed push: %+v", events)
	}
}
