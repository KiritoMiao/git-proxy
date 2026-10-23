package sshserver

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kirito/git-proxy/internal/store"
	"golang.org/x/term"
)

func TestDefaultDestinationTerminalPermissions(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "proxy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	admin, err := db.Bootstrap("admin", "admin-password-1234")
	if err != nil {
		t.Fatal(err)
	}
	member, err := db.CreateUser(admin.ID, "member", "member-password-1234", "user")
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{db: db}
	for _, command := range []string{"default destination", "default destination edit"} {
		var output bytes.Buffer
		terminal := term.NewTerminal(&output, "")
		if err := server.tuiCommand(terminal, member, command); err == nil {
			t.Fatalf("member accepted %s", command)
		}
	}
	// An administrator can enable and then disable the destination with the
	// actual prompt parser, without granting a management command to members.
	input := &terminalInput{Reader: strings.NewReader("true\r\r\r\rSHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\rtrue\r")}
	if err = server.tuiCommand(term.NewTerminal(input, ""), admin, "default destination edit"); err != nil {
		t.Fatal(err)
	}
	saved, err := db.GetDefaultDestination(admin.ID)
	if err != nil || !saved.Enabled || !saved.ReadOnly || saved.Host != "github.com" {
		t.Fatalf("saved %+v: %v", saved, err)
	}
	input = &terminalInput{Reader: strings.NewReader("false\r")}
	if err = server.tuiCommand(term.NewTerminal(input, ""), admin, "default destination edit"); err != nil {
		t.Fatal(err)
	}
	saved, err = db.GetDefaultDestination(admin.ID)
	if err != nil || saved.Enabled {
		t.Fatalf("disabled %+v: %v", saved, err)
	}
}

type terminalInput struct {
	*strings.Reader
	bytes.Buffer
}

func (i *terminalInput) Read(p []byte) (int, error)  { return i.Reader.Read(p) }
func (i *terminalInput) Write(p []byte) (int, error) { return i.Buffer.Write(p) }
