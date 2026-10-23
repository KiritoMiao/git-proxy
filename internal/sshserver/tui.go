package sshserver

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"

	ssh "github.com/gliderlabs/ssh"
	"github.com/kirito/git-proxy/internal/store"
	"github.com/kirito/git-proxy/internal/version"
	"golang.org/x/term"
)

// terminalText prevents stored names or remote error messages from injecting terminal escapes.
func terminalText(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}
func (s *Server) tui(sess ssh.Session, user store.User) {
	t := term.NewTerminal(sess, "proxy> ")
	pty, wins, _ := sess.Pty()
	_ = t.SetSize(pty.Window.Width, pty.Window.Height)
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case w, ok := <-wins:
				if !ok {
					return
				}
				_ = t.SetSize(w.Width, w.Height)
			case <-done:
				return
			}
		}
	}()
	fmt.Fprintf(t, "\r\n%s — %s (%s)\r\nRestricted management console. Type help for commands.\r\n", terminalText(s.db.GetSettings().Banner), terminalText(user.Username), user.Role)
	fmt.Fprintf(t, "Source: %s\r\n", version.Repository)
	for {
		line, err := t.ReadLine()
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		u, _, err := s.db.AuthenticateKey(sess.PublicKey())
		if err != nil {
			fmt.Fprintln(t, "Access revoked.")
			break
		}
		if line == "quit" || line == "exit" {
			break
		}
		err = s.tuiCommand(t, u, line)
		if err != nil {
			fmt.Fprintln(t, "Error:", terminalText(err.Error()))
		}
	}
	sess.Exit(0)
}
func prompt(t *term.Terminal, label, value string) (string, error) {
	p := label
	if value != "" {
		p += " [" + terminalText(value) + "]"
	}
	t.SetPrompt(p + ": ")
	defer t.SetPrompt("proxy> ")
	v, e := t.ReadLine()
	if len(v) > 8192 {
		return "", fmt.Errorf("input too long")
	}
	v = strings.TrimSpace(v)
	if v == "" {
		v = value
	}
	return v, e
}
func password(t *term.Terminal) (string, error) {
	p, e := t.ReadPassword("New password (12+ characters): ")
	if e != nil {
		return "", e
	}
	q, e := t.ReadPassword("Confirm password: ")
	if e != nil {
		return "", e
	}
	if p != q {
		return "", fmt.Errorf("passwords differ")
	}
	return p, nil
}
func (s *Server) tuiCommand(t *term.Terminal, u store.User, cmd string) error {
	switch cmd {
	case "help":
		fmt.Fprintln(t, "Commands (no shell or code execution):\n  mappings       list repository routes\n  mapping add    create a route\n  mapping edit   edit a route by ID\n  mapping delete delete a route by ID\n  keys           list registered keys\n  key add        register a public key\n  key delete     remove a key\n  activity       recent Git streams\n  password       change your password\n  quit           disconnect")
		if u.Role == "admin" {
			fmt.Fprintln(t, "Admin: users, user add, user edit, user delete, user password, settings, settings edit, default destination, default destination edit")
		}
	case "mappings":
		ms, e := s.db.Mappings(u.ID)
		if e != nil {
			return e
		}
		for _, m := range ms {
			fmt.Fprintf(t, "%s owner=%s key=%s %s -> %s@%s:%d:%s read-only=%t\n  host key: %s\n", m.ID, m.UserID, m.KeyID, m.Source, m.RemoteUser, m.Host, m.Port, m.RemotePath, m.ReadOnly, m.HostFingerprint)
		}
		if len(ms) == 0 {
			fmt.Fprintln(t, "No mappings. Use mapping add.")
		}
	case "mapping add", "mapping edit":
		return s.editMapping(t, u, cmd == "mapping edit")
	case "mapping delete":
		id, e := prompt(t, "Mapping ID", "")
		if e != nil {
			return e
		}
		return s.db.DeleteMapping(u.ID, id)
	case "keys":
		ks, e := s.db.Keys(u.ID)
		if e != nil {
			return e
		}
		for _, k := range ks {
			fmt.Fprintf(t, "%s owner=%s %s %s\n", k.ID, k.UserID, terminalText(k.Name), k.Fingerprint)
		}
	case "key add":
		owner := u.ID
		var e error
		if u.Role == "admin" {
			owner, e = prompt(t, "Owner user ID", u.ID)
			if e != nil {
				return e
			}
		}
		name, e := prompt(t, "Key name", "")
		if e != nil {
			return e
		}
		pub, e := prompt(t, "Public key (one line)", "")
		if e != nil {
			return e
		}
		k, e := s.db.AddKey(u.ID, owner, name, pub)
		if e == nil {
			fmt.Fprintln(t, "Registered", k.ID, k.Fingerprint)
		}
		return e
	case "key delete":
		id, e := prompt(t, "Key ID", "")
		if e != nil {
			return e
		}
		return s.db.DeleteKey(u.ID, id)
	case "activity":
		for _, e := range s.hub.Snapshot(u.ID, u.Role == "admin") {
			fmt.Fprintf(t, "%s %s %s %s in=%d out=%d %s\n", e.StartedAt.Format("15:04:05"), e.Username, e.Operation, e.Source, e.BytesIn, e.BytesOut, e.Status)
		}
	case "password":
		p, e := password(t)
		if e != nil {
			return e
		}
		return s.db.SetPassword(u.ID, u.ID, p)
	case "users":
		us, e := s.db.Users(u.ID)
		if e != nil {
			return e
		}
		for _, v := range us {
			fmt.Fprintf(t, "%s %s %s disabled=%t\n", v.ID, v.Username, v.Role, v.Disabled)
		}
	case "user add":
		if _, e := s.db.Users(u.ID); e != nil {
			return e
		}
		name, e := prompt(t, "Username", "")
		if e != nil {
			return e
		}
		role, e := prompt(t, "Role (admin/user)", "user")
		if e != nil {
			return e
		}
		p, e := password(t)
		if e != nil {
			return e
		}
		v, e := s.db.CreateUser(u.ID, name, p, role)
		if e == nil {
			fmt.Fprintln(t, "Created", v.ID)
		}
		return e
	case "user edit":
		us, e := s.db.Users(u.ID)
		if e != nil {
			return e
		}
		id, e := prompt(t, "User ID", "")
		if e != nil {
			return e
		}
		var v store.User
		for _, x := range us {
			if x.ID == id {
				v = x
			}
		}
		if v.ID == "" {
			return fmt.Errorf("user not found")
		}
		name, e := prompt(t, "Username", v.Username)
		if e != nil {
			return e
		}
		role, e := prompt(t, "Role (admin/user)", v.Role)
		if e != nil {
			return e
		}
		disabled, e := prompt(t, "Disabled (true/false)", strconv.FormatBool(v.Disabled))
		if e != nil {
			return e
		}
		b, e := strconv.ParseBool(disabled)
		if e != nil {
			return e
		}
		return s.db.UpdateUser(u.ID, id, name, role, b)
	case "user delete":
		if _, e := s.db.Users(u.ID); e != nil {
			return e
		}
		id, e := prompt(t, "User ID", "")
		if e != nil {
			return e
		}
		confirm, e := prompt(t, "Type DELETE to remove user and their keys/routes", "")
		if e != nil {
			return e
		}
		if confirm != "DELETE" {
			return fmt.Errorf("cancelled")
		}
		return s.db.DeleteUser(u.ID, id)
	case "user password":
		if _, e := s.db.Users(u.ID); e != nil {
			return e
		}
		id, e := prompt(t, "User ID", "")
		if e != nil {
			return e
		}
		p, e := password(t)
		if e != nil {
			return e
		}
		return s.db.SetPassword(u.ID, id, p)
	case "default destination", "default destination edit":
		return s.defaultDestination(t, u, cmd == "default destination edit")
	case "settings", "settings edit":
		if _, e := s.db.Users(u.ID); e != nil {
			return e
		}
		v := s.db.GetSettings()
		if cmd == "settings" {
			fmt.Fprintf(t, "Banner: %s\nMax sessions/user: %d\nSession timeout minutes: %d\n", terminalText(v.Banner), v.MaxSessionsPerUser, v.SessionTimeoutMinutes)
			return nil
		}
		banner, e := prompt(t, "Banner", v.Banner)
		if e != nil {
			return e
		}
		max, e := prompt(t, "Max sessions per user", strconv.Itoa(v.MaxSessionsPerUser))
		if e != nil {
			return e
		}
		timeout, e := prompt(t, "Session timeout minutes", strconv.Itoa(v.SessionTimeoutMinutes))
		if e != nil {
			return e
		}
		n, e := strconv.Atoi(max)
		if e != nil {
			return e
		}
		minutes, e := strconv.Atoi(timeout)
		if e != nil {
			return e
		}
		return s.db.SaveSettings(u.ID, store.Settings{Banner: banner, MaxSessionsPerUser: n, SessionTimeoutMinutes: minutes})
	default:
		return fmt.Errorf("unknown command; type help")
	}
	return nil
}
func (s *Server) editMapping(t *term.Terminal, u store.User, edit bool) error {
	m := store.Mapping{UserID: u.ID, Host: "github.com", Port: 22, RemoteUser: "git"}
	if edit {
		ms, e := s.db.Mappings(u.ID)
		if e != nil {
			return e
		}
		id, e := prompt(t, "Mapping ID", "")
		if e != nil {
			return e
		}
		found := false
		for _, v := range ms {
			if v.ID == id {
				m = v
				found = true
			}
		}
		if !found {
			return fmt.Errorf("mapping not found")
		}
	}
	var e error
	ask := func(label string, target *string) {
		if e != nil {
			return
		}
		*target, e = prompt(t, label, *target)
	}
	if u.Role == "admin" {
		ask("Owner user ID", &m.UserID)
	}
	fmt.Fprintln(t, "Use '-' for all owner keys; exact key routes take precedence.")
	key := m.KeyID
	if key == "" {
		key = "-"
	}
	ask("Key ID", &key)
	if key == "-" {
		key = ""
	}
	m.KeyID = key
	ask("Source repository (.git added if omitted)", &m.Source)
	ask("Upstream hostname/IP", &m.Host)
	port := strconv.Itoa(m.Port)
	ask("Upstream port", &port)
	ask("Upstream SSH user", &m.RemoteUser)
	ask("Upstream repository path", &m.RemotePath)
	ask("Trusted host SHA256 fingerprint", &m.HostFingerprint)
	ro := strconv.FormatBool(m.ReadOnly)
	ask("Read-only (true/false)", &ro)
	if e != nil {
		return e
	}
	m.Port, e = strconv.Atoi(port)
	if e != nil {
		return e
	}
	m.ReadOnly, e = strconv.ParseBool(ro)
	if e != nil {
		return e
	}
	m, e = s.db.SaveMapping(u.ID, m)
	if e == nil {
		fmt.Fprintln(t, "Saved mapping", m.ID)
	}
	return e
}

func (s *Server) defaultDestination(t *term.Terminal, u store.User, edit bool) error {
	d, err := s.db.GetDefaultDestination(u.ID)
	if err != nil {
		return err
	}
	if !edit {
		fmt.Fprintf(t, "Catch-all enabled: %t\nDestination: %s@%s:%d\nHost key: %s\nRead-only: %t\nUnmapped repositories retain their requested path.\n", d.Enabled, d.RemoteUser, d.Host, d.Port, d.HostFingerprint, d.ReadOnly)
		return nil
	}
	enabled, err := prompt(t, "Enable default destination (true/false)", strconv.FormatBool(d.Enabled))
	if err != nil {
		return err
	}
	d.Enabled, err = strconv.ParseBool(enabled)
	if err != nil {
		return err
	}
	if d.Enabled {
		ask := func(label string, value *string) {
			if err == nil {
				*value, err = prompt(t, label, *value)
			}
		}
		ask("Upstream hostname/IP", &d.Host)
		port := strconv.Itoa(d.Port)
		ask("Upstream port", &port)
		ask("Upstream SSH user", &d.RemoteUser)
		ask("Trusted host SHA256 fingerprint", &d.HostFingerprint)
		readOnly := strconv.FormatBool(d.ReadOnly)
		ask("Read-only (true/false)", &readOnly)
		if err != nil {
			return err
		}
		d.Port, err = strconv.Atoi(port)
		if err != nil {
			return err
		}
		d.ReadOnly, err = strconv.ParseBool(readOnly)
		if err != nil {
			return err
		}
	}
	if err = s.db.SaveDefaultDestination(u.ID, d); err != nil {
		return err
	}
	fmt.Fprintln(t, "Default destination saved.")
	return nil
}
