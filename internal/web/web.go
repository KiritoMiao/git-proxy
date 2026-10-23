package web

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kirito/git-proxy/internal/activity"
	"github.com/kirito/git-proxy/internal/store"
)

//go:embed templates/*.html static/*
var assets embed.FS

const sessionCookie = "git_proxy_session"

type session struct {
	UserID      string
	AuthVersion int64
	CSRF        string
	Expires     time.Time
}

type server struct {
	db             *store.Store
	hub            *activity.Hub
	bootstrapToken string
	secureCookie   bool
	templates      *template.Template
	mu             sync.Mutex
	sessions       map[string]session
	static         http.Handler
}

type pageData struct {
	Page, Title, CSRF, Error, Notice, Banner string
	User                                     store.User
	Users                                    []store.User
	Keys                                     []store.Key
	Mappings                                 []store.Mapping
	Events                                   []activity.Event
	Settings                                 store.Settings
	DefaultDestination                       store.DefaultDestination
	DefaultDestinationPort                   string
	EditMapping                              store.Mapping
	Editing                                  bool
	Active                                   int
	Owners                                   map[string]string
	KeyNames                                 map[string]string
}

// New serves the management application and its embedded, locally built assets.
func New(db *store.Store, hub *activity.Hub, bootstrapToken string, secureCookie bool) http.Handler {
	static, err := fs.Sub(assets, "static")
	if err != nil {
		panic(err)
	}
	funcs := template.FuncMap{
		"when":  func(t time.Time) string { return t.Local().Format("Jan 2, 15:04:05") },
		"bytes": formatBytes,
		"owner": func(d pageData, id string) string {
			if n := d.Owners[id]; n != "" {
				return n
			}
			return id
		},
		"keyName": func(d pageData, id string) string {
			if id == "" {
				return "All owner keys"
			}
			if n := d.KeyNames[id]; n != "" {
				return n
			}
			return id
		},
	}
	s := &server{db: db, hub: hub, bootstrapToken: bootstrapToken, secureCookie: secureCookie,
		templates: template.Must(template.New("pages").Funcs(funcs).ParseFS(assets, "templates/*.html")),
		sessions:  make(map[string]session), static: http.StripPrefix("/static/", http.FileServer(http.FS(static)))}
	return s
}

func formatBytes(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	v := float64(n)
	for _, unit := range []string{"KiB", "MiB", "GiB", "TiB", "PiB", "EiB"} {
		v /= 1024
		if v < 1024 || unit == "EiB" {
			return fmt.Sprintf("%.1f %s", v, unit)
		}
	}
	return "0 B"
}

func randomToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("secure random unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func (s *server) timeout() time.Duration {
	n := s.db.GetSettings().SessionTimeoutMinutes
	if n < 1 {
		n = 120
	}
	return time.Duration(n) * time.Minute
}

func (s *server) issueSession(w http.ResponseWriter, user store.User) (string, session) {
	id := randomToken()
	sess := session{UserID: user.ID, AuthVersion: user.AuthVersion, CSRF: randomToken(), Expires: time.Now().Add(s.timeout())}
	s.mu.Lock()
	// Anonymous visitors may never return a cookie; prune during issuance too.
	now := time.Now()
	for token, existing := range s.sessions {
		if !now.Before(existing.Expires) {
			delete(s.sessions, token)
		}
	}
	if len(s.sessions) >= 4096 {
		var oldest string
		var expires time.Time
		for token, existing := range s.sessions {
			if oldest == "" || existing.Expires.Before(expires) {
				oldest, expires = token, existing.Expires
			}
		}
		delete(s.sessions, oldest)
	}
	s.sessions[id] = sess
	s.mu.Unlock()
	s.cookie(w, id, int(s.timeout().Seconds()))
	return id, sess
}

func (s *server) cookie(w http.ResponseWriter, id string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: id, Path: "/", HttpOnly: true,
		Secure: s.secureCookie, SameSite: http.SameSiteStrictMode, MaxAge: maxAge})
}

func (s *server) getSession(r *http.Request) (string, session, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return "", session{}, false
	}
	now := time.Now()
	ttl := s.timeout()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.sessions {
		if !now.Before(sess.Expires) {
			delete(s.sessions, id)
		}
	}
	sess, ok := s.sessions[c.Value]
	if !ok {
		return "", session{}, false
	}
	sess.Expires = now.Add(ttl)
	s.sessions[c.Value] = sess
	return c.Value, sess, true
}

func (s *server) removeSession(id string) {
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
}

func (s *server) purgeUser(id string) {
	s.mu.Lock()
	for token, sess := range s.sessions {
		if sess.UserID == id {
			delete(s.sessions, token)
		}
	}
	s.mu.Unlock()
}

func (s *server) sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = r.Header.Get("Referer")
	}
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.User != nil {
		return false
	}
	scheme := "http"
	if r.TLS != nil || s.secureCookie {
		scheme = "https"
	}
	return u.Scheme == scheme && strings.EqualFold(u.Host, r.Host)
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	if strings.HasPrefix(r.URL.Path, "/static/") {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			methodNotAllowed(w)
			return
		}
		s.static.ServeHTTP(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	id, sess, hasSession := s.getSession(r)
	var user store.User
	if hasSession && sess.UserID != "" {
		var err error
		user, err = s.db.User(sess.UserID)
		if err != nil || user.Disabled || user.AuthVersion != sess.AuthVersion {
			s.removeSession(id)
			hasSession = false
			user = store.User{}
		}
	}
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Request is too large or invalid.", http.StatusBadRequest)
			return
		}
		if !hasSession || !s.sameOrigin(r) || subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(sess.CSRF)) != 1 {
			http.Error(w, "This form has expired or came from another site. Reload the page and try again.", http.StatusForbidden)
			return
		}
	}
	if r.URL.Path == "/login" || r.URL.Path == "/setup" {
		if user.ID != "" {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		initialized := s.db.Initialized()
		if r.URL.Path == "/setup" && initialized {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if r.URL.Path == "/login" && !initialized {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		if !hasSession {
			id, sess = s.issueSession(w, store.User{})
		}
		page := strings.TrimPrefix(r.URL.Path, "/")
		d := s.data(user, sess, page)
		if r.Method == http.MethodPost {
			var err error
			if page == "setup" {
				token := r.PostForm.Get("bootstrap_token")
				if s.bootstrapToken == "" || subtle.ConstantTimeCompare([]byte(token), []byte(s.bootstrapToken)) != 1 {
					err = fmt.Errorf("The bootstrap token is incorrect. Use the setup-token file in the server data directory.")
				} else {
					user, err = s.db.Bootstrap(r.PostForm.Get("username"), r.PostForm.Get("password"))
				}
			} else {
				user, err = s.db.Authenticate(r.PostForm.Get("username"), r.PostForm.Get("password"))
			}
			if err != nil {
				d.Error = err.Error()
				s.render(w, d, http.StatusBadRequest)
				return
			}
			s.removeSession(id)
			s.issueSession(w, user)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		s.render(w, d, http.StatusOK)
		return
	}
	if r.URL.Path == "/docs" && r.Method == http.MethodGet {
		s.render(w, s.data(user, sess, "docs"), http.StatusOK)
		return
	}
	if user.ID == "" {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.Error(w, "Authentication required.", http.StatusUnauthorized)
			return
		}
		target := "/login"
		if !s.db.Initialized() {
			target = "/setup"
		}
		http.Redirect(w, r, target, http.StatusSeeOther)
		return
	}
	s.cookie(w, id, int(s.timeout().Seconds()))
	if r.URL.Path == "/logout" {
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		s.removeSession(id)
		s.cookie(w, "", -1)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if r.URL.Path == "/api/activity" {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		events := s.hub.Snapshot(user.ID, user.Role == "admin")
		if events == nil {
			events = []activity.Event{}
		}
		json.NewEncoder(w).Encode(events)
		return
	}
	if r.URL.Path == "/api/host-identity" {
		s.hostIdentity(w, r)
		return
	}
	if r.URL.Path == "/actions" {
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		s.action(w, r, user, sess)
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	pages := map[string]string{"/": "dashboard", "/mappings": "mappings", "/keys": "keys", "/users": "users", "/settings": "settings", "/account": "account"}
	page, ok := pages[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if (page == "users" || page == "settings") && user.Role != "admin" {
		http.Error(w, "Administrator access required.", http.StatusForbidden)
		return
	}
	d := s.data(user, sess, page)
	d.Notice = r.URL.Query().Get("notice")
	if err := s.load(&d); err != nil {
		d.Error = err.Error()
		s.render(w, d, http.StatusInternalServerError)
		return
	}
	if page == "mappings" && r.URL.Query().Get("edit") != "" {
		for _, m := range d.Mappings {
			if m.ID == r.URL.Query().Get("edit") {
				d.EditMapping = m
				d.Editing = true
				break
			}
		}
		if !d.Editing {
			http.NotFound(w, r)
			return
		}
	}
	s.render(w, d, http.StatusOK)
}

func methodNotAllowed(w http.ResponseWriter) {
	w.Header().Set("Allow", "GET, POST")
	http.Error(w, "Method not allowed.", http.StatusMethodNotAllowed)
}

func (s *server) data(user store.User, sess session, page string) pageData {
	titles := map[string]string{"dashboard": "Overview", "mappings": "Repository routes", "keys": "SSH keys", "users": "People", "settings": "Settings", "account": "Your account", "login": "Welcome back", "setup": "Create your control plane", "docs": "Connection documentation"}
	settings := s.db.GetSettings()
	return pageData{Page: page, Title: titles[page], CSRF: sess.CSRF, User: user, Banner: settings.Banner, Settings: settings,
		Owners: make(map[string]string), KeyNames: make(map[string]string), EditMapping: store.Mapping{UserID: user.ID, Host: "github.com", Port: 22, RemoteUser: "git"}}
}

func (s *server) load(d *pageData) error {
	var err error
	if d.User.Role == "admin" {
		d.Users, err = s.db.Users(d.User.ID)
		if err != nil {
			return err
		}
	} else {
		d.Users = []store.User{d.User}
	}
	for _, u := range d.Users {
		d.Owners[u.ID] = u.Username
	}
	if d.Page == "settings" && d.User.Role == "admin" {
		d.DefaultDestination, err = s.db.GetDefaultDestination(d.User.ID)
		if err != nil {
			return err
		}
		d.DefaultDestinationPort = strconv.Itoa(d.DefaultDestination.Port)
	}
	if d.Page == "dashboard" || d.Page == "keys" || d.Page == "mappings" {
		d.Keys, err = s.db.Keys(d.User.ID)
		if err != nil {
			return err
		}
		for _, k := range d.Keys {
			d.KeyNames[k.ID] = k.Name
		}
	}
	if d.Page == "dashboard" || d.Page == "mappings" {
		d.Mappings, err = s.db.Mappings(d.User.ID)
		if err != nil {
			return err
		}
	}
	if d.Page == "dashboard" {
		d.Events = s.hub.Snapshot(d.User.ID, d.User.Role == "admin")
		for _, e := range d.Events {
			if e.FinishedAt == nil {
				d.Active++
			}
		}
	}
	return nil
}

func (s *server) render(w http.ResponseWriter, d pageData, status int) {
	// Render before writing headers, so a template failure never emits a partial page.
	var b strings.Builder
	if err := s.templates.ExecuteTemplate(&b, "layout", d); err != nil {
		http.Error(w, "Unable to render this page.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprint(w, b.String())
}

func (s *server) action(w http.ResponseWriter, r *http.Request, user store.User, sess session) {
	f := r.PostForm
	var err error
	var defaultDestination store.DefaultDestination
	page, notice := "dashboard", "Changes saved."
	switch f.Get("action") {
	case "key_add":
		page = "keys"
		_, err = s.db.AddKey(user.ID, f.Get("user_id"), f.Get("name"), f.Get("public_key"))
		notice = "SSH key added."
	case "key_delete":
		page = "keys"
		err = s.db.DeleteKey(user.ID, f.Get("id"))
		notice = "SSH key removed."
	case "mapping_save":
		page = "mappings"
		port, parseErr := strconv.Atoi(f.Get("port"))
		if parseErr != nil {
			err = fmt.Errorf("Enter a valid upstream port.")
			break
		}
		_, err = s.db.SaveMapping(user.ID, store.Mapping{ID: f.Get("id"), UserID: f.Get("user_id"), KeyID: f.Get("key_id"), Source: f.Get("source"), Host: f.Get("host"), Port: port, RemoteUser: f.Get("remote_user"), RemotePath: f.Get("remote_path"), HostFingerprint: f.Get("host_fingerprint"), ReadOnly: f.Get("read_only") == "on"})
		notice = "Repository route saved."
	case "mapping_delete":
		page = "mappings"
		err = s.db.DeleteMapping(user.ID, f.Get("id"))
		notice = "Repository route removed."
	case "user_create":
		page = "users"
		_, err = s.db.CreateUser(user.ID, f.Get("username"), f.Get("password"), f.Get("role"))
		notice = "User created."
	case "user_update":
		page = "users"
		err = s.db.UpdateUser(user.ID, f.Get("id"), f.Get("username"), f.Get("role"), f.Get("disabled") == "on")
		if err == nil {
			s.purgeUser(f.Get("id"))
		}
	case "user_delete":
		page = "users"
		if user.Role != "admin" {
			err = fmt.Errorf("Administrator access required.")
			break
		}
		if f.Get("id") == user.ID {
			err = fmt.Errorf("You cannot delete the account you are currently using.")
			break
		}
		target, lookupErr := s.db.User(f.Get("id"))
		if lookupErr != nil {
			err = lookupErr
			break
		}
		if f.Get("confirm_username") != target.Username {
			err = fmt.Errorf("Type the exact username to confirm deletion.")
			break
		}
		err = s.db.DeleteUser(user.ID, target.ID)
		if err == nil {
			s.purgeUser(target.ID)
		}
		notice = "User and their keys and routes removed."
	case "password":
		page = "account"
		target := user.ID
		if user.Role == "admin" && f.Get("user_id") != "" {
			target = f.Get("user_id")
			page = "users"
		}
		if f.Get("password") != f.Get("password_confirm") {
			err = fmt.Errorf("The passwords do not match.")
			break
		}
		err = s.db.SetPassword(user.ID, target, f.Get("password"))
		if err == nil {
			s.purgeUser(target)
			if target == user.ID {
				s.cookie(w, "", -1)
				http.Redirect(w, r, "/login?changed=1", http.StatusSeeOther)
				return
			}
		}
		notice = "Password updated and all sessions for this user signed out."
	case "default_destination":
		page = "settings"
		if user.Role != "admin" {
			http.Error(w, "Administrator access required.", http.StatusForbidden)
			return
		}
		defaultDestination = store.DefaultDestination{Enabled: f.Get("enabled") == "on", Host: f.Get("host"), RemoteUser: f.Get("remote_user"), HostFingerprint: f.Get("host_fingerprint"), ReadOnly: f.Get("read_only") == "on"}
		port, parseErr := strconv.Atoi(f.Get("port"))
		if parseErr != nil {
			err = fmt.Errorf("Enter a valid upstream port.")
			break
		}
		defaultDestination.Port = port
		err = s.db.SaveDefaultDestination(user.ID, defaultDestination)
		notice = "Default destination saved."
	case "settings":
		page = "settings"
		max, e1 := strconv.Atoi(f.Get("max_sessions"))
		timeout, e2 := strconv.Atoi(f.Get("session_timeout"))
		if e1 != nil || e2 != nil {
			err = fmt.Errorf("Session limits must be whole numbers.")
			break
		}
		err = s.db.SaveSettings(user.ID, store.Settings{Banner: f.Get("banner"), MaxSessionsPerUser: max, SessionTimeoutMinutes: timeout})
	default:
		http.Error(w, "Unknown action.", http.StatusBadRequest)
		return
	}
	if err != nil {
		if (page == "users" || page == "settings") && user.Role != "admin" {
			http.Error(w, "Administrator access required.", http.StatusForbidden)
			return
		}
		d := s.data(user, sess, page)
		d.Error = err.Error()
		if loadErr := s.load(&d); loadErr != nil {
			http.Error(w, loadErr.Error(), http.StatusInternalServerError)
			return
		}
		if f.Get("action") == "mapping_save" {
			port, _ := strconv.Atoi(f.Get("port"))
			d.EditMapping = store.Mapping{ID: f.Get("id"), UserID: f.Get("user_id"), KeyID: f.Get("key_id"), Source: f.Get("source"), Host: f.Get("host"), Port: port, RemoteUser: f.Get("remote_user"), RemotePath: f.Get("remote_path"), HostFingerprint: f.Get("host_fingerprint"), ReadOnly: f.Get("read_only") == "on"}
			d.Editing = f.Get("id") != ""
		}
		if f.Get("action") == "default_destination" {
			d.DefaultDestination = defaultDestination
			d.DefaultDestinationPort = f.Get("port")
		}
		s.render(w, d, http.StatusBadRequest)
		return
	}
	target := "/" + page
	if page == "dashboard" {
		target = "/"
	}
	http.Redirect(w, r, target+"?notice="+url.QueryEscape(notice), http.StatusSeeOther)
}
