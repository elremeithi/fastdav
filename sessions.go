package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Browser sign-in sessions for the account page (and read-only browsing),
// so browsers get a real login page instead of the Basic-auth popup.
// WebDAV clients keep using Basic auth.

const (
	cookieName      = "fastdav_session"
	sessionTTL      = 12 * time.Hour
	sessionTTLLong  = 30 * 24 * time.Hour
	maxSessionsKept = 10000
)

type session struct {
	user    string
	pwHash  string // invalidates the session when the password changes
	expires time.Time
	long    bool // "keep me signed in"
}

type sessionStore struct {
	mu sync.Mutex
	m  map[[32]byte]*session
}

func newSessionStore() *sessionStore { return &sessionStore{m: map[[32]byte]*session{}} }

func (ss *sessionStore) create(user, pwHash string, ttl time.Duration) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	tok := base64.RawURLEncoding.EncodeToString(b)
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if len(ss.m) >= maxSessionsKept {
		ss.pruneLocked()
	}
	ss.m[sha256.Sum256([]byte(tok))] = &session{user: user, pwHash: pwHash, expires: time.Now().Add(ttl), long: ttl == sessionTTLLong}
	return tok
}

func (ss *sessionStore) get(tok string) *session {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	k := sha256.Sum256([]byte(tok))
	s := ss.m[k]
	if s == nil {
		return nil
	}
	if time.Now().After(s.expires) {
		delete(ss.m, k)
		return nil
	}
	c := *s
	return &c
}

func (ss *sessionStore) delete(tok string) {
	ss.mu.Lock()
	delete(ss.m, sha256.Sum256([]byte(tok)))
	ss.mu.Unlock()
}

func (ss *sessionStore) prune() {
	ss.mu.Lock()
	ss.pruneLocked()
	ss.mu.Unlock()
}

func (ss *sessionStore) pruneLocked() {
	now := time.Now()
	for k, s := range ss.m {
		if now.After(s.expires) {
			delete(ss.m, k)
		}
	}
}

// sessionPrincipal returns the signed-in user for a browser request, or nil.
func (s *Server) sessionPrincipal(r *http.Request) *Principal {
	c, err := r.Cookie(cookieName)
	if err != nil || c.Value == "" {
		return nil
	}
	sess := s.sessions.get(c.Value)
	if sess == nil {
		return nil
	}
	u := s.store.Snapshot().user(sess.user)
	if u == nil || u.PasswordHash != sess.pwHash {
		s.sessions.delete(c.Value)
		return nil
	}
	return &Principal{User: u.Username, Admin: u.Admin, ReadOnly: u.ReadOnly, Root: s.store.userRoot(u), AppOnly: u.AppOnly}
}

// sessionIsLong reports whether the request's session was "keep me signed in".
func (s *Server) sessionIsLong(r *http.Request) bool {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	sess := s.sessions.get(c.Value)
	return sess != nil && sess.long
}

func (s *Server) cookiePath() string { return s.opt.Prefix + "/" }

func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, user string, remember bool) {
	u := s.store.Snapshot().user(user)
	if u == nil {
		return
	}
	ttl := sessionTTL
	if remember {
		ttl = sessionTTLLong
	}
	c := &http.Cookie{
		Name:     cookieName,
		Value:    s.sessions.create(user, u.PasswordHash, ttl),
		Path:     s.cookiePath(),
		HttpOnly: true,
		Secure:   r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"),
		SameSite: http.SameSiteStrictMode,
	}
	if remember {
		c.MaxAge = int(ttl.Seconds())
	}
	http.SetCookie(w, c)
}

func (s *Server) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		s.sessions.delete(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: s.cookiePath(), MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

// basicPrincipal checks Basic credentials without ever sending a
// WWW-Authenticate challenge (which is what makes browsers show a popup).
func (s *Server) basicPrincipal(r *http.Request) *Principal {
	user, pass, ok := r.BasicAuth()
	if !ok {
		return nil
	}
	ip := s.clientIP(r)
	if s.lim.Blocked(ip) {
		return nil
	}
	if p := s.store.Authenticate(user, pass); p != nil {
		return p
	}
	s.lim.Fail(ip)
	return nil
}

// isBrowser reports whether a request comes from a web browser navigating
// to a page (as opposed to a WebDAV client such as Windows' WebClient,
// macOS WebDAVFS, Office, rclone or a mobile app).
func isBrowser(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if !strings.Contains(r.Header.Get("Accept"), "text/html") {
		return false
	}
	ua := r.Header.Get("User-Agent")
	if !strings.HasPrefix(ua, "Mozilla/") {
		return false
	}
	for _, x := range []string{"MiniRedir", "WebDAV", "Microsoft Office", "FrontPage", "DavClnt", "Microsoft-WebDAV"} {
		if strings.Contains(ua, x) {
			return false
		}
	}
	return true
}

// safeNext only allows redirects to a local path under the server prefix.
func (s *Server) safeNext(next string) string {
	def := s.opt.Prefix + uiPath
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.ContainsAny(next, "\\\r\n") {
		return def
	}
	if s.opt.Prefix != "" && next != s.opt.Prefix && !strings.HasPrefix(next, s.opt.Prefix+"/") {
		return def
	}
	return next
}
