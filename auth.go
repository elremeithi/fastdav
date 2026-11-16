package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type AppPassword struct {
	ID       string     `json:"id"`
	Name     string     `json:"name"`
	Hash     string     `json:"hash"` // sha256(token), hex
	Hint     string     `json:"hint"` // last 4 chars, for display
	ReadOnly bool       `json:"read_only"`
	Scope    string     `json:"scope"` // optional sub-folder the token is confined to
	Created  time.Time  `json:"created"`
	LastUsed *time.Time `json:"last_used,omitempty"`
	Expires  *time.Time `json:"expires,omitempty"`
}

type User struct {
	Username     string         `json:"username"`
	PasswordHash string         `json:"password_hash"` // bcrypt
	Root         string         `json:"root"`          // relative to DATA_DIR, "" = whole data dir
	Admin        bool           `json:"admin"`
	ReadOnly     bool           `json:"read_only"`
	AppOnly      bool           `json:"app_passwords_only"` // main password only valid for the web UI
	AppPasswords []*AppPassword `json:"app_passwords"`
}

type Config struct {
	Users []*User `json:"users"`
}

func (c *Config) user(name string) *User {
	for _, u := range c.Users {
		if u.Username == name {
			return u
		}
	}
	return nil
}

// Principal is the result of a successful authentication.
type Principal struct {
	User     string
	Admin    bool
	ReadOnly bool
	Root     string // absolute on-disk root for this session
	AppID    string // "" when the main password was used
	AppOnly  bool
}

type cacheEntry struct {
	p       *Principal
	gen     uint64
	expires int64
}

type appRef struct {
	user string
	app  *AppPassword
}

type Store struct {
	path    string
	dataDir string

	mu        sync.RWMutex
	cfg       *Config
	modTime   time.Time
	byHash    map[string]appRef
	lastCheck atomic.Int64
	gen       atomic.Uint64

	cache    sync.Map // [32]byte -> cacheEntry
	used     sync.Map // app id -> time.Time
	dirty    atomic.Bool
	dummyBcr []byte
}

func NewStore(path, dataDir string) (*Store, error) {
	s := &Store{path: path, dataDir: dataDir, cfg: &Config{}, byHash: map[string]appRef{}}
	s.dummyBcr, _ = bcrypt.GenerateFromPassword([]byte("dummy-password"), bcrypt.DefaultCost)
	if err := s.load(true); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) load(force bool) error {
	fi, err := os.Stat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	s.mu.RLock()
	same := fi.ModTime().Equal(s.modTime)
	s.mu.RUnlock()
	if same && !force {
		return nil
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	cfg := &Config{}
	if err := json.Unmarshal(b, cfg); err != nil {
		return fmt.Errorf("parse %s: %w", s.path, err)
	}
	s.mu.Lock()
	s.setLocked(cfg, fi.ModTime())
	s.mu.Unlock()
	return nil
}

func (s *Store) setLocked(cfg *Config, mt time.Time) {
	idx := map[string]appRef{}
	for _, u := range cfg.Users {
		for _, a := range u.AppPasswords {
			idx[a.Hash] = appRef{user: u.Username, app: a}
		}
	}
	s.cfg, s.modTime, s.byHash = cfg, mt, idx
	s.gen.Add(1) // invalidates the auth cache
}

// maybeReload picks up edits made by the CLI (at most once per second).
func (s *Store) maybeReload() {
	now := time.Now().UnixNano()
	last := s.lastCheck.Load()
	if now-last < int64(time.Second) || !s.lastCheck.CompareAndSwap(last, now) {
		return
	}
	_ = s.load(false)
}

// Update applies fn to a fresh copy of the config and saves it atomically.
func (s *Store) Update(fn func(c *Config) error) error {
	_ = s.load(false)
	s.mu.Lock()
	defer s.mu.Unlock()
	b, _ := json.Marshal(s.cfg)
	cfg := &Config{}
	_ = json.Unmarshal(b, cfg)
	if err := fn(cfg); err != nil {
		return err
	}
	s.applyUsedLocked(cfg)
	if err := writeJSONAtomic(s.path, cfg); err != nil {
		return err
	}
	fi, _ := os.Stat(s.path)
	var mt time.Time
	if fi != nil {
		mt = fi.ModTime()
	}
	s.setLocked(cfg, mt)
	return nil
}

func (s *Store) applyUsedLocked(cfg *Config) {
	s.used.Range(func(k, v any) bool {
		t := v.(time.Time)
		for _, u := range cfg.Users {
			for _, a := range u.AppPasswords {
				if a.ID == k.(string) && (a.LastUsed == nil || a.LastUsed.Before(t)) {
					a.LastUsed = &t
				}
			}
		}
		s.used.Delete(k)
		return true
	})
	s.dirty.Store(false)
}

// FlushUsage persists "last used" timestamps (batched, not per request).
func (s *Store) FlushUsage() {
	if !s.dirty.Load() {
		return
	}
	_ = s.Update(func(*Config) error { return nil })
}

func writeJSONAtomic(p string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	chownToPUID(tmp)
	return os.Rename(tmp, p)
}

func (s *Store) Snapshot() *Config {
	s.maybeReload()
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, _ := json.Marshal(s.cfg)
	c := &Config{}
	_ = json.Unmarshal(b, c)
	return c
}

func (s *Store) UserCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.cfg.Users)
}

func (s *Store) userRoot(u *User) string {
	return resolve(s.dataDir, u.Root)
}

// Authenticate verifies a username + password (main or app password).
// Results are cached for 5 minutes keyed by sha256(user, password) so the
// expensive bcrypt check runs only once per client session.
func (s *Store) Authenticate(user, pass string) *Principal {
	s.maybeReload()
	gen := s.gen.Load()
	key := sha256.Sum256([]byte(user + "\x00" + pass))
	now := time.Now()
	if v, ok := s.cache.Load(key); ok {
		e := v.(cacheEntry)
		if e.gen == gen && e.expires > now.UnixNano() {
			if e.p.AppID != "" {
				s.used.Store(e.p.AppID, now)
				s.dirty.Store(true)
			}
			return e.p
		}
	}

	var p *Principal
	th := sha256.Sum256([]byte(pass))
	hexHash := hex.EncodeToString(th[:])

	s.mu.RLock()
	u := s.cfg.user(user)
	var ref appRef
	var refOK bool
	if u != nil {
		ref, refOK = s.byHash[hexHash]
	}
	var uc User
	if u != nil {
		uc = *u
	}
	s.mu.RUnlock()

	switch {
	case u == nil:
		_ = bcrypt.CompareHashAndPassword(s.dummyBcr, []byte(pass)) // timing equalisation
		return nil
	case refOK && subtle.ConstantTimeCompare([]byte(ref.user), []byte(user)) == 1:
		a := ref.app
		if a.Expires != nil && now.After(*a.Expires) {
			return nil
		}
		p = &Principal{
			User: user, Admin: false,
			ReadOnly: uc.ReadOnly || a.ReadOnly,
			Root:     resolve(s.userRoot(&uc), a.Scope),
			AppID:    a.ID,
		}
		s.used.Store(a.ID, now)
		s.dirty.Store(true)
	case uc.PasswordHash != "" && bcrypt.CompareHashAndPassword([]byte(uc.PasswordHash), []byte(pass)) == nil:
		p = &Principal{User: user, Admin: uc.Admin, ReadOnly: uc.ReadOnly, Root: s.userRoot(&uc), AppOnly: uc.AppOnly}
	default:
		return nil
	}

	if n := countMap(&s.cache); n > 50000 {
		s.cache.Clear()
	}
	s.cache.Store(key, cacheEntry{p: p, gen: gen, expires: now.Add(5 * time.Minute).UnixNano()})
	return p
}

func countMap(m *sync.Map) (n int) {
	m.Range(func(any, any) bool { n++; return n <= 50001 })
	return
}

// --- helpers used by CLI + UI ---------------------------------------------

const tokenAlphabet = "abcdefghjkmnpqrstuvwxyz23456789" // no 0/o/1/l/i

// NewAppToken returns a 25-char (≈124 bit) token formatted xxxxx-xxxxx-xxxxx-xxxxx-xxxxx.
func NewAppToken() string {
	var sb strings.Builder
	b := make([]byte, 1)
	for i := 0; i < 25; i++ {
		if i > 0 && i%5 == 0 {
			sb.WriteByte('-')
		}
		for {
			_, _ = rand.Read(b)
			if int(b[0]) < 256-256%len(tokenAlphabet) { // unbiased
				sb.WriteByte(tokenAlphabet[int(b[0])%len(tokenAlphabet)])
				break
			}
		}
	}
	return sb.String()
}

func randomID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func hashPassword(pw string) (string, error) {
	if len(pw) < 8 {
		return "", errors.New("password must be at least 8 characters")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), 11)
	return string(h), err
}

func cleanScope(scope string) string {
	scope = strings.TrimSpace(scope)
	if scope == "" || scope == "/" {
		return ""
	}
	return path.Clean("/" + scope)
}

// CreateAppPassword creates a token for user; returns (plain token, record).
func (s *Store) CreateAppPassword(user, name string, readOnly bool, scope string, ttl time.Duration) (string, *AppPassword, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", nil, errors.New("name is required")
	}
	tok := NewAppToken()
	sum := sha256.Sum256([]byte(tok))
	a := &AppPassword{
		ID: randomID(), Name: name, Hash: hex.EncodeToString(sum[:]),
		Hint: tok[len(tok)-4:], ReadOnly: readOnly, Scope: cleanScope(scope),
		Created: time.Now().UTC().Truncate(time.Second),
	}
	if ttl > 0 {
		e := a.Created.Add(ttl)
		a.Expires = &e
	}
	err := s.Update(func(c *Config) error {
		u := c.user(user)
		if u == nil {
			return fmt.Errorf("user %q not found", user)
		}
		u.AppPasswords = append(u.AppPasswords, a)
		return nil
	})
	if err != nil {
		return "", nil, err
	}
	return tok, a, nil
}

func (s *Store) RevokeAppPassword(user, idOrName string) error {
	return s.Update(func(c *Config) error {
		u := c.user(user)
		if u == nil {
			return fmt.Errorf("user %q not found", user)
		}
		out := u.AppPasswords[:0]
		found := false
		for _, a := range u.AppPasswords {
			if a.ID == idOrName || a.Name == idOrName {
				found = true
				continue
			}
			out = append(out, a)
		}
		if !found {
			return fmt.Errorf("app password %q not found", idOrName)
		}
		u.AppPasswords = out
		return nil
	})
}

func (s *Store) SetUser(name, password string, mutate func(u *User)) error {
	if !validUsername(name) {
		return errors.New("invalid username (use letters, digits, . _ - @)")
	}
	var h string
	if password != "" {
		var err error
		if h, err = hashPassword(password); err != nil {
			return err
		}
	}
	return s.Update(func(c *Config) error {
		u := c.user(name)
		if u == nil {
			if h == "" {
				return errors.New("password required for new user")
			}
			u = &User{Username: name}
			c.Users = append(c.Users, u)
			sort.Slice(c.Users, func(i, j int) bool { return c.Users[i].Username < c.Users[j].Username })
		}
		if h != "" {
			u.PasswordHash = h
		}
		if mutate != nil {
			mutate(u)
		}
		u.Root = cleanScope(u.Root)
		return nil
	})
}

func (s *Store) DeleteUser(name string) error {
	return s.Update(func(c *Config) error {
		for i, u := range c.Users {
			if u.Username == name {
				c.Users = append(c.Users[:i], c.Users[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("user %q not found", name)
	})
}

func validUsername(n string) bool {
	if n == "" || len(n) > 64 {
		return false
	}
	for _, r := range n {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-@", r)) {
			return false
		}
	}
	return true
}

// --- brute-force protection ----------------------------------------------

type limiter struct {
	mu   sync.Mutex
	fail map[string]*failRec
	max  int
	win  time.Duration
	ban  time.Duration
}

type failRec struct {
	n       int
	first   time.Time
	blocked time.Time
}

func newLimiter(max int, win, ban time.Duration) *limiter {
	return &limiter{fail: map[string]*failRec{}, max: max, win: win, ban: ban}
}

func (l *limiter) Blocked(ip string) bool {
	if l.max <= 0 {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	r := l.fail[ip]
	return r != nil && time.Now().Before(r.blocked)
}

func (l *limiter) Fail(ip string) {
	if l.max <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	r := l.fail[ip]
	if r == nil || now.Sub(r.first) > l.win {
		r = &failRec{first: now}
		l.fail[ip] = r
	}
	r.n++
	if r.n >= l.max {
		r.blocked = now.Add(l.ban)
		logf("auth: blocking %s for %s after %d failed logins", ip, l.ban, r.n)
	}
	if len(l.fail) > 100000 {
		l.fail = map[string]*failRec{}
	}
}

func (l *limiter) Success(ip string) {
	l.mu.Lock()
	delete(l.fail, ip)
	l.mu.Unlock()
}
