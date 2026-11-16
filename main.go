package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	_ "time/tzdata"

	"golang.org/x/net/webdav"
)

var version = "1.0.0"

type Options struct {
	Listen      string
	DataDir     string
	ConfigDir   string
	Prefix      string
	TLS         string // "auto" (default) or "off"
	TLSCert     string
	TLSKey      string
	TLSHosts    []string
	HTTPListen  string // optional extra plain-HTTP listener (reverse proxy / LAN)
	HTTP2       bool
	ReadOnly    bool
	DeadProps   bool
	Quota       bool
	AccessLog   bool
	TrustProxy  bool
	CORSOrigins []string
	MaxFails    int
	Realm       string
	UI          bool
	DirListing  bool
}

func env(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		return v
	}
	return def
}

func envBool(k string, def bool) bool {
	v := strings.ToLower(env(k, ""))
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return def
}

func loadOptions() Options {
	o := Options{
		Listen:     env("LISTEN", ":8443"),
		TLS:        strings.ToLower(env("TLS", "auto")),
		HTTPListen: env("HTTP_LISTEN", ""),
		HTTP2:      envBool("HTTP2", false),
		DataDir:    env("DATA_DIR", "/data"),
		ConfigDir:  env("CONFIG_DIR", "/config"),
		Prefix:     strings.TrimRight(env("URL_PREFIX", ""), "/"),
		TLSCert:    env("TLS_CERT", ""),
		TLSKey:     env("TLS_KEY", ""),
		ReadOnly:   envBool("READ_ONLY", false),
		DeadProps:  envBool("DEAD_PROPS", true),
		Quota:      envBool("QUOTA", true),
		AccessLog:  envBool("ACCESS_LOG", false),
		TrustProxy: envBool("TRUST_PROXY", false),
		Realm:      env("REALM", "FastDAV"),
		UI:         envBool("WEB_UI", true),
		DirListing: envBool("DIR_LISTING", true),
	}
	o.MaxFails, _ = strconv.Atoi(env("MAX_LOGIN_FAILURES", "10"))
	if o.TLS != "off" && o.TLS != "false" && o.TLS != "0" && o.TLS != "no" {
		o.TLS = "auto"
	} else {
		o.TLS = "off"
	}
	for _, h := range strings.Split(env("TLS_HOSTS", ""), ",") {
		if h = strings.TrimSpace(h); h != "" {
			o.TLSHosts = append(o.TLSHosts, h)
		}
	}
	if c := env("CORS_ORIGINS", ""); c != "" {
		for _, s := range strings.Split(c, ",") {
			if s = strings.TrimSpace(s); s != "" {
				o.CORSOrigins = append(o.CORSOrigins, s)
			}
		}
	}
	if o.Prefix != "" && !strings.HasPrefix(o.Prefix, "/") {
		o.Prefix = "/" + o.Prefix
	}
	return o
}

func logf(format string, a ...any) { log.Printf(format, a...) }

func configPath(o Options) string { return filepath.Join(o.ConfigDir, "fastdav.json") }

func main() {
	log.SetFlags(log.LstdFlags)
	args := os.Args[1:]
	if len(args) == 0 || args[0] == "serve" {
		serve()
		return
	}
	os.Exit(runCLI(args))
}

// ---------------------------------------------------------------------------

type Server struct {
	opt      Options
	store    *Store
	locks    webdav.LockSystem
	handlers sync.Map // root -> *webdav.Handler
	lim      *limiter
	ui       http.Handler
	tls      *tlsManager
}

func serve() {
	o := loadOptions()
	applyUmask()
	if err := os.MkdirAll(o.ConfigDir, 0o700); err != nil {
		log.Fatalf("config dir: %v", err)
	}
	chownToPUID(o.ConfigDir)
	if fi, err := os.Stat(configPath(o)); err == nil && fi.Mode().IsRegular() {
		chownToPUID(configPath(o))
	}
	if err := dropPrivileges(); err != nil {
		log.Fatalf("drop privileges: %v", err)
	}

	st, err := NewStore(configPath(o), o.DataDir)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	bootstrapUser(st)
	if st.UserCount() == 0 {
		log.Printf("WARNING: no users configured. Set DAV_USER / DAV_PASSWORD or run: fastdav user add <name>")
	}

	s := &Server{opt: o, store: st, locks: webdav.NewMemLS(), lim: newLimiter(o.MaxFails, 5*time.Minute, 15*time.Minute)}
	s.ui = newUI(s)

	if tlsEnabled(o) {
		if s.tls, err = newTLSManager(o); err != nil {
			log.Fatalf("tls: %v", err)
		}
	}

	newSrv := func(addr string, tc *tls.Config) *http.Server {
		srv := &http.Server{
			Addr:              addr,
			Handler:           s,
			TLSConfig:         tc,
			ReadHeaderTimeout: 30 * time.Second,
			IdleTimeout:       5 * time.Minute,
			MaxHeaderBytes:    1 << 20,
			ErrorLog:          log.New(os.Stderr, "http: ", log.LstdFlags),
			// Big flow-control windows: the HTTP/2 default (1 MB) caps a
			// single upload at ~1 MB per round trip (≈ 40 Mbit/s at 200 ms RTT).
			HTTP2: &http.HTTP2Config{
				MaxConcurrentStreams:          250,
				MaxReadFrameSize:              1 << 20,
				MaxReceiveBufferPerConnection: 64 << 20,
				MaxReceiveBufferPerStream:     32 << 20,
			},
		}
		return srv
	}
	var servers []*http.Server
	var tc *tls.Config
	if s.tls != nil {
		tc = s.tls.config()
	}
	servers = append(servers, newSrv(o.Listen, tc))
	if o.HTTPListen != "" {
		servers = append(servers, newSrv(o.HTTPListen, nil))
	}

	go func() { // periodic housekeeping
		t := time.NewTicker(time.Minute)
		for range t.C {
			st.FlushUsage()
		}
	}()

	for _, srv := range servers {
		ln, err := net.Listen("tcp", srv.Addr)
		if err != nil {
			log.Fatalf("listen: %v", err)
		}
		scheme := "http"
		if srv.TLSConfig != nil {
			scheme = "https"
			if o.HTTP2 {
				http2Enable(srv)
			} else {
				// HTTP/1.1 only: for large WebDAV transfers it is 2-3x faster
				// than Go's HTTP/2 (no framing/flow-control overhead), and
				// Windows/macOS WebDAV clients use HTTP/1.1 anyway.
				srv.TLSConfig.NextProtos = []string{"http/1.1"}
				srv.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
			}
			ln = tls.NewListener(ln, srv.TLSConfig)
		}
		log.Printf("FastDAV %s listening on %s://%s (data=%s prefix=%q uid=%d)", version, scheme, srv.Addr, o.DataDir, o.Prefix, os.Getuid())
		go func() {
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("serve: %v", err)
			}
		}()
	}
	if s.tls != nil {
		hw := "no AES hardware: ChaCha20-Poly1305 preferred"
		if hasAESHardware() {
			hw = "AES hardware detected: AES-128-GCM preferred"
		}
		log.Printf("tls: %s certificate, TLS 1.2/1.3, %s", s.tls.mode, hw)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Printf("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(ctx)
	}
	st.FlushUsage()
}

// bootstrapUser creates/updates the admin user from DAV_USER / DAV_PASSWORD.
func bootstrapUser(st *Store) {
	u, p := os.Getenv("DAV_USER"), os.Getenv("DAV_PASSWORD")
	if u == "" || p == "" {
		return
	}
	cfg := st.Snapshot()
	if ex := cfg.user(u); ex != nil && st.checkHash(ex.PasswordHash, p) {
		if !ex.Admin {
			_ = st.SetUser(u, "", func(x *User) { x.Admin = true })
		}
		return
	}
	if err := st.SetUser(u, p, func(x *User) { x.Admin = true }); err != nil {
		log.Fatalf("DAV_USER: %v", err)
	}
	log.Printf("admin user %q configured from environment", u)
}

func (s *Store) checkHash(hash, pw string) bool {
	return hash != "" && bcryptOK(hash, pw)
}

// ---------------------------------------------------------------------------

func (s *Server) handlerFor(root string) *webdav.Handler {
	if h, ok := s.handlers.Load(root); ok {
		return h.(*webdav.Handler)
	}
	h := &webdav.Handler{
		Prefix:     s.opt.Prefix,
		FileSystem: newDavFS(root, s.opt.DeadProps, s.opt.Quota),
		LockSystem: scopedLS{ls: s.locks, prefix: filepath.ToSlash(root)},
		Logger: func(r *http.Request, err error) {
			if err != nil && s.opt.AccessLog {
				log.Printf("dav error: %s %s: %v", r.Method, r.URL.Path, err)
			}
		},
	}
	act, _ := s.handlers.LoadOrStore(root, h)
	return act.(*webdav.Handler)
}

func (s *Server) clientIP(r *http.Request) string {
	if s.opt.TrustProxy {
		if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
			return strings.TrimSpace(strings.Split(xf, ",")[0])
		}
		if xr := r.Header.Get("X-Real-IP"); xr != "" {
			return xr
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

const allowMethods = "OPTIONS, GET, HEAD, POST, PUT, DELETE, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK"

func (s *Server) cors(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" || len(s.opt.CORSOrigins) == 0 {
		return false
	}
	ok := false
	for _, o := range s.opt.CORSOrigins {
		if o == "*" || strings.EqualFold(o, origin) {
			ok = true
			break
		}
	}
	if !ok {
		return false
	}
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", origin)
	h.Set("Access-Control-Allow-Credentials", "true")
	h.Add("Vary", "Origin")
	h.Set("Access-Control-Expose-Headers", "DAV, Content-Length, Content-Range, ETag, Last-Modified, Location, Lock-Token")
	if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
		h.Set("Access-Control-Allow-Methods", allowMethods)
		h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Depth, Destination, If, If-Match, If-None-Match, If-Modified-Since, Lock-Token, Overwrite, Range, Timeout, X-Requested-With, X-FastDAV")
		h.Set("Access-Control-Max-Age", "86400")
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	return false
}

type statusWriter struct {
	http.ResponseWriter
	status int
	n      int64
}

func (w *statusWriter) WriteHeader(c int) { w.status = c; w.ResponseWriter.WriteHeader(c) }
func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	n, err := w.ResponseWriter.Write(b)
	w.n += int64(n)
	return n, err
}
func (w *statusWriter) ReadFrom(r io.Reader) (int64, error) {
	if w.status == 0 {
		w.status = 200
	}
	n, err := io.Copy(w.ResponseWriter, r) // keeps sendfile on the underlying writer
	w.n += n
	return n, err
}
func (w *statusWriter) Flush()                      { http.NewResponseController(w.ResponseWriter).Flush() }
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.opt.AccessLog {
		sw := &statusWriter{ResponseWriter: w}
		start := time.Now()
		defer func() {
			log.Printf("%s %s %s %d %dB %s", s.clientIP(r), r.Method, r.URL.Path, sw.status, sw.n, time.Since(start).Round(time.Microsecond))
		}()
		w = sw
	}
	h := w.Header()
	h.Set("Server", "FastDAV")
	h.Set("MS-Author-Via", "DAV") // Windows / Office

	if s.cors(w, r) {
		return
	}

	p := r.URL.Path
	if r.Method == http.MethodGet && (p == "/healthz" || p == s.opt.Prefix+"/healthz") && r.Header.Get("Authorization") == "" {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok\n"))
		return
	}
	if s.opt.UI && strings.HasPrefix(p, s.opt.Prefix+uiPath) {
		s.ui.ServeHTTP(w, r)
		return
	}
	if s.opt.Prefix != "" && p != s.opt.Prefix && !strings.HasPrefix(p, s.opt.Prefix+"/") {
		http.NotFound(w, r)
		return
	}

	// Unauthenticated OPTIONS: advertise DAV capabilities. Windows' WebClient
	// and several mobile clients probe this before sending credentials.
	if r.Method == http.MethodOptions && r.Header.Get("Authorization") == "" {
		h.Set("DAV", "1, 2")
		h.Set("Allow", allowMethods)
		h.Set("Content-Length", "0")
		w.WriteHeader(http.StatusOK)
		return
	}

	pr := s.authenticate(w, r)
	if pr == nil {
		return
	}
	if pr.AppOnly && pr.AppID == "" {
		http.Error(w, "this account requires an app password for WebDAV access", http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, "PROPFIND":
	default:
		if pr.ReadOnly || s.opt.ReadOnly {
			http.Error(w, "read-only access", http.StatusForbidden)
			return
		}
	}

	if (r.Method == "PROPFIND" || r.Method == "PROPPATCH") && r.ContentLength != 0 {
		body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		if err != nil || badNamespaces(body) {
			http.Error(w, "invalid XML namespace declaration", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
	}

	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		if s.serveFile(w, r, pr.Root) {
			return
		}
	}
	s.handlerFor(pr.Root).ServeHTTP(w, r)
}

func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) *Principal {
	ip := s.clientIP(r)
	if s.lim.Blocked(ip) {
		w.Header().Set("Retry-After", "900")
		http.Error(w, "too many failed login attempts", http.StatusTooManyRequests)
		return nil
	}
	user, pass, ok := r.BasicAuth()
	if ok {
		if p := s.store.Authenticate(user, pass); p != nil {
			if s.opt.MaxFails > 0 {
				s.lim.Success(ip)
			}
			return p
		}
		s.lim.Fail(ip)
		log.Printf("auth: failed login for %q from %s", user, ip)
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="`+s.opt.Realm+`", charset="UTF-8"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return nil
}

// serveFile is the GET/HEAD fast path: hands the *os.File straight to
// http.ServeContent so the kernel uses sendfile(2). Range, If-Range,
// If-None-Match and If-Modified-Since are handled by net/http.
func (s *Server) serveFile(w http.ResponseWriter, r *http.Request, root string) bool {
	name := strings.TrimPrefix(r.URL.Path, s.opt.Prefix)
	fp := resolve(root, name)
	if fp == "" {
		return false
	}
	f, err := os.Open(fp)
	if err != nil {
		return false // let webdav produce the right status
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	if fi.IsDir() {
		if !s.opt.DirListing {
			return false
		}
		if !strings.HasSuffix(r.URL.Path, "/") {
			http.Redirect(w, r, r.URL.Path+"/", http.StatusMovedPermanently)
			return true
		}
		dirList(w, r, f, name, s.opt.Prefix)
		return true
	}
	h := w.Header()
	h.Set("ETag", fmt.Sprintf(`"%x%x"`, fi.ModTime().UnixNano(), fi.Size()))
	h.Set("Content-Type", contentTypeFor(fi.Name()))
	h.Set("Accept-Ranges", "bytes")
	http.ServeContent(w, r, fi.Name(), fi.ModTime(), f)
	return true
}

// badNamespaces rejects prefixed namespace declarations with an empty value
// (xmlns:x=""), which "Namespaces in XML 1.0" forbids; Go's parser accepts them.
func badNamespaces(b []byte) bool {
	if !bytes.Contains(b, []byte("xmlns:")) {
		return false
	}
	d := xml.NewDecoder(bytes.NewReader(b))
	for {
		t, err := d.RawToken()
		if err != nil {
			return false
		}
		if se, ok := t.(xml.StartElement); ok {
			for _, a := range se.Attr {
				if a.Name.Space == "xmlns" && a.Value == "" {
					return true
				}
			}
		}
	}
}

// http2Enable makes srv.Serve(tlsListener) speak HTTP/2: net/http only
// auto-configures h2 in ServeTLS/ListenAndServeTLS, so declare the protocols.
func http2Enable(srv *http.Server) {
	var p http.Protocols
	p.SetHTTP1(true)
	p.SetHTTP2(true)
	srv.Protocols = &p
}
