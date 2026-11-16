package main

import (
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"
)

const uiPath = "/.fastdav/"

//go:embed ui.html
var uiHTML []byte

func insecureTLS() *tls.Config { return &tls.Config{InsecureSkipVerify: true} } // healthcheck on localhost only

type uiServer struct{ s *Server }

func newUI(s *Server) http.Handler { return &uiServer{s: s} }

type apiApp struct {
	ID       string     `json:"id"`
	Name     string     `json:"name"`
	Hint     string     `json:"hint"`
	ReadOnly bool       `json:"read_only"`
	Scope    string     `json:"scope"`
	Created  time.Time  `json:"created"`
	LastUsed *time.Time `json:"last_used"`
	Expires  *time.Time `json:"expires"`
}

type apiUser struct {
	Username     string   `json:"username"`
	Root         string   `json:"root"`
	Admin        bool     `json:"admin"`
	ReadOnly     bool     `json:"read_only"`
	AppOnly      bool     `json:"app_passwords_only"`
	EnvManaged   bool     `json:"env_managed"`
	AppPasswords []apiApp `json:"app_passwords"`
}

func toAPIUser(u *User) apiUser {
	out := apiUser{Username: u.Username, Root: u.Root, Admin: u.Admin, ReadOnly: u.ReadOnly, AppOnly: u.AppOnly,
		EnvManaged: u.Username == os.Getenv("DAV_USER") && os.Getenv("DAV_PASSWORD") != "", AppPasswords: []apiApp{}}
	if out.Root == "" {
		out.Root = "/"
	}
	for _, a := range u.AppPasswords {
		sc := a.Scope
		if sc == "" {
			sc = "/"
		}
		out.AppPasswords = append(out.AppPasswords, apiApp{a.ID, a.Name, a.Hint, a.ReadOnly, sc, a.Created, a.LastUsed, a.Expires})
	}
	return out
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func jerr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func (u *uiServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s := u.s
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")

	// The CA certificate is public; serve it without login so devices can
	// install it before they have credentials configured.
	if strings.TrimPrefix(r.URL.Path, s.opt.Prefix+uiPath) == "ca.crt" {
		if s.tls == nil || len(s.tls.caPEM) == 0 {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Header().Set("Content-Disposition", `attachment; filename="fastdav-ca.crt"`)
		_, _ = w.Write(s.tls.caPEM)
		return
	}

	pr := s.authenticate(w, r)
	if pr == nil {
		return
	}
	if pr.AppID != "" {
		http.Error(w, "app passwords cannot be used for account management; sign in with your main password", http.StatusForbidden)
		return
	}
	rel := strings.TrimPrefix(r.URL.Path, s.opt.Prefix+uiPath)

	if rel == "" || rel == "index.html" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:")
		_, _ = w.Write(uiHTML)
		return
	}
	if !strings.HasPrefix(rel, "api/") {
		http.NotFound(w, r)
		return
	}
	// CSRF guard: browsers can't attach custom headers cross-origin without a CORS preflight.
	if r.Method != http.MethodGet && r.Header.Get("X-FastDAV") != "1" {
		jerr(w, http.StatusForbidden, errors.New("missing X-FastDAV header"))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	api := strings.TrimPrefix(rel, "api/")
	st := s.store

	switch {
	case api == "me" && r.Method == http.MethodGet:
		cu := st.Snapshot().user(pr.User)
		if cu == nil {
			jerr(w, 404, errors.New("user not found"))
			return
		}
		out := map[string]any{"user": toAPIUser(cu), "tls": nil, "conn": connInfo(r)}
		if s.tls != nil {
			out["tls"] = s.tls.Info()
		}
		writeJSON(w, 200, out)

	case api == "apppasswords" && r.Method == http.MethodPost:
		var in struct {
			Name        string `json:"name"`
			ReadOnly    bool   `json:"read_only"`
			Scope       string `json:"scope"`
			ExpiresDays int    `json:"expires_days"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			jerr(w, 400, errors.New("bad request"))
			return
		}
		tok, a, err := st.CreateAppPassword(pr.User, in.Name, in.ReadOnly, in.Scope, time.Duration(in.ExpiresDays)*24*time.Hour)
		if err != nil {
			jerr(w, 400, err)
			return
		}
		writeJSON(w, 201, map[string]any{"token": tok, "id": a.ID, "name": a.Name})

	case strings.HasPrefix(api, "apppasswords/") && r.Method == http.MethodDelete:
		id := strings.TrimPrefix(api, "apppasswords/")
		user := pr.User
		if q := r.URL.Query().Get("user"); q != "" && pr.Admin {
			user = q
		}
		if err := st.RevokeAppPassword(user, id); err != nil {
			jerr(w, 404, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})

	case api == "password" && r.Method == http.MethodPost:
		var in struct{ Current, New string }
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			jerr(w, 400, errors.New("bad request"))
			return
		}
		cu := st.Snapshot().user(pr.User)
		if cu == nil || !bcryptOK(cu.PasswordHash, in.Current) {
			jerr(w, 403, errors.New("current password is incorrect"))
			return
		}
		if toAPIUser(cu).EnvManaged {
			jerr(w, 400, errors.New("this account's password is set by DAV_PASSWORD in the container settings"))
			return
		}
		if err := st.SetUser(pr.User, in.New, nil); err != nil {
			jerr(w, 400, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})

	// ---- admin ----
	case strings.HasPrefix(api, "users") && !pr.Admin:
		jerr(w, 403, errors.New("admin only"))

	case api == "users" && r.Method == http.MethodGet:
		out := []apiUser{}
		for _, x := range st.Snapshot().Users {
			out = append(out, toAPIUser(x))
		}
		writeJSON(w, 200, out)

	case api == "users" && r.Method == http.MethodPost:
		var in struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Root     string `json:"root"`
			Admin    bool   `json:"admin"`
			ReadOnly bool   `json:"read_only"`
			AppOnly  bool   `json:"app_passwords_only"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			jerr(w, 400, errors.New("bad request"))
			return
		}
		if in.Username == pr.User && !in.Admin {
			jerr(w, 400, errors.New("you cannot remove your own admin rights"))
			return
		}
		err := st.SetUser(in.Username, in.Password, func(x *User) {
			x.Root, x.Admin, x.ReadOnly, x.AppOnly = in.Root, in.Admin, in.ReadOnly, in.AppOnly
		})
		if err != nil {
			jerr(w, 400, err)
			return
		}
		if in.Root != "" {
			if p := resolve(s.opt.DataDir, in.Root); p != "" {
				_ = os.MkdirAll(p, 0o777)
			}
		}
		writeJSON(w, 200, map[string]bool{"ok": true})

	case strings.HasPrefix(api, "users/") && r.Method == http.MethodDelete:
		name := strings.TrimPrefix(api, "users/")
		if name == pr.User {
			jerr(w, 400, errors.New("you cannot delete yourself"))
			return
		}
		if err := st.DeleteUser(name); err != nil {
			jerr(w, 404, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})

	default:
		jerr(w, 404, errors.New("not found"))
	}
}

func connInfo(r *http.Request) map[string]any {
	if r.TLS == nil {
		return map[string]any{"encrypted": false, "proto": r.Proto}
	}
	return map[string]any{
		"encrypted": true,
		"proto":     r.Proto,
		"version":   tlsVersionName(r.TLS.Version),
		"cipher":    tls.CipherSuiteName(r.TLS.CipherSuite),
		"resumed":   r.TLS.DidResume,
	}
}
