package main

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/net/webdav"
)

// scopedLS lets many handlers (different user roots / app-password scopes)
// share one lock table keyed by absolute on-disk path, so a lock taken by
// one client is honoured by every other client touching the same file.
type scopedLS struct {
	ls     webdav.LockSystem
	prefix string // absolute root path, slash separated
}

func (s scopedLS) abs(name string) string {
	if name == "" {
		return ""
	}
	return path.Join(s.prefix, name)
}

func (s scopedLS) rel(name string) string {
	r := strings.TrimPrefix(name, s.prefix)
	if r == "" || r[0] != '/' {
		r = "/" + r
	}
	return r
}

func (s scopedLS) etag(name string) string {
	fi, err := os.Stat(filepath.FromSlash(s.abs(name)))
	if err != nil {
		return ""
	}
	return fmt.Sprintf(`"%x%x"`, fi.ModTime().UnixNano(), fi.Size())
}

// Confirm adds what memLS lacks: evaluation of ETag conditions and of
// "Not <token>" / ETag-only state lists (RFC 4918 §10.4).
func (s scopedLS) Confirm(now time.Time, n0, n1 string, conds ...webdav.Condition) (func(), error) {
	var toks []webdav.Condition
	cur := ""
	haveCur := false
	for _, c := range conds {
		if c.ETag != "" {
			if !haveCur {
				cur, haveCur = s.etag(n0), true
			}
			if (cur == c.ETag) == c.Not {
				return nil, webdav.ErrConfirmationFailed
			}
			continue
		}
		if c.Token != "" && !c.Not {
			toks = append(toks, c)
		}
	}
	if len(toks) > 0 {
		return s.ls.Confirm(now, s.abs(n0), s.abs(n1), toks...)
	}
	// Only ETag / negated conditions: the list is satisfied, but the
	// resources must still not be locked by someone else.
	var held []string
	release := func() {
		for _, t := range held {
			_ = s.ls.Unlock(now, t)
		}
	}
	for _, n := range []string{n0, n1} {
		if n == "" {
			continue
		}
		t, err := s.ls.Create(now, webdav.LockDetails{Root: s.abs(n), Duration: time.Hour, ZeroDepth: true})
		if err != nil {
			release()
			return nil, webdav.ErrConfirmationFailed
		}
		held = append(held, t)
	}
	return release, nil
}

func (s scopedLS) Create(now time.Time, d webdav.LockDetails) (string, error) {
	d.Root = s.abs(d.Root)
	return s.ls.Create(now, d)
}

func (s scopedLS) Refresh(now time.Time, token string, dur time.Duration) (webdav.LockDetails, error) {
	d, err := s.ls.Refresh(now, token, dur)
	d.Root = s.rel(d.Root)
	return d, err
}

func (s scopedLS) Unlock(now time.Time, token string) error { return s.ls.Unlock(now, token) }
