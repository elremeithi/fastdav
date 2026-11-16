package main

import (
	"html/template"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"time"
)

var dirTmpl = template.Must(template.New("d").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Path}} – FastDAV</title>
<style>
:root{--bg:#fff;--fg:#1d1f23;--mut:#6b7280;--ln:#e5e7eb;--ac:#2563eb;--hv:#f3f4f6}
@media (prefers-color-scheme:dark){:root{--bg:#111316;--fg:#e6e7e9;--mut:#9aa0a8;--ln:#24272c;--ac:#6ea0ff;--hv:#1a1d21}}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:960px;margin:0 auto;padding:24px 16px}
h1{font-size:18px;font-weight:600;margin:0 0 16px;word-break:break-all}
table{width:100%;border-collapse:collapse}
td,th{padding:7px 8px;border-bottom:1px solid var(--ln);text-align:left;white-space:nowrap}
th{color:var(--mut);font-weight:500;font-size:12px}
td.n{white-space:normal;word-break:break-all;width:100%}
td.r,th.r{text-align:right;color:var(--mut);font-variant-numeric:tabular-nums}
tr:hover td{background:var(--hv)}
a{color:var(--ac);text-decoration:none}
@media (max-width:600px){.m{display:none}}
</style></head><body><main>
<h1>{{.Path}}</h1>
<table><thead><tr><th>Name</th><th class="r">Size</th><th class="r m">Modified</th></tr></thead><tbody>
{{if .Parent}}<tr><td class="n"><a href="../">../</a></td><td></td><td class="m"></td></tr>{{end}}
{{range .Entries}}<tr><td class="n"><a href="{{.Href}}">{{.Name}}</a></td><td class="r">{{.Size}}</td><td class="r m">{{.Mod}}</td></tr>
{{end}}</tbody></table></main></body></html>`))

type dirEntry struct{ Name, Href, Size, Mod string }

func humanSize(n int64) string {
	const u = "KMGTPE"
	if n < 1024 {
		return itoa(n) + " B"
	}
	f, i := float64(n)/1024, 0
	for f >= 1024 && i < len(u)-1 {
		f /= 1024
		i++
	}
	return strings.TrimRight(strings.TrimRight(ftoa(f), "0"), ".") + " " + u[i:i+1] + "iB"
}

func dirList(w http.ResponseWriter, r *http.Request, f *os.File, name, prefix string) {
	fis, err := f.Readdir(-1)
	if err != nil {
		http.Error(w, "cannot read directory", http.StatusInternalServerError)
		return
	}
	sort.Slice(fis, func(i, j int) bool {
		if fis[i].IsDir() != fis[j].IsDir() {
			return fis[i].IsDir()
		}
		return strings.ToLower(fis[i].Name()) < strings.ToLower(fis[j].Name())
	})
	ents := make([]dirEntry, 0, len(fis))
	for _, fi := range fis {
		n := fi.Name()
		e := dirEntry{Name: n, Href: (&url.URL{Path: n}).EscapedPath(), Mod: fi.ModTime().Local().Format(time.DateTime)}
		if strings.Contains(n, ":") {
			e.Href = "./" + e.Href
		}
		if fi.IsDir() {
			e.Name += "/"
			e.Href += "/"
			e.Size = "—"
		} else {
			e.Size = humanSize(fi.Size())
		}
		ents = append(ents, e)
	}
	p := path.Clean("/" + name)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	if r.Method == http.MethodHead {
		return
	}
	_ = dirTmpl.Execute(w, map[string]any{"Path": prefix + p, "Parent": p != "/", "Entries": ents})
}
