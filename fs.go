package main

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/webdav"
)

// davFS wraps webdav.Dir and adds:
//   - extension-based content types (no 512-byte sniff per file in PROPFIND)
//   - persistent dead properties stored in a user xattr (PROPPATCH works)
//   - Windows Win32 timestamp PROPPATCH applied to the real file mtime
//   - RFC 4331 quota properties on collections
//   - kernel-side copies (copy_file_range / reflink) for COPY
//   - large pooled buffers for PUT
type davFS struct {
	root      string
	dir       webdav.Dir
	deadProps bool
	quota     bool
}

func newDavFS(root string, deadProps, quota bool) *davFS {
	return &davFS{root: root, dir: webdav.Dir(root), deadProps: deadProps, quota: quota}
}

func (d *davFS) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	return d.dir.Mkdir(ctx, name, perm)
}
func (d *davFS) RemoveAll(ctx context.Context, name string) error {
	return d.dir.RemoveAll(ctx, name)
}
func (d *davFS) Rename(ctx context.Context, o, n string) error { return d.dir.Rename(ctx, o, n) }

func (d *davFS) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	fi, err := d.dir.Stat(ctx, name)
	if err != nil {
		return nil, err
	}
	return fileInfo{fi}, nil
}

func (d *davFS) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	f, err := d.dir.OpenFile(ctx, name, flag, perm)
	if err != nil && flag&(os.O_RDWR|os.O_WRONLY) != 0 && errors.Is(err, syscall.EISDIR) {
		// PROPPATCH opens O_RDWR; directories can't be opened for writing.
		f, err = d.dir.OpenFile(ctx, name, os.O_RDONLY, 0)
	}
	if err != nil {
		return nil, err
	}
	return &davFile{File: f.(*os.File), fs: d}, nil
}

// ---------------------------------------------------------------------------

type fileInfo struct{ os.FileInfo }

// ContentType avoids opening + sniffing every file during PROPFIND.
func (fi fileInfo) ContentType(context.Context) (string, error) {
	return contentTypeFor(fi.Name()), nil
}

func contentTypeFor(name string) string {
	if t := mime.TypeByExtension(filepath.Ext(name)); t != "" {
		return t
	}
	return "application/octet-stream"
}

// ---------------------------------------------------------------------------

type davFile struct {
	*os.File
	fs *davFS
}

func (f *davFile) Stat() (os.FileInfo, error) {
	fi, err := f.File.Stat()
	if err != nil {
		return nil, err
	}
	return fileInfo{fi}, nil
}

func (f *davFile) Readdir(n int) ([]os.FileInfo, error) {
	fis, err := f.File.Readdir(n)
	for i := range fis {
		fis[i] = fileInfo{fis[i]}
	}
	return fis, err
}

var bufPool = sync.Pool{New: func() any { b := make([]byte, 1<<20); return &b }}

// ReadFrom is used by PUT (io.Copy(file, body)) and COPY.
func (f *davFile) ReadFrom(r io.Reader) (int64, error) {
	if src, ok := r.(*davFile); ok {
		return f.File.ReadFrom(src.File) // copy_file_range: reflink on btrfs/xfs
	}
	if src, ok := r.(*os.File); ok {
		return f.File.ReadFrom(src)
	}
	// Fill the whole 1 MiB buffer before each write: TLS (and HTTP/2) bodies
	// arrive in ≤16 KiB pieces, and one large write is far cheaper than 64 small ones.
	bp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bp)
	buf := *bp
	var total int64
	for {
		n, rerr := io.ReadFull(r, buf)
		if n > 0 {
			w, werr := f.File.Write(buf[:n])
			total += int64(w)
			if werr != nil {
				return total, werr
			}
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			return total, nil
		}
		if rerr != nil {
			return total, rerr
		}
	}
}

func (f *davFile) WriteTo(w io.Writer) (int64, error) {
	if dst, ok := w.(*davFile); ok {
		return dst.File.ReadFrom(f.File)
	}
	return f.File.WriteTo(w)
}

// --- dead properties -------------------------------------------------------

const xattrName = "user.fastdav.props"

type storedProp struct {
	Space string `json:"s"`
	Local string `json:"l"`
	Lang  string `json:"g,omitempty"`
	Inner []byte `json:"v,omitempty"`
}

func (f *davFile) loadProps() map[xml.Name]webdav.Property {
	m := map[xml.Name]webdav.Property{}
	if !f.fs.deadProps {
		return m
	}
	buf := make([]byte, 4096)
	n, err := syscall.Getxattr(f.Name(), xattrName, buf)
	if errors.Is(err, syscall.ERANGE) {
		if sz, e := syscall.Getxattr(f.Name(), xattrName, nil); e == nil {
			buf = make([]byte, sz)
			n, err = syscall.Getxattr(f.Name(), xattrName, buf)
		}
	}
	if err != nil || n <= 0 {
		return m
	}
	var list []storedProp
	if json.Unmarshal(buf[:n], &list) != nil {
		return m
	}
	for _, p := range list {
		name := xml.Name{Space: p.Space, Local: p.Local}
		m[name] = webdav.Property{XMLName: name, Lang: p.Lang, InnerXML: p.Inner}
	}
	return m
}

func (f *davFile) saveProps(m map[xml.Name]webdav.Property) {
	if !f.fs.deadProps {
		return
	}
	if len(m) == 0 {
		_ = syscall.Removexattr(f.Name(), xattrName)
		return
	}
	list := make([]storedProp, 0, len(m))
	for k, p := range m {
		list = append(list, storedProp{Space: k.Space, Local: k.Local, Lang: p.Lang, Inner: p.InnerXML})
	}
	b, _ := json.Marshal(list)
	_ = syscall.Setxattr(f.Name(), xattrName, b, 0) // best effort (fs may lack xattrs)
}

func (f *davFile) DeadProps() (map[xml.Name]webdav.Property, error) {
	m := f.loadProps()
	if f.fs.quota {
		if fi, err := f.File.Stat(); err == nil && fi.IsDir() {
			var st syscall.Statfs_t
			if syscall.Statfs(f.Name(), &st) == nil {
				avail := st.Bavail * uint64(st.Bsize)
				used := (st.Blocks - st.Bfree) * uint64(st.Bsize)
				qa := xml.Name{Space: "DAV:", Local: "quota-available-bytes"}
				qu := xml.Name{Space: "DAV:", Local: "quota-used-bytes"}
				m[qa] = webdav.Property{XMLName: qa, InnerXML: []byte(strconv.FormatUint(avail, 10))}
				m[qu] = webdav.Property{XMLName: qu, InnerXML: []byte(strconv.FormatUint(used, 10))}
			}
		}
	}
	return m, nil
}

const msNS = "urn:schemas-microsoft-com:"

func (f *davFile) Patch(patches []webdav.Proppatch) ([]webdav.Propstat, error) {
	m := f.loadProps()
	ok := webdav.Propstat{Status: http.StatusOK}
	var mtime, atime time.Time
	for _, p := range patches {
		for _, prop := range p.Props {
			ok.Props = append(ok.Props, webdav.Property{XMLName: prop.XMLName})
			if prop.XMLName.Space == "DAV:" && strings.HasPrefix(prop.XMLName.Local, "quota-") {
				continue
			}
			if p.Remove {
				delete(m, prop.XMLName)
				continue
			}
			// Windows Explorer sets timestamps via PROPPATCH after upload.
			if prop.XMLName.Space == msNS {
				v := strings.TrimSpace(string(prop.InnerXML))
				switch prop.XMLName.Local {
				case "Win32LastModifiedTime":
					mtime, _ = http.ParseTime(v)
					continue
				case "Win32LastAccessTime":
					atime, _ = http.ParseTime(v)
					continue
				case "Win32CreationTime", "Win32FileAttributes":
					continue // not representable on Linux; accept silently
				}
			}
			m[prop.XMLName] = prop
		}
	}
	if !mtime.IsZero() || !atime.IsZero() {
		if mtime.IsZero() {
			mtime = atime
		}
		if atime.IsZero() {
			atime = mtime
		}
		_ = os.Chtimes(f.Name(), atime, mtime)
	}
	f.saveProps(m)
	return []webdav.Propstat{ok}, nil
}

// resolve maps a URL path to an on-disk path inside root (same rules as webdav.Dir).
func resolve(root, name string) string {
	if filepath.Separator != '/' && strings.ContainsRune(name, filepath.Separator) || strings.Contains(name, "\x00") {
		return ""
	}
	return filepath.Join(root, filepath.FromSlash(path.Clean("/"+name)))
}
