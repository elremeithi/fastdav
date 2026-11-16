package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/cpu"
)

// TLS design goals: encrypted by default, as fast as possible.
//
//   - TLS 1.3 preferred (1-RTT handshakes, session resumption via tickets).
//   - AES-128-GCM first when the CPU has AES instructions (AES-NI / ARMv8 AES):
//     multiple GB/s per core. ChaCha20-Poly1305 is used automatically for
//     clients without AES hardware (older phones / ARM boards), where it is
//     2-3x faster than software AES. Go negotiates this per connection.
//   - ECDSA P-256 keys: signatures are ~10x cheaper than RSA-2048, so
//     handshakes (many short WebDAV connections) stay cheap.
//   - Only AEAD ciphers; no CBC, no RSA key exchange.
//   - Large HTTP/2 flow-control windows so encrypted HTTP/2 transfers over
//     high-latency links aren't throttled by the 1 MB default.

type tlsManager struct {
	mode      string // "auto" or "files"
	certFile  string
	keyFile   string
	dir       string
	hosts     []string
	caPEM     []byte
	mu        sync.RWMutex
	cert      *tls.Certificate
	leaf      *x509.Certificate
	modTime   time.Time
	lastCheck time.Time
}

func tlsEnabled(o Options) bool { return o.TLS != "off" }

func newTLSManager(o Options) (*tlsManager, error) {
	m := &tlsManager{dir: filepath.Join(o.ConfigDir, "tls"), hosts: o.TLSHosts}
	if o.TLSCert != "" || o.TLSKey != "" {
		if o.TLSCert == "" || o.TLSKey == "" {
			return nil, errors.New("TLS_CERT and TLS_KEY must both be set")
		}
		m.mode, m.certFile, m.keyFile = "files", o.TLSCert, o.TLSKey
	} else {
		m.mode = "auto"
		m.certFile = filepath.Join(m.dir, "server.crt")
		m.keyFile = filepath.Join(m.dir, "server.key")
		if err := m.ensureAuto(); err != nil {
			return nil, err
		}
	}
	if err := m.reload(true); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *tlsManager) config() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: m.getCertificate,
		// TLS 1.2 fallback: AEAD + forward secrecy only, fastest first.
		// (TLS 1.3 suites are all AEAD and ordered by Go based on hardware.)
		CipherSuites: tls12Suites(),
		NextProtos:   []string{"h2", "http/1.1"},
	}
}

func tls12Suites() []uint16 {
	aes := []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	}
	cc := []uint16{tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256}
	if hasAESHardware() {
		return append(aes, cc...)
	}
	return append(cc, aes...)
}

func hasAESHardware() bool {
	return (cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ) || (cpu.ARM64.HasAES && cpu.ARM64.HasPMULL) || cpu.S390X.HasAES
}

// getCertificate hot-reloads the certificate when the files change, so
// renewed Let's Encrypt certs (e.g. from SWAG / NPM) are picked up without a restart.
func (m *tlsManager) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	stale := time.Since(m.lastCheck) > 30*time.Second
	c := m.cert
	m.mu.RUnlock()
	if stale {
		if m.mode == "auto" {
			if err := m.ensureAuto(); err != nil {
				log.Printf("tls: renew: %v", err)
			}
		}
		if err := m.reload(false); err != nil {
			log.Printf("tls: reload: %v", err)
		}
		m.mu.RLock()
		c = m.cert
		m.mu.RUnlock()
	}
	return c, nil
}

func (m *tlsManager) reload(force bool) error {
	m.mu.Lock()
	m.lastCheck = time.Now()
	m.mu.Unlock()
	fi, err := os.Stat(m.certFile)
	if err != nil {
		return err
	}
	m.mu.RLock()
	same := fi.ModTime().Equal(m.modTime)
	m.mu.RUnlock()
	if same && !force {
		return nil
	}
	c, err := tls.LoadX509KeyPair(m.certFile, m.keyFile)
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return err
	}
	c.Leaf = leaf
	m.mu.Lock()
	m.cert, m.leaf, m.modTime = &c, leaf, fi.ModTime()
	m.mu.Unlock()
	if !force {
		log.Printf("tls: loaded new certificate (expires %s)", leaf.NotAfter.Format("2006-01-02"))
	}
	return nil
}

// Info describes the certificate for the web UI.
func (m *tlsManager) Info() map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sum := sha256.Sum256(m.leaf.Raw)
	info := map[string]any{
		"mode":        m.mode,
		"subject":     m.leaf.Subject.CommonName,
		"issuer":      m.leaf.Issuer.CommonName,
		"names":       append(append([]string{}, m.leaf.DNSNames...), ipStrings(m.leaf.IPAddresses)...),
		"expires":     m.leaf.NotAfter,
		"fingerprint": colonHex(sum[:]),
		"aes_hw":      hasAESHardware(),
	}
	if m.mode == "auto" && len(m.caPEM) > 0 {
		if b, _ := pem.Decode(m.caPEM); b != nil {
			s := sha256.Sum256(b.Bytes)
			info["ca_fingerprint"] = colonHex(s[:])
		}
	}
	return info
}

func colonHex(b []byte) string {
	h := strings.ToUpper(hex.EncodeToString(b))
	var sb strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			sb.WriteByte(':')
		}
		sb.WriteString(h[i : i+2])
	}
	return sb.String()
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

// --- automatic local CA ----------------------------------------------------
//
// A private CA (10 years) signs a server certificate (397 days, auto-renewed).
// Install ca.crt once on your devices (download it from /.fastdav/ca.crt) and
// every future renewal or hostname change is trusted automatically.

func (m *tlsManager) ensureAuto() error {
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return err
	}
	caCrt, caKeyF := filepath.Join(m.dir, "ca.crt"), filepath.Join(m.dir, "ca.key")
	ca, caKey, err := loadPair(caCrt, caKeyF)
	if err != nil || time.Until(ca.NotAfter) < 30*24*time.Hour {
		host, _ := os.Hostname()
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber:          serial(),
			Subject:               pkix.Name{CommonName: "FastDAV Local CA (" + host + ")", Organization: []string{"FastDAV"}},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().AddDate(10, 0, 0),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			return err
		}
		if err := writePair(caCrt, caKeyF, der, key); err != nil {
			return err
		}
		ca, _ = x509.ParseCertificate(der)
		caKey = key
		_ = os.Remove(m.certFile) // force a new leaf
		log.Printf("tls: created local CA %q — install %s (or download /.fastdav/ca.crt) on your devices", tmpl.Subject.CommonName, caCrt)
	}
	m.caPEM, _ = os.ReadFile(caCrt)

	dns, ips := m.wantedNames()
	leaf, _, err := loadPair(m.certFile, m.keyFile)
	if err == nil && time.Until(leaf.NotAfter) > 30*24*time.Hour && leaf.CheckSignatureFrom(ca) == nil &&
		covers(leaf, dns, ips) {
		return nil
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: dns[0], Organization: []string{"FastDAV"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(0, 0, 397), // Apple/Chrome max validity
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dns,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return err
	}
	// Chain: leaf + CA, so clients that trust the CA can build the path.
	if err := writePair(m.certFile, m.keyFile, der, key, ca.Raw); err != nil {
		return err
	}
	log.Printf("tls: issued server certificate for %s", strings.Join(append(append([]string{}, dns...), ipStrings(ips)...), ", "))
	return nil
}

func (m *tlsManager) wantedNames() ([]string, []net.IP) {
	var dns []string
	var ips []net.IP
	add := func(h string) {
		h = strings.TrimSpace(h)
		if h == "" {
			return
		}
		if ip := net.ParseIP(h); ip != nil {
			if !slices.ContainsFunc(ips, ip.Equal) {
				ips = append(ips, ip)
			}
		} else if !slices.Contains(dns, strings.ToLower(h)) {
			dns = append(dns, strings.ToLower(h))
		}
	}
	for _, h := range m.hosts { // user-supplied first (becomes the CN)
		add(h)
	}
	if h, err := os.Hostname(); err == nil {
		add(h)
	}
	add("localhost")
	add("127.0.0.1")
	add("::1")
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && !n.IP.IsLinkLocalUnicast() {
				add(n.IP.String())
			}
		}
	}
	return dns, ips
}

func covers(c *x509.Certificate, dns []string, ips []net.IP) bool {
	for _, d := range dns {
		if !slices.Contains(c.DNSNames, d) {
			return false
		}
	}
	for _, ip := range ips {
		if !slices.ContainsFunc(c.IPAddresses, ip.Equal) {
			return false
		}
	}
	return true
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n
}

func loadPair(crtF, keyF string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	cb, err := os.ReadFile(crtF)
	if err != nil {
		return nil, nil, err
	}
	kb, err := os.ReadFile(keyF)
	if err != nil {
		return nil, nil, err
	}
	cp, _ := pem.Decode(cb)
	kp, _ := pem.Decode(kb)
	if cp == nil || kp == nil {
		return nil, nil, errors.New("bad PEM")
	}
	c, err := x509.ParseCertificate(cp.Bytes)
	if err != nil {
		return nil, nil, err
	}
	k, err := x509.ParseECPrivateKey(kp.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return c, k, nil
}

func writePair(crtF, keyF string, der []byte, key *ecdsa.PrivateKey, chain ...[]byte) error {
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	for _, c := range chain {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c})...)
	}
	if err := writeFileAtomic(keyF, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return err
	}
	return writeFileAtomic(crtF, certPEM, 0o644)
}

func writeFileAtomic(p string, b []byte, mode os.FileMode) error {
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	chownToPUID(tmp)
	return os.Rename(tmp, p)
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	}
	return fmt.Sprintf("0x%04x", v)
}
