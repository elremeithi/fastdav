## FastDAV v1.0.0

First release of FastDAV, a high-speed WebDAV server for Unraid Docker with per-device app passwords.

### Highlights
- WebDAV class 1 + 2 (RFC 4918) with persistent custom properties and RFC 4331 quotas. Litmus: basic, copymove, props and http 100%; locks 33/34 (shared locks not supported, exclusive locks are).
- **App passwords:** per device, revocable, optional read-only, folder scope and expiry, last-used tracking, and an "app passwords only" mode per user.
- **Encrypted by default:** TLS 1.3, hardware AES-128-GCM or ChaCha20-Poly1305, ECDSA certificates, an auto-generated local CA with automatic renewal, and hot-reload for your own certificates.
- **Fast:** ~1.2 GB/s encrypted and ~1.9 GB/s plain downloads in testing, kernel copies for server-side COPY, batched upload writes.
- Web UI at `/.fastdav/` for app passwords, users and certificate download, plus a full CLI.
- Unraid-ready: PUID/PGID/UMASK, a ~10 MB `scratch` image, a health check and an Unraid template.

### Install
- **Docker image:** `ghcr.io/<owner>/fastdav:1.0.0` (amd64 + arm64)
- **Unraid:** use the attached `fastdav.xml` template
- **Binaries:** `fastdav_v1.0.0_linux_amd64.tar.gz` and `fastdav_v1.0.0_linux_arm64.tar.gz` (static, no dependencies)
