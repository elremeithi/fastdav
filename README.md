# FastDAV

A fast, small (≈10 MB, `FROM scratch`), fully compliant WebDAV server built for Unraid Docker — with **per-device app passwords**.

- **WebDAV class 1 + 2** (RFC 4918): `OPTIONS GET HEAD PUT DELETE PROPFIND PROPPATCH MKCOL COPY MOVE LOCK UNLOCK`, `Depth`, `Overwrite`, `If` headers (lock tokens **and** ETags), `Range` / `If-Range` / `If-None-Match`
- **Persistent dead properties** (`PROPPATCH`) stored in xattrs, so they survive restarts and follow files on MOVE/COPY
- **RFC 4331 quotas** – free space shows up in Finder / Explorer
- **Windows quirks**: `MS-Author-Via`, unauthenticated `OPTIONS` probe, `Win32LastModifiedTime` PROPPATCH applied to the real mtime
- **Speed**: `sendfile(2)` for downloads, `copy_file_range` (reflink on btrfs/XFS) for server-side COPY, 1 MiB pooled upload buffers, no content sniffing during listings, bcrypt result cache so only the first request of a session pays for password hashing
- **App passwords**: one per device/app, revocable, optional **read-only**, optional **folder scope** (token only sees `/Photos`, for example), optional **expiry**, "last used" tracking; per-user **"app passwords only"** mode
- Multiple users with their own home folders, admin web UI at `/.fastdav/` with a proper **sign-in page** (no browser popup, optional "keep me signed in"), CLI for everything
- Brute-force protection (per-IP lockout), CSRF-protected API, privilege drop to `PUID`/`PGID`, `UMASK`
- **Encrypted by default** — see [Encryption](#encryption-fast-https)
- Browser directory listing, optional CORS for web clients, URL prefix for reverse proxies
- Shared lock table across users/scopes: a lock taken by one client is honoured by everyone

## Compliance (litmus 0.13)

| suite | result |
|---|---|
| basic | 16/16 |
| copymove | 13/13 |
| props | 30/30 |
| locks | 33/34 – shared locks are not supported (exclusive locks, used by Windows, macOS and Office, are) |
| http | 4/4 |

## Encryption (fast HTTPS)

HTTPS is on by default (`TLS=auto`) and tuned for throughput:

| choice | why it's fast |
|---|---|
| **TLS 1.3** (1.2 minimum) | 1-round-trip handshakes and session-ticket resumption |
| **AES-128-GCM** when the CPU has AES instructions (every x86 Unraid box with AES-NI, ARMv8) | hardware-accelerated, several GB/s per core |
| **ChaCha20-Poly1305** for clients without AES hardware | 2–3× faster than software AES on those devices; chosen per connection automatically |
| **ECDSA P-256** certificates | handshakes ~10× cheaper than RSA-2048 (100 new connections ≈ 0.9 s incl. curl startup) |
| AEAD ciphers only, forward secrecy only | no slow or weak CBC/RSA-kex suites |
| **HTTP/1.1** by default | Go's HTTP/2 is 2–3× slower for big transfers; `HTTP2=true` turns it on (with 64 MB flow-control windows) |
| 1 MiB write batching for uploads | encrypted bodies arrive in 16 KiB records; they're coalesced into 1 MiB disk writes |

**Certificates**
- *Automatic (default):* on first start FastDAV creates a private **local CA** (10 years) and a server certificate signed by it (397 days, renewed automatically, re-issued if `TLS_HOSTS` changes). Install the CA **once** per device — download it from the account page or `https://<ip>:8443/.fastdav/ca.crt` (no login needed) — and every renewal is trusted. Files live in `/config/tls/`.
  - Windows: double-click → Install → Local Machine → *Trusted Root Certification Authorities*.
  - macOS: open in Keychain Access → *System* → set *Always Trust*.
  - iOS: install profile, then Settings → General → About → Certificate Trust Settings → enable.
  - Android: Settings → Security → Install certificate → CA certificate.
- *Your own certificate:* set `TLS_CERT` / `TLS_KEY` (e.g. Let's Encrypt `fullchain.pem` / `privkey.pem` from SWAG mounted into the container). Files are re-read automatically after renewal.
- Set `TLS_HOSTS` to every name/IP you connect with (e.g. `tower.local,192.168.1.10,dav.example.com`); the container can't see your Unraid LAN IP by itself in bridge mode.

## Performance (loopback, single client, 4 vCPU)

| test | plain HTTP | HTTPS (TLS 1.3, AES-128-GCM) |
|---|---|---|
| GET 2 GiB | ~1.9 GB/s (sendfile) | **~1.2 GB/s** (≈ 10 Gbit/s) |
| PUT 2 GiB | 0.5–1.5 GB/s (disk-bound) | 0.5–0.7 GB/s (disk-bound) |

Earlier plain-HTTP measurements:

| test | result |
|---|---|
| PROPFIND depth 1, 5,000 files | 0.18 s |
| small GETs over keep-alive | ~5,300 req/s from one curl process |

## Install on Unraid

### Option A – publish the image with GitHub (recommended)
1. Push this folder to a GitHub repo. The included workflow (`.github/workflows/docker.yml`) builds `ghcr.io/elremeithi/fastdav:latest` for amd64 + arm64.
2. Make the package public (GitHub → Packages → fastdav → settings).
3. Copy `unraid/fastdav.xml` to `/boot/config/plugins/dockerMan/templates-user/my-FastDAV.xml` on the Unraid flash drive.
4. Docker tab → **Add Container** → pick *FastDAV* from the template list → set the admin password → **Apply**.

### Option B – build directly on Unraid
```bash
cd /mnt/user/appdata && git clone https://github.com/elremeithi/fastdav.git fastdav-src
```
```bash
docker build -t fastdav:latest /mnt/user/appdata/fastdav-src
```
Then use the template with `Repository` set to `fastdav:latest` (or `docker compose up -d` with the included `docker-compose.yml`).

Open `https://<unraid-ip>:8443/.fastdav/` (accept the warning once, then download and install the CA certificate from that page) and sign in with the admin account to create app passwords and users.

## Configuration (environment variables)

| variable | default | meaning |
|---|---|---|
| `DAV_USER` / `DAV_PASSWORD` | – | admin account, (re)applied on every start |
| `DATA_DIR` | `/data` | folder that is shared |
| `CONFIG_DIR` | `/config` | holds `fastdav.json` (users, bcrypt hashes, SHA-256 hashes of app passwords) |
| `LISTEN` | `:8443` | listen address (HTTPS unless `TLS=off`) |
| `TLS` | `auto` | `auto` = HTTPS with your cert or an auto-generated one; `off` = plain HTTP |
| `TLS_HOSTS` | – | names/IPs to put in the auto certificate |
| `TLS_CERT` / `TLS_KEY` | – | your own PEM cert (full chain) + key, hot-reloaded |
| `HTTP2` | `false` | offer HTTP/2 over TLS |
| `HTTP_LISTEN` | – | extra **unencrypted** listener, e.g. `:8080`, for a reverse proxy that terminates TLS |
| `PUID` / `PGID` / `UMASK` | `99` / `100` / `000` | Unraid defaults (nobody:users) |
| `READ_ONLY` | `false` | whole server read-only |
| `URL_PREFIX` | – | e.g. `/dav` |
| `TRUST_PROXY` | `false` | take client IP from `X-Forwarded-For` |
| `MAX_LOGIN_FAILURES` | `10` | per IP in 5 min before a 15 min block; `0` = off |
| `CORS_ORIGINS` | – | comma list or `*` for browser-based clients |
| `DEAD_PROPS` | `true` | store PROPPATCH properties in xattrs |
| `QUOTA` | `true` | report free/used bytes |
| `DIR_LISTING` | `true` | HTML listing on browser GET of a folder |
| `WEB_UI` | `true` | account page at `/.fastdav/` |
| `ACCESS_LOG` | `false` | log every request |

## CLI

```bash
docker exec -it FastDAV fastdav apppass add admin "iPhone"
```
```bash
docker exec -it FastDAV fastdav apppass add admin "Backup job" --scope /Backups --expires 2160h
```
```bash
docker exec -it FastDAV fastdav apppass add admin "Photo frame" --read-only --scope /Photos
```
```bash
docker exec -it FastDAV fastdav apppass list admin
```
```bash
docker exec -it FastDAV fastdav apppass revoke admin "iPhone"
```
```bash
docker exec -it FastDAV fastdav user add alice --root /alice --app-only
```
```bash
docker exec -it FastDAV fastdav user list
```

Changes made by the CLI are picked up by the running server within a second; revoked tokens stop working immediately.

## Client notes

- **Windows Explorer**: install the CA certificate, then *Map network drive* → `https://tower.local:8443/`. Raise `HKLM\SYSTEM\CurrentControlSet\Services\WebClient\Parameters\FileSizeLimitInBytes` (max `0xFFFFFFFF`) for files over 50 MB.
- **macOS Finder**: ⌘K → `https://<ip>:8443/`. Locks are supported, so Finder mounts read-write.
- **rclone**: `rclone config` → type `webdav`, vendor `other`.
- **Reverse proxy** (SWAG / NPM / Caddy): pass `Destination`, `Overwrite`, `Depth`, `If`, `Lock-Token` headers through unchanged, disable request buffering and body-size limits, and set `TRUST_PROXY=true`. Either proxy to `https://fastdav:8443` or set `HTTP_LISTEN=:8080` and proxy to plain HTTP inside your LAN. If the proxy terminates TLS, the `Destination` header carries `https://…`; FastDAV only checks the path so this works.

## Security model

- All traffic, including passwords, is encrypted with TLS by default.
- Main passwords are bcrypt (cost 11). App passwords are 25 random characters (~124 bits) and stored as SHA-256 only — shown once at creation.
- The account page uses its own sign-in page and an `HttpOnly`, `SameSite=Strict` session cookie (`Secure` over HTTPS). Changing a password signs out the user's other browsers. A browser session can only read files; changes need a WebDAV client.
- App passwords cannot sign in to the account page, so a leaked device token can't create more tokens or change the password.
- Turn on **App passwords only** for a user to stop the main password from working for WebDAV at all.

## Limitations

- Shared locks (`<D:shared/>`) return 501; exclusive write locks are fully supported.
- Locks are held in memory and are dropped on restart (clients simply re-lock).
- Dead properties need a filesystem with user xattrs (XFS, btrfs, ext4, ZFS and Unraid's `/mnt/user` support them). Without xattrs, PROPPATCH still succeeds but the properties are not kept.

## Releasing

Bump `VERSION`, update `RELEASE_NOTES.md`, push to `main`. The `release` workflow creates the `vX.Y.Z` tag, the GitHub Release (binaries for amd64/arm64, Unraid template, checksums) and pushes `ghcr.io/elremeithi/fastdav:X.Y.Z` + `latest`.
