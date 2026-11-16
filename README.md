# FastDAV

A fast, small (≈10 MB, `FROM scratch`), fully compliant WebDAV server built for Unraid Docker — with **per-device app passwords**.

- **WebDAV class 1 + 2** (RFC 4918): `OPTIONS GET HEAD PUT DELETE PROPFIND PROPPATCH MKCOL COPY MOVE LOCK UNLOCK`, `Depth`, `Overwrite`, `If` headers (lock tokens **and** ETags), `Range` / `If-Range` / `If-None-Match`
- **Persistent dead properties** (`PROPPATCH`) stored in xattrs, so they survive restarts and follow files on MOVE/COPY
- **RFC 4331 quotas** – free space shows up in Finder / Explorer
- **Windows quirks**: `MS-Author-Via`, unauthenticated `OPTIONS` probe, `Win32LastModifiedTime` PROPPATCH applied to the real mtime
- **Speed**: `sendfile(2)` for downloads, `copy_file_range` (reflink on btrfs/XFS) for server-side COPY, 1 MiB pooled upload buffers, no content sniffing during listings, bcrypt result cache so only the first request of a session pays for password hashing
- **App passwords**: one per device/app, revocable, optional **read-only**, optional **folder scope** (token only sees `/Photos`, for example), optional **expiry**, "last used" tracking; per-user **"app passwords only"** mode
- Multiple users with their own home folders, admin web UI at `/.fastdav/`, CLI for everything
- Brute-force protection (per-IP lockout), CSRF-protected API, privilege drop to `PUID`/`PGID`, `UMASK`
- Browser directory listing, optional CORS for web clients, optional built-in TLS (HTTP/2), URL prefix for reverse proxies
- Shared lock table across users/scopes: a lock taken by one client is honoured by everyone

## Compliance (litmus 0.13)

| suite | result |
|---|---|
| basic | 16/16 |
| copymove | 13/13 |
| props | 30/30 |
| locks | 33/34 – shared locks are not supported (exclusive locks, used by Windows, macOS and Office, are) |
| http | 4/4 |

## Performance (loopback, single client)

| test | result |
|---|---|
| GET 1 GiB | ~1.8 GB/s |
| PUT 1 GiB | ~520 MB/s (disk-bound) |
| PROPFIND depth 1, 5,000 files | 0.18 s |
| small GETs over keep-alive | ~5,300 req/s from one curl process |

## Install on Unraid

### Option A – publish the image with GitHub (recommended)
1. Push this folder to a GitHub repo. The included workflow (`.github/workflows/docker.yml`) builds `ghcr.io/<you>/fastdav:latest` for amd64 + arm64.
2. Make the package public (GitHub → Packages → fastdav → settings).
3. Copy `unraid/fastdav.xml` to `/boot/config/plugins/dockerMan/templates-user/my-FastDAV.xml` on the Unraid flash drive, replace `YOUR_GITHUB_USER`.
4. Docker tab → **Add Container** → pick *FastDAV* from the template list → set the admin password → **Apply**.

### Option B – build directly on Unraid
```bash
cd /mnt/user/appdata && git clone https://github.com/<you>/fastdav.git fastdav-src
```
```bash
docker build -t fastdav:latest /mnt/user/appdata/fastdav-src
```
Then use the template with `Repository` set to `fastdav:latest` (or `docker compose up -d` with the included `docker-compose.yml`).

Open `http://<unraid-ip>:8080/.fastdav/` and sign in with the admin account to create app passwords and users.

## Configuration (environment variables)

| variable | default | meaning |
|---|---|---|
| `DAV_USER` / `DAV_PASSWORD` | – | admin account, (re)applied on every start |
| `DATA_DIR` | `/data` | folder that is shared |
| `CONFIG_DIR` | `/config` | holds `fastdav.json` (users, bcrypt hashes, SHA-256 hashes of app passwords) |
| `LISTEN` | `:8080` | listen address |
| `PUID` / `PGID` / `UMASK` | `99` / `100` / `000` | Unraid defaults (nobody:users) |
| `READ_ONLY` | `false` | whole server read-only |
| `URL_PREFIX` | – | e.g. `/dav` |
| `TLS_CERT` / `TLS_KEY` | – | serve HTTPS (+HTTP/2) directly |
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

- **Windows Explorer** only sends Basic auth over HTTPS by default. Either use HTTPS (TLS vars or a reverse proxy), or set `HKLM\SYSTEM\CurrentControlSet\Services\WebClient\Parameters\BasicAuthLevel` = `2` and restart the *WebClient* service. Raise `FileSizeLimitInBytes` there (max `0xFFFFFFFF`) for files over 50 MB.
- **macOS Finder**: ⌘K → `http://<ip>:8080/`. Locks are supported, so Finder mounts read-write.
- **rclone**: `rclone config` → type `webdav`, vendor `other`.
- **Reverse proxy** (SWAG / NPM / Caddy): pass `Destination`, `Overwrite`, `Depth`, `If`, `Lock-Token` headers through unchanged, disable request buffering and body-size limits, and set `TRUST_PROXY=true`. If the proxy terminates TLS, the `Destination` header carries `https://…`; FastDAV only checks the path so this works.

## Security model

- Main passwords are bcrypt (cost 11). App passwords are 25 random characters (~124 bits) and stored as SHA-256 only — shown once at creation.
- App passwords cannot sign in to the account page, so a leaked device token can't create more tokens or change the password.
- Turn on **App passwords only** for a user to stop the main password from working for WebDAV at all.

## Limitations

- Shared locks (`<D:shared/>`) return 501; exclusive write locks are fully supported.
- Locks are held in memory and are dropped on restart (clients simply re-lock).
- Dead properties need a filesystem with user xattrs (XFS, btrfs, ext4, ZFS and Unraid's `/mnt/user` support them). Without xattrs, PROPPATCH still succeeds but the properties are not kept.
