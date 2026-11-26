## FastDAV v1.1.0

### Sign-in page instead of the browser popup
- The account page at `/.fastdav/` now has its own **sign-in page**. Browsers no longer show the Basic-auth popup.
- Optional **"Keep me signed in for 30 days"**, and a **Sign out** button.
- Opening the server address (or any folder) in a browser sends you to the sign-in page, then back to that folder.
- Sessions use an `HttpOnly`, `SameSite=Strict` cookie, marked `Secure` over HTTPS.
- Changing your password signs out your other browsers. Sign-in attempts count toward the same per-IP lockout as WebDAV logins.
- App passwords are refused on the sign-in page: they only work for WebDAV clients.
- A browser session can only **read** files (browse and download). Uploads and changes still need a WebDAV client.

### Unchanged
WebDAV clients (Windows Explorer, macOS Finder, rclone, mobile apps) still sign in with Basic auth and app passwords exactly as before.

### Install
- **Docker image:** `ghcr.io/elremeithi/fastdav:1.1.0` (amd64 + arm64)
- **Unraid:** use the attached `fastdav.xml` template, or press *Check for Updates* on the Docker tab
- **Binaries:** `fastdav_v1.1.0_linux_amd64.tar.gz` and `fastdav_v1.1.0_linux_arm64.tar.gz`
