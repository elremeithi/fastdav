package main

import (
	"log"
	"os"
	"strconv"
	"syscall"

	"golang.org/x/crypto/bcrypt"
)

func bcryptOK(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

func puidPgid() (int, int, bool) {
	u, e1 := strconv.Atoi(os.Getenv("PUID"))
	g, e2 := strconv.Atoi(os.Getenv("PGID"))
	if e1 != nil || e2 != nil || u < 0 || g < 0 {
		return 0, 0, false
	}
	return u, g, true
}

// applyUmask honours UMASK (octal). Unraid convention is 000.
func applyUmask() {
	if v := os.Getenv("UMASK"); v != "" {
		if m, err := strconv.ParseUint(v, 8, 32); err == nil {
			syscall.Umask(int(m))
		}
	}
}

// chownToPUID makes files written while running as root (e.g. via
// `docker exec fastdav fastdav ...`) readable by the server process.
func chownToPUID(p string) {
	if os.Getuid() != 0 {
		return
	}
	if u, g, ok := puidPgid(); ok {
		_ = os.Chown(p, u, g)
	}
}

// dropPrivileges switches to PUID/PGID when started as root.
func dropPrivileges() error {
	if os.Getuid() != 0 {
		return nil
	}
	u, g, ok := puidPgid()
	if !ok || u == 0 {
		log.Printf("WARNING: running as root (set PUID/PGID to drop privileges)")
		return nil
	}
	if err := syscall.Setgroups([]int{g}); err != nil {
		return err
	}
	if err := syscall.Setgid(g); err != nil {
		return err
	}
	return syscall.Setuid(u)
}
