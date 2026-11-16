package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"
)

func itoa(n int64) string   { return strconv.FormatInt(n, 10) }
func ftoa(f float64) string { return strconv.FormatFloat(f, 'f', 1, 64) }

const usage = `FastDAV - high-speed WebDAV server

Usage:
  fastdav [serve]                                  start the server
  fastdav user list
  fastdav user add <name> [--root DIR] [--admin] [--read-only] [--app-only]
  fastdav user passwd <name>
  fastdav user set <name> [--root DIR] [--admin=BOOL] [--read-only=BOOL] [--app-only=BOOL]
  fastdav user del <name>
  fastdav apppass list <user>
  fastdav apppass add <user> <label> [--read-only] [--scope /sub/dir] [--expires 720h]
  fastdav apppass revoke <user> <id|label>
  fastdav healthcheck
  fastdav version

Inside Docker:  docker exec -it fastdav fastdav apppass add alice phone
`

func runCLI(args []string) int {
	o := loadOptions()
	st, err := NewStore(configPath(o), o.DataDir)
	needStore := args[0] == "user" || args[0] == "apppass"
	if needStore && err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fail := func(err error) int { fmt.Fprintln(os.Stderr, "error:", err); return 1 }
	sub := ""
	if len(args) > 1 {
		sub = args[1]
	}
	rest := []string{}
	if len(args) > 2 {
		rest = args[2:]
	}

	switch args[0] {
	case "version", "--version", "-v":
		fmt.Println("fastdav", version)
	case "healthcheck":
		addr := o.Listen
		if strings.HasPrefix(addr, ":") {
			addr = "127.0.0.1" + addr
		}
		scheme := "http"
		if o.TLSCert != "" {
			scheme = "https"
		}
		c := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: insecureTLS()}}
		resp, err := c.Get(scheme + "://" + addr + o.Prefix + "/healthz")
		if err != nil || resp.StatusCode != 200 {
			fmt.Fprintln(os.Stderr, "unhealthy", err)
			return 1
		}
		fmt.Println("ok")
	case "user":
		switch sub {
		case "list":
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "USER\tROOT\tADMIN\tREAD-ONLY\tAPP-ONLY\tAPP PASSWORDS")
			for _, u := range st.Snapshot().Users {
				root := u.Root
				if root == "" {
					root = "/"
				}
				fmt.Fprintf(tw, "%s\t%s\t%v\t%v\t%v\t%d\n", u.Username, root, u.Admin, u.ReadOnly, u.AppOnly, len(u.AppPasswords))
			}
			tw.Flush()
		case "add", "set":
			name, fl := popName(rest)
			fs := flag.NewFlagSet("user", flag.ContinueOnError)
			root := fs.String("root", "", "home folder relative to DATA_DIR")
			admin := fs.Bool("admin", false, "")
			ro := fs.Bool("read-only", false, "")
			ao := fs.Bool("app-only", false, "")
			pw := fs.String("password", "", "password (prompted if omitted)")
			if err := fs.Parse(fl); err != nil || name == "" {
				fmt.Print(usage)
				return 2
			}
			set := map[string]bool{}
			fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
			p := *pw
			if sub == "add" && p == "" {
				if p, err = promptPassword(); err != nil {
					return fail(err)
				}
			}
			err := st.SetUser(name, p, func(u *User) {
				if set["root"] || sub == "add" {
					u.Root = *root
				}
				if set["admin"] || sub == "add" {
					u.Admin = *admin
				}
				if set["read-only"] || sub == "add" {
					u.ReadOnly = *ro
				}
				if set["app-only"] || sub == "add" {
					u.AppOnly = *ao
				}
			})
			if err != nil {
				return fail(err)
			}
			fmt.Println("saved user", name)
		case "passwd":
			if len(rest) < 1 {
				fmt.Print(usage)
				return 2
			}
			p, err := promptPassword()
			if err != nil {
				return fail(err)
			}
			if st.Snapshot().user(rest[0]) == nil {
				return fail(fmt.Errorf("user %q not found", rest[0]))
			}
			if err := st.SetUser(rest[0], p, nil); err != nil {
				return fail(err)
			}
			fmt.Println("password updated")
		case "del", "delete", "rm":
			if len(rest) < 1 {
				fmt.Print(usage)
				return 2
			}
			if err := st.DeleteUser(rest[0]); err != nil {
				return fail(err)
			}
			fmt.Println("deleted user", rest[0])
		default:
			fmt.Print(usage)
			return 2
		}
	case "apppass", "app":
		switch sub {
		case "list", "ls":
			if len(rest) < 1 {
				fmt.Print(usage)
				return 2
			}
			u := st.Snapshot().user(rest[0])
			if u == nil {
				return fail(fmt.Errorf("user %q not found", rest[0]))
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tLABEL\tTOKEN\tACCESS\tSCOPE\tCREATED\tLAST USED\tEXPIRES")
			for _, a := range u.AppPasswords {
				acc := "read-write"
				if a.ReadOnly {
					acc = "read-only"
				}
				sc := a.Scope
				if sc == "" {
					sc = "/"
				}
				fmt.Fprintf(tw, "%s\t%s\t…%s\t%s\t%s\t%s\t%s\t%s\n", a.ID, a.Name, a.Hint, acc, sc,
					a.Created.Local().Format("2006-01-02"), fmtTime(a.LastUsed), fmtTime(a.Expires))
			}
			tw.Flush()
		case "add", "create", "new":
			if len(rest) < 2 {
				fmt.Print(usage)
				return 2
			}
			user, label := rest[0], rest[1]
			fs := flag.NewFlagSet("apppass", flag.ContinueOnError)
			ro := fs.Bool("read-only", false, "")
			scope := fs.String("scope", "", "")
			exp := fs.Duration("expires", 0, "")
			if err := fs.Parse(rest[2:]); err != nil {
				return 2
			}
			tok, a, err := st.CreateAppPassword(user, label, *ro, *scope, *exp)
			if err != nil {
				return fail(err)
			}
			fmt.Printf("App password %q created for %s (id %s)\n\n    %s\n\nIt will not be shown again.\n", a.Name, user, a.ID, tok)
		case "revoke", "del", "rm":
			if len(rest) < 2 {
				fmt.Print(usage)
				return 2
			}
			if err := st.RevokeAppPassword(rest[0], rest[1]); err != nil {
				return fail(err)
			}
			fmt.Println("revoked")
		default:
			fmt.Print(usage)
			return 2
		}
	default:
		fmt.Print(usage)
		if args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
			return 0
		}
		return 2
	}
	return 0
}

// popName allows flags before or after the positional name.
func popName(a []string) (string, []string) {
	var name string
	var out []string
	for i := 0; i < len(a); i++ {
		if !strings.HasPrefix(a[i], "-") && name == "" {
			// value of a preceding non-bool flag?
			if i > 0 && (a[i-1] == "--root" || a[i-1] == "-root" || a[i-1] == "--password" || a[i-1] == "-password") {
				out = append(out, a[i])
				continue
			}
			name = a[i]
			continue
		}
		out = append(out, a[i])
	}
	return name, out
}

func fmtTime(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return t.Local().Format("2006-01-02 15:04")
}

func promptPassword() (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("no password on stdin (use docker exec -it)")
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	fmt.Fprint(os.Stderr, "Password: ")
	a, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	fmt.Fprint(os.Stderr, "Repeat:   ")
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if string(a) != string(b) {
		return "", fmt.Errorf("passwords do not match")
	}
	return string(a), nil
}
