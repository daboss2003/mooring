// Command mooring is the single static binary: the admin server and the
// root-of-trust CLI (plan §2, §5.1). Subcommands that read secrets read them
// from /dev/tty, never from argv or the environment.
package main

import (
	"fmt"
	"os"
)

const usage = `mooring — lightweight, security-first self-hosted ops dashboard

Usage:
  mooring <command> [flags]

Server:
  serve            Load config, open the DB, and run the loopback admin server.

Host setup (Linux; the runtime service is unprivileged, so these are admin-run):
  doctor           Check host prerequisites (Caddy, Docker, DNS, caps; --l4 adds
                   nginx+stream) and print the exact fix for anything missing.
  setup            Print a fix plan for the above; --yes applies it (root, apt).

Definition file (mooring.yaml — same validation as the dashboard):
  validate         Parse + validate a mooring.yaml through the §5.6/§6.2 chokepoints
                   (read-only, no DB — safe in CI).
  init             Scaffold a mooring.yaml from an existing compose (--from-compose).
  secret import    Import a .env into an app's encrypted store (§7.9: classify,
                   literal-secret hard stop, by-reference; values from the file).

Disaster recovery:
  restore          Restore Mooring's database from an encrypted backup archive
                   (.mbk). Run with the service stopped; needs the same master key.

Scoped machine API tokens (§17.1 — minted ONLY here, never from the web):
  token mint       Mint a scoped, CIDR-bound, expiring bearer token (shown once).
  token list       List tokens (id, state, expiry, scopes — never the secret).
  token revoke     Revoke a token by id (rejected at auth immediately).

Root of trust (run over SSH; secrets read from /dev/tty, never argv):
  gen-key          Generate the AES-256-GCM master key (base64).
  hash-password    Produce an argon2id hash for auth.password_hash.
  gen-totp         Generate a TOTP secret (+ a scannable QR code).
  verify-key       Confirm the configured key matches the DB before it corrupts.

Other:
  version          Print version information.
  help             Show this help.

Flags:
  --config PATH    Config file (default /etc/mooring/config.yaml).
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "serve":
		err = cmdServe(args)
	case "doctor":
		err = cmdDoctor(args)
	case "setup":
		err = cmdSetup(args)
	case "validate":
		err = cmdValidate(args)
	case "init":
		err = cmdInit(args)
	case "secret":
		err = cmdSecret(args)
	case "token":
		err = cmdToken(args)
	case "restore":
		err = cmdRestore(args)
	case "restore-volume":
		err = cmdRestoreVolume(args)
	case "gen-key":
		err = cmdGenKey(args)
	case "hash-password":
		err = cmdHashPassword(args)
	case "gen-totp":
		err = cmdGenTOTP(args)
	case "verify-key":
		err = cmdVerifyKey(args)
	case "version":
		fmt.Println(versionString())
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "mooring: unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "mooring %s: %v\n", cmd, err)
		os.Exit(1)
	}
}
