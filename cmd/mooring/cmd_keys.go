package main

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/crypto"
	"github.com/daboss2003/mooring/internal/store"
	"golang.org/x/term"
)

// readSecretTTY reads a secret from the controlling terminal with echo off.
// Secrets are NEVER read from argv or the environment (plan §5.1).
func readSecretTTY(prompt string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", errors.New("no controlling terminal; run this over an interactive SSH session")
	}
	defer tty.Close()
	fmt.Fprint(tty, prompt)
	b, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func cmdGenKey(args []string) error {
	fs := flag.NewFlagSet("gen-key", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	key := crypto.RandomBytes(32)
	fmt.Printf("encryption_key: %q\n", base64.StdEncoding.EncodeToString(key))
	fmt.Fprintln(os.Stderr, "Paste this into /etc/mooring/config.yaml (root:mooring, mode 0640). Back it up offsite, separately from the DB.")
	return nil
}

func cmdHashPassword(args []string) error {
	fs := flag.NewFlagSet("hash-password", flag.ContinueOnError)
	memMiB := fs.Uint("memory-mib", 8, "argon2id memory cost in MiB (raise on a larger host)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pw, err := readSecretTTY("New password: ")
	if err != nil {
		return err
	}
	if len(pw) < 12 {
		return errors.New("password must be at least 12 characters")
	}
	confirm, err := readSecretTTY("Confirm password: ")
	if err != nil {
		return err
	}
	if pw != confirm {
		return errors.New("passwords do not match")
	}
	params := crypto.DefaultArgon2Params
	params.Memory = uint32(*memMiB) * 1024
	hash, err := crypto.HashPassword([]byte(pw), params)
	if err != nil {
		return err
	}
	fmt.Printf("password_hash: %q\n", hash)
	return nil
}

func cmdGenTOTP(args []string) error {
	fs := flag.NewFlagSet("gen-totp", flag.ContinueOnError)
	account := fs.String("account", "operator", "account label for the otpauth URL")
	issuer := fs.String("issuer", "Mooring", "issuer label for the otpauth URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	sec, err := crypto.GenerateTOTPSecret()
	if err != nil {
		return err
	}
	fmt.Printf("totp_secret: %q\n", sec)
	otpauth := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		url.PathEscape(*issuer), url.PathEscape(*account), sec, url.QueryEscape(*issuer))
	// Scan-to-add: render the otpauth URL as a terminal QR so the operator just points
	// their authenticator at it instead of hand-typing a URL. The URL + secret are still
	// printed below as a fallback (manual entry, or a render failure on a dumb terminal).
	fmt.Fprintln(os.Stderr, "Scan this with your authenticator app:")
	if err := printQR(os.Stderr, otpauth); err != nil {
		fmt.Fprintf(os.Stderr, "(could not render the QR code: %v)\n", err)
	}
	fmt.Fprintf(os.Stderr, "\nOr add it manually:\n%s\n", otpauth)
	return nil
}

func cmdVerifyKey(args []string) error {
	fs := flag.NewFlagSet("verify-key", flag.ContinueOnError)
	configPath := fs.String("config", config.DefaultPath, "path to config.yaml")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	cipher, err := openCipher(cfg)
	if err != nil {
		return err
	}
	db, err := store.Open(filepath.Join(cfg.DataDir, "mooring.db"))
	if err != nil {
		return err
	}
	defer db.Close()

	res, err := verifyOrInitSentinel(cipher, db)
	if err != nil {
		return err
	}
	switch res {
	case sentinelInitialized:
		fmt.Println("verify-key: initialized key-check sentinel for this DB")
	default:
		fmt.Println("verify-key: OK — key matches the DB")
	}
	return nil
}
