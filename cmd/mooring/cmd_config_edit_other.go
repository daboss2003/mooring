//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package main

// cmdConfigEdit needs flock, O_NOFOLLOW and file ownership; elsewhere the file is edited by hand.
func cmdConfigEdit(args []string) error {
	return usageError("config edit is not available on this system; edit the file, then run: mooring config check")
}
