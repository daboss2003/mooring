//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package main

// serviceView has no answer where a file's owner and group can't be read, and no child can be
// started as another user.
func serviceView(path string) error { return nil }
