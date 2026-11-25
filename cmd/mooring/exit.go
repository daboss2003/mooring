package main

import (
	"errors"
	"fmt"
	"io"
)

// exitError is a command error that carries its own exit status. Every other command error exits 1.
type exitError struct {
	code int
	err  error
	// printed: the command already wrote what the operator needs (a log line, the diagnostics), so
	// main prints nothing more.
	printed bool
}

func (e *exitError) Error() string {
	if e.err == nil {
		return fmt.Sprintf("exit status %d", e.code)
	}
	return e.err.Error()
}

func (e *exitError) Unwrap() error { return e.err }

// usageError is a wrong invocation (exit 2, like an unknown command).
func usageError(format string, a ...any) error {
	return &exitError{code: 2, err: fmt.Errorf(format, a...)}
}

// exitStatus is the process exit status for a command's error; it prints the error to w unless the
// command already did.
func exitStatus(cmd string, err error, w io.Writer) int {
	if err == nil {
		return 0
	}
	var ee *exitError
	if errors.As(err, &ee) {
		if !ee.printed && ee.err != nil {
			fmt.Fprintf(w, "mooring %s: %v\n", cmd, err)
		}
		if ee.code == 0 {
			return 1 // an error never exits 0
		}
		return ee.code
	}
	fmt.Fprintf(w, "mooring %s: %v\n", cmd, err)
	return 1
}
