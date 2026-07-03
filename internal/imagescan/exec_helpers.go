package imagescan

import (
	"bytes"
	"os"
)

// minimalEnv is the tight environment the docker CLI runs with (mirrors
// dockerexec/sandbox): only what docker needs to find the daemon + config.
func minimalEnv() []string {
	var env []string
	for _, k := range []string{"PATH", "HOME", "TMPDIR", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "XDG_RUNTIME_DIR"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// cappedWriter accumulates into buf but silently drops anything past cap bytes, so a
// hostile/huge scan output can't exhaust memory.
type cappedWriter struct {
	buf *bytes.Buffer
	cap int
}

func (w *cappedWriter) Write(p []byte) (int, error) {
	if room := w.cap - w.buf.Len(); room > 0 {
		if len(p) > room {
			w.buf.Write(p[:room])
		} else {
			w.buf.Write(p)
		}
	}
	return len(p), nil // report full consumption so the child never blocks on a full cap
}
