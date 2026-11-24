//go:build race

package redact

// raceDetector is true in a -race build, where timings say nothing about the code.
const raceDetector = true
