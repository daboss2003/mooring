//go:build race

package config

// raceDetector: the tests run under -race (about 15 times slower per parsed file).
const raceDetector = true
