package logger

import "testing"

func TestLoggers(t *testing.T) {
	Debug("debug messages ...")
	Info("info messages ...")
	Warn("warn messages ...")
	Error("error messages ...")
	// Fatal("Fatal messages ...")
}
