package main

import (
	"io"
	"os"
)

// Only a compact report sent directly to a capable terminal is styled. Neither
// a destination file, pipe, machine format nor an arbitrary Writer gains ANSI.
func scanTerminalFormat(format, output string, out io.Writer) string {
	if format != "terminal" || output != "-" {
		return format
	}
	if _, disabled := os.LookupEnv("NO_COLOR"); disabled || os.Getenv("TERM") == "dumb" {
		return format
	}
	file, ok := out.(*os.File)
	if ok && terminalSupportsANSI(file) {
		return "terminal-color"
	}
	return format
}
