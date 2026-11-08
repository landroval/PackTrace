package cli

import "testing"

func TestScanVerboseArguments(t *testing.T) {
	for _, args := range [][]string{
		{"scan", "--verbose", "root"},
		{"scan", "--format", "terminal", "--verbose", "root"},
		{"scan", "--verbose", "--privacy", "local", "root"},
	} {
		inv, err := ParseArgs(args)
		if err != nil || inv.Scan.Format != "terminal-verbose" {
			t.Fatalf("verbose terminal rejected: %v %v", inv, err)
		}
	}
	for _, args := range [][]string{
		{"scan", "--verbose", "--format", "json", "root"},
		{"scan", "--format", "sarif", "--verbose", "root"},
		{"scan", "--verbose=true", "root"},
		{"scan", "--verbose", "--verbose", "root"},
		{"setup", "--verbose"},
		{"intel", "status", "--verbose"},
	} {
		if _, err := ParseArgs(args); err == nil {
			t.Fatalf("ambiguous verbose accepted: %v", args)
		}
	}
}
