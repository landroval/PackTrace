package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

const commandSRI = "sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="

type commandErrReader struct{}

func (commandErrReader) Read([]byte) (int, error) { return 0, errors.New("PRIVATE-READER-ERROR") }

type commandFailWriter struct{ short bool }

func (w commandFailWriter) Write(p []byte) (int, error) {
	if w.short {
		return 0, nil
	}
	return 0, errors.New("PRIVATE-WRITER-ERROR")
}

type commandNoRead struct{}

func (commandNoRead) Read([]byte) (int, error) { panic("read before validation") }
func TestReferenceDigestCommandReports(t *testing.T) {
	for _, tc := range []struct{ input, state, format string }{{"abc", "match", "json"}, {"abd", "mismatch", "terminal"}, {"abc", "match", "terminal"}} {
		var out, diag bytes.Buffer
		exit := runInput([]string{"check-reference-digest", "--integrity=" + commandSRI, "--format", tc.format}, strings.NewReader(tc.input), &out, &diag)
		if exit != 3 || diag.Len() != 0 || !strings.Contains(out.String(), tc.state) || !strings.Contains(out.String(), "archive") || strings.Contains(out.String(), commandSRI) || strings.Contains(out.String(), "ungWv48B") {
			t.Fatal(exit, out.String(), diag.String())
		}
		if tc.format == "json" {
			var r struct {
				Schema, Scope, Privacy, State, Algorithm string
				Experimental                             bool
				BytesRead                                int64 `json:"bytes_read"`
				ExitCode                                 int   `json:"exit_code"`
			}
			if json.Unmarshal(out.Bytes(), &r) != nil || r.Schema != "packtrace.reference-digest.v1" || r.Scope != "supplied-reference-bytes" || r.Privacy != "portable" || !r.Experimental || r.State != "match" || r.Algorithm != "sha256" || r.BytesRead != 3 || r.ExitCode != 3 {
				t.Fatal(out.String())
			}
		}
	}
	for _, sri := range []string{"sha1-PRIVATE", commandSRI + " " + commandSRI} {
		var out, diag bytes.Buffer
		if runInput([]string{"check-reference-digest", "--integrity", sri}, commandNoRead{}, &out, &diag) != 3 || !strings.Contains(out.String(), "unknown") || strings.Contains(out.String(), sri) || diag.Len() != 0 {
			t.Fatal(out.String(), diag.String())
		}
	}
}
func TestReferenceDigestCommandValidationBeforeRead(t *testing.T) {
	for _, tail := range [][]string{{}, {"--integrity"}, {"--integrity="}, {"--integrity", commandSRI, "--integrity", commandSRI}, {"--integrity", commandSRI, "--max-bytes"}, {"--integrity", commandSRI, "--max-bytes=-1"}, {"--integrity", commandSRI, "--max-bytes=+1"}, {"--integrity", commandSRI, "--max-bytes=1.0"}, {"--integrity", commandSRI, "--max-bytes=536870913"}, {"--integrity", commandSRI, "--max-bytes=999999999999999999999"}, {"--integrity", commandSRI, "--max-bytes=1", "--max-bytes=2"}, {"--integrity", commandSRI, "--format=xml"}, {"--integrity", commandSRI, "--format"}, {"--integrity", commandSRI, "--format=json", "--format=terminal"}, {"--integrity", commandSRI, "--identity-profile=explicit-only"}, {"--integrity", commandSRI, "--set-profile=multi"}, {"--integrity", commandSRI, "--policy=PRIVATE"}, {"--integrity", commandSRI, "--path=PRIVATE"}, {"--integrity", commandSRI, "--enforce"}, {"--integrity", commandSRI, "--help"}, {"--integrity", commandSRI, "PRIVATE"}} {
		var out, diag bytes.Buffer
		if exit := runInput(append([]string{"check-reference-digest"}, tail...), commandNoRead{}, &out, &diag); exit != 2 || out.Len() != 0 || diag.String() != "check-reference-digest: invalid-arguments\n" {
			t.Fatal(tail, exit, out.String(), diag.String())
		}
	}
	var out, diag bytes.Buffer
	if runInput([]string{"check-reference-digest", "--help"}, commandNoRead{}, &out, &diag) != 0 || !strings.Contains(out.String(), "--max-bytes") || diag.Len() != 0 {
		t.Fatal(out.String(), diag.String())
	}
	for _, short := range []bool{false, true} {
		if runInput([]string{"check-reference-digest", "--help"}, commandNoRead{}, commandFailWriter{short}, &diag) != 2 {
			t.Fatal("help writer")
		}
	}
}
func TestReferenceDigestCommandFailuresAndLimits(t *testing.T) {
	for _, tc := range []struct {
		in  io.Reader
		max string
	}{{strings.NewReader("abc"), "2"}, {strings.NewReader("a"), "0"}, {commandErrReader{}, "3"}} {
		var out, diag bytes.Buffer
		if runInput([]string{"check-reference-digest", "--integrity", commandSRI, "--max-bytes", tc.max}, tc.in, &out, &diag) != 2 || out.Len() != 0 || diag.String() != "check-reference-digest: check-failed\n" {
			t.Fatal(out.String(), diag.String())
		}
	}
	for _, short := range []bool{false, true} {
		var diag bytes.Buffer
		if runInput([]string{"check-reference-digest", "--integrity", commandSRI}, strings.NewReader("abc"), commandFailWriter{short}, &diag) != 2 || diag.String() != "cli: output-failed\n" {
			t.Fatal(diag.String())
		}
	}
	var out, diag bytes.Buffer
	if runInput([]string{"check-reference-digest", "--integrity", commandSRI, "--max-bytes=03"}, strings.NewReader("abc"), &out, &diag) != 3 {
		t.Fatal("decimal digits", diag.String())
	}
	out.Reset()
	diag.Reset()
	if runInput([]string{"check-reference-digest", "--integrity", commandSRI, "--max-bytes=536870912"}, strings.NewReader("abc"), &out, &diag) != 3 {
		t.Fatal("max admitted", diag.String())
	}
	out.Reset()
	diag.Reset()
	if runInput([]string{"--help"}, commandNoRead{}, &out, &diag) != 0 || !strings.Contains(out.String(), "check-reference-digest") {
		t.Fatal("root help", out.String())
	}
}
