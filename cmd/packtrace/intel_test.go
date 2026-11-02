package main

import (
	"bytes"
	"context"
	"encoding/json"
	"packtrace/internal/cli"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestIntelStatusRealConsumerMissingStateProducesPrivateIncompleteReport(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("native role")
	}
	private := filepath.Join(t.TempDir(), "private-state")
	var out, diag bytes.Buffer
	code := runMain([]string{"intel", "status", "--state-dir", private, "--format", "json"}, strings.NewReader("must not read"), &out, &diag)
	var result map[string]any
	if code != 3 || json.Unmarshal(out.Bytes(), &result) != nil || bytes.Contains(out.Bytes(), []byte(private)) || diag.Len() != 0 {
		t.Fatal("real consumer failed", code, out.String(), diag.String())
	}
}
func TestIntelCLIRealOfflineImportExportAndMaintenance(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("native worker")
	}
	base := t.TempDir()
	state := filepath.Join(base, "state")
	fixture, e := filepath.Abs("../../internal/execution/testdata/intel/owned.bundle")
	if e != nil {
		t.Fatal(e)
	}
	var out, diag bytes.Buffer
	code := runMain([]string{"intel", "import", "--state-dir", state, "--format=json", fixture}, strings.NewReader(""), &out, &diag)
	if code != 3 || !bytes.Contains(out.Bytes(), []byte(`"sourceAuthority":"unqualified"`)) {
		t.Fatal("actual import failed", code, out.String(), diag.String())
	}
	out.Reset()
	output := filepath.Join(base, "transport.bundle")
	code = runMain([]string{"intel", "export", "--state-dir", state, "--format=json", "--output", output}, strings.NewReader(""), &out, &diag)
	if code != 3 {
		t.Fatal("actual export failed", code, out.String(), diag.String())
	}
	out.Reset()
	code = runMain([]string{"cache", "prune", "--state-dir", state, "--format=json"}, strings.NewReader(""), &out, &diag)
	if code != 0 || !bytes.Contains(out.Bytes(), []byte(`"preview"`)) {
		t.Fatal("actual preview failed", code, out.String(), diag.String())
	}
}

func TestIntelOutputFailureAndInterruptKeepExitPrecedence(t *testing.T) {
	request := cli.IntelArgumentRequest{Action: cli.ArgumentActionIntelStatus, StateDir: filepath.Join(t.TempDir(), "absent"), Format: "json"}
	if code := runIntelContext(context.Background(), request, failedIntelWriter{}, &bytes.Buffer{}); code != 2 {
		t.Fatal("output failure masked", code)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if code := runIntelContext(ctx, request, &bytes.Buffer{}, &bytes.Buffer{}); code != 130 {
		t.Fatal("interruption masked", code)
	}
}

type failedIntelWriter struct{}

func (failedIntelWriter) Write([]byte) (int, error) { return 0, context.Canceled }
