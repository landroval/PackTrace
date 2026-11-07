package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestScanAndIntelUseTheSameLowercaseDefaultStore(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("owned native store")
	}
	cache := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cache)
	t.Setenv("LOCALAPPDATA", cache)
	t.Setenv("HOME", cache)
	base, e := os.UserCacheDir()
	if e != nil {
		t.Fatal(e)
	}
	id := importIntelScanFixture(t, filepath.Join(base, "packtrace"))
	target, policy := scanFixture(t)
	var output, diagnostic bytes.Buffer
	code := runMain([]string{"scan", "--policy", policy, "--checks", "integrity,malicious,vulnerability", "--format", "json", target}, forbiddenReader{}, &output, &diagnostic)
	var report struct {
		Intelligence struct{ State string } `json:"intelligence"`
	}
	if code != 3 || diagnostic.Len() != 0 || json.Unmarshal(output.Bytes(), &report) != nil || report.Intelligence.State != "available" || !strings.Contains(output.String(), hex.EncodeToString(id[:])) {
		t.Fatal("scan did not select the prepared lowercase default", code, output.String(), diagnostic.String())
	}
}
