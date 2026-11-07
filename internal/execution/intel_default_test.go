package execution

import (
	"os"
	"packtrace/internal/cli"
	"path/filepath"
	"testing"
)

func TestIntelDefaultUsesVersionedLowercaseDirectory(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", root)
	t.Setenv("LOCALAPPDATA", root)
	t.Setenv("HOME", root)
	cache, e := os.UserCacheDir()
	if e != nil {
		t.Fatal(e)
	}
	got, e := normalizeIntelRequest(cli.IntelArgumentRequest{Action: cli.ArgumentActionIntelStatus})
	if e != nil || got.StateDir != filepath.Join(cache, "packtrace") {
		t.Fatal("default differs from approved design section29", got.StateDir, e)
	}
}
func TestIntelRelativeEnvironmentCannotInventDefaultStateUnderWorkingDirectory(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", "relative-cache")
	t.Setenv("LOCALAPPDATA", "relative-cache")
	t.Setenv("HOME", "relative-home")
	if _, e := normalizeIntelRequest(cli.IntelArgumentRequest{Action: cli.ArgumentActionIntelStatus}); e == nil {
		t.Fatal("relative environment was silently made into an absolute default")
	}
	got, e := normalizeIntelRequest(cli.IntelArgumentRequest{Action: cli.ArgumentActionIntelStatus, StateDir: "explicit-relative"})
	if e != nil || !filepath.IsAbs(got.StateDir) {
		t.Fatal("explicit invocation-relative state selector lost", got, e)
	}
}
