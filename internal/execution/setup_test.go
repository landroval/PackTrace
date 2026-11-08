//go:build linux

package execution

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"packtrace/internal/cli"
	"packtrace/internal/integrityscan"
)

func ownedUserSetup(t *testing.T) (string, string, string) {
	t.Helper()
	base := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", base)
	policy := filepath.Join(t.TempDir(), "policy.json")
	data := []byte(`{"version":1,"designation":"user-designated","reason":"Owned setup test","provenance":"Explicit operator selection, not publisher trust","manager":"npm@10-11","requiredChecks":["malicious"],"failOn":[],"minimumAssurance":"lockfile-consistent","references":[],"advisoryCandidates":true}`)
	if err := os.WriteFile(policy, data, 0600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(t.TempDir(), "absent")
	if err := RunSetup(context.Background(), cli.SetupArgumentRequest{PolicyPath: policy, StateDir: state}); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(base, "packtrace", userSetupName), policy, state
}

func TestUserSetupDefaultsAndOverrides(t *testing.T) {
	config, policy, state := ownedUserSetup(t)
	target := t.TempDir()
	parsed, err := cli.ParseArgs([]string{"scan", target})
	if err != nil {
		t.Fatal(err)
	}
	o, r, err := loadScanSetup(context.Background(), target, parsed.Scan)
	if err != nil || o == nil {
		t.Fatal(err)
	}
	defer o.close()
	data, _ := os.ReadFile(policy)
	sum := sha256.Sum256(data)
	if r.PolicyPath != policy || r.TrustedPolicyDigest != "sha256-"+base64.StdEncoding.EncodeToString(sum[:]) || r.StateDir != state || r.Privacy != "local" || r.Checks != cli.ArgumentCheckMalicious {
		t.Fatal("saved defaults not applied", r)
	}
	for _, args := range [][]string{
		{"scan", "--privacy", "portable", "--checks", "malicious,integrity", target},
		{"scan", "--policy", policy, target},
	} {
		p, err := cli.ParseArgs(args)
		if err != nil {
			t.Fatal(err)
		}
		q, got, err := loadScanSetup(context.Background(), target, p.Scan)
		if err != nil {
			t.Fatal(err)
		}
		if p.Scan.PolicyPath != "" {
			if q != nil || got != p.Scan {
				t.Fatal("explicit policy merged with saved grants")
			}
		} else {
			if q == nil || got.Privacy != "portable" || got.Checks != p.Scan.Checks {
				t.Fatal("explicit options lost", got)
			}
			q.close()
		}
	}
	// The exact original stays retained: mutation invalidates output/checkpoint.
	if err := os.WriteFile(config, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if o.check(context.Background()) == nil {
		t.Fatal("mutated configuration retained authority")
	}
}

func TestUserSetupRefusals(t *testing.T) {
	for _, mode := range []string{"missing", "hardlink", "symlink", "mode", "copied-root", "target-overlap", "duplicate", "case-alias", "null", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			config, _, _ := ownedUserSetup(t)
			target := t.TempDir()
			data, _ := os.ReadFile(config)
			switch mode {
			case "missing":
				if err := os.Remove(config); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(config, filepath.Join(t.TempDir(), "extra")); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				other := filepath.Join(t.TempDir(), "other")
				if err := os.Rename(config, other); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(other, config); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.Chmod(filepath.Dir(config), 0755); err != nil {
					t.Fatal(err)
				}
			case "copied-root":
				base := t.TempDir()
				if err := os.Mkdir(filepath.Join(base, "packtrace"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(base, "packtrace", userSetupName), data, 0600); err != nil {
					t.Fatal(err)
				}
				t.Setenv("XDG_CONFIG_HOME", base)
			case "target-overlap":
				target = filepath.Dir(config)
			case "duplicate":
				data = append([]byte(`{"version":1,`), data[1:]...)
			case "case-alias":
				data = []byte(strings.Replace(string(data), `"version":`, `"Version":`, 1))
			case "null":
				data = []byte(strings.Replace(string(data), `"privacy":"local"`, `"privacy":null`, 1))
			case "oversize":
				data = []byte(strings.Repeat(" ", maxUserSetupBytes+1))
			}
			if mode == "duplicate" || mode == "case-alias" || mode == "null" || mode == "oversize" {
				if err := os.WriteFile(config, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			p, _ := cli.ParseArgs([]string{"scan", target})
			o, _, err := loadScanSetup(context.Background(), target, p.Scan)
			if o != nil {
				defer o.close()
			}
			if err == nil {
				t.Fatal("unsafe setup accepted", mode)
			}
		})
	}
}

func TestUserSetupDoesNotReapprovePolicyOrClobberConfig(t *testing.T) {
	config, policy, state := ownedUserSetup(t)
	before, _ := os.ReadFile(config)
	if err := RunSetup(context.Background(), cli.SetupArgumentRequest{PolicyPath: policy, StateDir: state}); err == nil {
		t.Fatal("setup overwrote existing operator configuration")
	}
	after, _ := os.ReadFile(config)
	if string(before) != string(after) {
		t.Fatal("existing setup changed")
	}
	target := t.TempDir()
	p, _ := cli.ParseArgs([]string{"scan", target})
	o, r, err := loadScanSetup(context.Background(), target, p.Scan)
	if err != nil {
		t.Fatal(err)
	}
	defer o.close()
	data, _ := os.ReadFile(policy)
	if err := os.WriteFile(policy, append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := integrityscan.AcquirePolicyPinned(context.Background(), policy, target, r.TrustedPolicyDigest); err == nil {
		t.Fatal("normal scan silently reapproved changed policy")
	}
}

func TestUserSetupAbsentAndRelativeEnvironment(t *testing.T) {
	base := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", base)
	p, _ := cli.ParseArgs([]string{"scan", t.TempDir()})
	o, got, err := loadScanSetup(context.Background(), p.Scan.Path, p.Scan)
	if o != nil || err != nil || got != p.Scan {
		t.Fatal("absent setup changed legacy defaults", got, err)
	}
	// A project-local lookalike is never consulted.
	if err := os.WriteFile(filepath.Join(p.Scan.Path, userSetupName), []byte("untrusted"), 0600); err != nil {
		t.Fatal(err)
	}
	o, got, err = loadScanSetup(context.Background(), p.Scan.Path, p.Scan)
	if o != nil || err != nil || got != p.Scan {
		t.Fatal("target configuration discovered")
	}
	t.Setenv("XDG_CONFIG_HOME", "relative-config")
	if _, _, err := loadScanSetup(context.Background(), p.Scan.Path, p.Scan); err == nil {
		t.Fatal("cwd-relative config invented")
	}
}
