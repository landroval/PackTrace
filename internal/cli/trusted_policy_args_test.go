package cli

import (
	"strings"
	"testing"
)

func TestTrustedPolicyDigestArgumentIsExplicitBoundedAndNotAuthority(t *testing.T) {
	pin := "sha256-" + strings.Repeat("A", 43) + "="
	for _, args := range [][]string{{"scan", "--trusted-policy-digest", pin, "--policy", "external.json", "root"}, {"scan", "--trusted-policy-digest=" + pin, "--policy", "external.json", "root"}} {
		inv, e := ParseArgs(args)
		if e != nil || inv.Action != ArgumentActionScan || inv.Scan.Provided&ArgumentOptions(256) == 0 {
			t.Fatal("explicit policy pin not parsed", e)
		}
	}
	for _, args := range [][]string{{"scan", "--trusted-policy-digest", "--policy", "p", "root"}, {"scan", "--trusted-policy-digest=", "root"}, {"scan", "--trusted-policy-digest", pin, "--trusted-policy-digest", pin, "root"}, {"scan", "--trusted-policy-digest", strings.Repeat("PRIVATE", 400), "root"}} {
		_, e := ParseArgs(args)
		if e == nil || strings.Contains(e.Error(), "PRIVATE") {
			t.Fatal("invalid pin option accepted or exposed")
		}
	}
}
