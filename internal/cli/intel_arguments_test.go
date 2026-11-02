package cli

import (
	"strings"
	"testing"
)

func TestIntelSyncRejectsProjectArgument(t *testing.T) {
	if _, e := ParseArgs([]string{"intel", "sync", "private-project"}); e == nil {
		t.Fatal("sync accepted project target")
	}
}
func TestIntelPureGrammarClosedActionsAndSelectors(t *testing.T) {
	id := strings.Repeat("a", 64)
	for _, args := range [][]string{
		{"intel", "sync"}, {"intel", "sync", "--full", "--state-dir", "private-state", "--format=json"},
		{"intel", "import", "--trusted-snapshot-digest", "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "--", "-owned.bundle"},
		{"intel", "export", "--output", "owned.bundle"}, {"intel", "status"}, {"intel", "pin", id}, {"intel", "unpin", id}, {"cache", "prune"}, {"cache", "prune", "--apply", id, "--format", "json"},
	} {
		invocation, e := ParseArgs(args)
		if e != nil {
			t.Fatal(args, e)
		}
		if invocation.Action == ArgumentActionUnknown || invocation.Action == ArgumentActionScan {
			t.Fatal("intel command misrouted")
		}
	}
	invocation, e := ParseArgs([]string{"intel", "sync", "--full"})
	if e != nil || !invocation.Intel.Full || invocation.Intel.StateDir != "" {
		t.Fatal("pure default/full request changed", e)
	}
}
func TestIntelGrammarRejectsDuplicateCrossActionAndWeakAuthoritySelectors(t *testing.T) {
	for _, args := range [][]string{
		{"intel", "sync", "--state-dir=a", "--state-dir=b"}, {"intel", "sync", "--format"}, {"intel", "sync", "--full=true"}, {"intel", "sync", "--full", "--full"},
		{"intel", "sync", "--output", "private"}, {"intel", "status", "--full"}, {"intel", "status", "private-target"}, {"intel", "export"}, {"intel", "export", "--output=-"},
		{"intel", "import"}, {"intel", "import", "a", "b"}, {"intel", "import", "--trusted-snapshot-digest", "sha1-Zm9v", "owned"}, {"intel", "import", "--trusted-snapshot-digest", "sha256-a sha256-b", "owned"},
		{"intel", "pin", strings.Repeat("A", 64)}, {"intel", "pin", strings.Repeat("0", 64)}, {"intel", "unpin", ""}, {"intel", "pin", "--format=json", strings.Repeat("a", 64)},
		{"cache", "prune", "--apply", strings.Repeat("0", 64)}, {"cache", "prune", "--state-dir=bad\x00dir"}, {"cache", "prune", "private-target"}, {"cache", "prune", "--format=sarif"}, {"cache", "delete"},
	} {
		if _, e := ParseArgs(args); e == nil {
			t.Fatal("invalid request admitted", args)
		}
	}
}
