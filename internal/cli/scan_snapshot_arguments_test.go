package cli

import (
	"strings"
	"testing"
)

func TestScanSnapshotDigestRequiresCanonicalSingleSHA256(t *testing.T) {
	good := "sha256-" + strings.Repeat("AQEB", 10) + "AQE="
	for _, v := range []struct {
		value string
		ok    bool
	}{{good, true}, {good + " " + good, false}, {"sha384-" + strings.Repeat("A", 64), false}, {"sha256-" + strings.Repeat("A", 44), false}} {
		_, e := ParseArgs([]string{"scan", "--trusted-snapshot-digest", v.value, "project"})
		if (e == nil) != v.ok {
			t.Fatalf("canonical pin grammar ok=%t err=%v", v.ok, e)
		}
	}
}
