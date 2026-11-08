package main

import (
	"encoding/json"
	"packtrace/internal/cli"
	"packtrace/internal/execution"
	"packtrace/internal/intel"
	"packtrace/internal/intelstore"
	"strings"
	"testing"
)

func TestDatabaseTerminalGuidanceDoesNotChangeStructuredEvidence(t *testing.T) {
	for _, age := range []intel.FreshnessState{intel.FreshnessCurrent, intel.FreshnessExpired, intel.FreshnessUnknown} {
		r := execution.IntelResult{Action: cli.ArgumentActionIntelStatus, Outcome: "complete", Generation: strings.Repeat("1", 64), Observation: &intelstore.Observation{Records: 7, Check: age, FullReconciliation: age, SourceAuthority: intelstore.SourceDesignated, IdentityGaps: 1}}
		before, _ := json.Marshal(r)
		text := string(renderIntelTerminal(r))
		after, _ := json.Marshal(r)
		if string(before) != string(after) || !strings.Contains(text, "Advisory records: 7 (not installed packages or confirmed vulnerabilities)") || !strings.Contains(text, "not publisher authentication") {
			t.Fatal("metadata promoted or changed", text)
		}
		switch age {
		case intel.FreshnessCurrent:
			if strings.Contains(text, "sync --full") || !strings.Contains(text, "not a complete project investigation") {
				t.Fatal("current dates promoted to safety", text)
			}
		case intel.FreshnessExpired:
			if !strings.Contains(text, "sync --full --state-dir DIR") || !strings.Contains(text, "writes the store") {
				t.Fatal("missing effect/next", text)
			}
		case intel.FreshnessUnknown:
			if !strings.Contains(text, "not proven current") || strings.Contains(text, "sync --full") {
				t.Fatal("unknown source got an automatic repair", text)
			}
		}
	}
}
