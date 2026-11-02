package execution

import (
	"packtrace/internal/cli"
	"packtrace/internal/intelstore"
	"testing"
)

func TestIntelResultCompleteWithoutConcreteClosureIsNotAuthority(t *testing.T) {
	for _, action := range []cli.ArgumentAction{cli.ArgumentActionUnknown, cli.ArgumentActionIntelSync, cli.ArgumentActionIntelImport, cli.ArgumentActionIntelStatus, cli.ArgumentActionIntelExport, cli.ArgumentActionIntelPin, cli.ArgumentActionCachePrune} {
		if validateIntelResult(IntelResult{Action: action, Outcome: "complete"}, cli.IntelArgumentRequest{Action: action}) == nil {
			t.Fatal("isolated completion flag accepted", action)
		}
	}
}
func TestIntelResultRejectsCrossActionAndUnconfirmedCounters(t *testing.T) {
	request := cli.IntelArgumentRequest{Action: cli.ArgumentActionIntelStatus}
	good := IntelResult{Action: request.Action, Outcome: "unavailable"}
	if validateIntelResult(good, request) != nil {
		t.Fatal("closed unavailable status rejected")
	}
	bad := good
	bad.Action = cli.ArgumentActionIntelSync
	if validateIntelResult(bad, request) == nil {
		t.Fatal("cross-action result")
	}
	bad = good
	bad.Outcome = "all-safe"
	if validateIntelResult(bad, request) == nil {
		t.Fatal("unknown outcome")
	}
	bad = good
	bad.WrittenBytes = 1
	if validateIntelResult(bad, request) == nil {
		t.Fatal("status invented output bytes")
	}
	bad = good
	bad.Prune = &intelstore.PruneResult{}
	if validateIntelResult(bad, request) == nil {
		t.Fatal("status reported destructive operation")
	}
}
