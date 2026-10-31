package execution

import (
	"context"
	"io"
	"os"
	"os/exec"
	"packtrace/internal/demo"
	"packtrace/internal/inspect"
	"strings"
	"testing"
	"time"
)

// Review-only child. It uses the actual supervisor with an owned, inert driver;
// no production/test hook has been added to the reviewed workspace.
func reviewDriver(mode string) int {
	identity, e := buildIdentity()
	if e != nil {
		return 90
	}
	c := newChannel(os.Stdin, os.Stdout, &traffic{})
	if c.send("hello", hello{identity}) != nil {
		return 91
	}
	var h hello
	var cfg config
	if c.expect("hello", &h) != nil || c.expect("config", &cfg) != nil {
		return 92
	}
	if _, e = c.receive(); e != io.EOF {
		return 93
	}
	data, e := readInheritedInput(cfg)
	if e != nil {
		return 94
	}
	result, e := inspect.ReadBatchProfile(strings.NewReader(string(data)), cfg.Profile)
	if e != nil {
		return 95
	}
	for ai, a := range result.Advisories {
		if a.Report == nil {
			continue
		}
		r := a.Report
		switch mode {
		case "no-match-with-support":
			r.Evaluations[0].VersionOutcome = "no-match"
		case "mixed-withdrawal":
			r.Evaluations[1].Withdrawal = "reported"
		case "identity-drift":
			r.Evaluations[1].IdentityQualification = "unqualified"
			r.Evaluations[1].IdentityComparison = "indeterminate"
		case "late-version-contradiction":
			if ai == 1 {
				r.Evaluations[0].VersionOutcome = "no-match"
			}
		case "inventory-invalid-drift":
			if ai == 1 {
				r.Inventory[0].LinkQualification = "invalid-type"
			}
		case "inventory-drift":
			if ai == 1 {
				r.Inventory[0].LinkQualification = "link"
				r.Coverage[5] = demo.Coverage{Check: "record-qualification", Outcome: "incomplete", Reason: "missing-unqualified-or-link-claims"}
			}
		case "no-match-problems":
			r.Evaluations[0].VersionOutcome = "no-match"
			r.Evaluations[0].VersionFullyEvaluated = false
			r.Evaluations[0].Support = []demo.Support{}
			r.Evaluations[0].Problems = []demo.Problem{{Kind: "version-outside-profile", VersionIndex: 0, RangeIndex: -1, EventIndex: -1}}
			r.Coverage[1] = demo.Coverage{Check: "version-conditions", Outcome: "incomplete", Reason: "unsupported-or-unqualified"}
		}
		r.Candidates = expectedCandidates(r)
	}
	result.CandidateCount = 0
	if c.send("start", start{result.LockedEntries, len(result.Advisories)}) != nil {
		return 96
	}
	for i, a := range result.Advisories {
		values := []demo.Candidate{}
		n := 0
		if a.Report != nil {
			values = a.Report.Candidates
			a.Report.Candidates = []demo.Candidate{}
			n = len(a.Report.Evaluations)
		}
		if c.send("advisory", advisory{i, a.State, a.Report}) != nil {
			return 97
		}
		for _, v := range values {
			if c.send("candidate", candidate{i, v}) != nil {
				return 98
			}
		}
		if c.send("closure", closure{i, len(values), n}) != nil {
			return 99
		}
		result.CandidateCount += len(values)
	}
	if c.send("done", done{len(result.Advisories), result.CandidateCount}) != nil {
		return 100
	}
	return 0
}

func TestReviewCoherentControl(t *testing.T)           { reviewResult(t, "healthy", false) }
func TestReviewRejectNoMatchWithSupport(t *testing.T)  { reviewResult(t, "no-match-with-support", true) }
func TestReviewRejectNoMatchWithProblems(t *testing.T) { reviewResult(t, "no-match-problems", true) }
func TestReviewRejectMixedWithdrawal(t *testing.T)     { reviewResult(t, "mixed-withdrawal", true) }
func TestReviewRejectInventoryDrift(t *testing.T)      { reviewResult(t, "inventory-drift", true) }
func TestSharedIdentityQualification(t *testing.T)     { reviewResult(t, "identity-drift", true) }
func TestLateContradictionRetainsIndependentScope(t *testing.T) {
	reviewResult(t, "late-version-contradiction", true)
}
func TestInvalidInventoryDriftInvalidatesEarlierScope(t *testing.T) {
	reviewResult(t, "inventory-invalid-drift", true)
}

func reviewResult(t *testing.T, mode string, reject bool) {
	t.Helper()
	input := strings.Replace(fixture, `"version":"1.2.3"}}}`, `"version":"1.2.3"},"node_modules/second":{"name":"owned","version":"1.2.3"}}}`, 1)
	// Two usable entries establish shared-lock inventory consistency.
	ad := `{"id":"OWNED","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"owned"},"versions":["1.2.3"]}]}`
	input = strings.Replace(input, `42]}`, ad+`]}`, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	identity, e := buildIdentity()
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(os.Args[0], "--review-driver", mode)
	cmd.Env = []string{}
	run, e := supervise(ctx, strings.NewReader(input), "explicit-only", cmd, identity)
	if cmd.ProcessState == nil {
		t.Fatal("unreaped")
	}
	t.Logf("mode=%s error=%v usable=%t advisories=%d candidates=%d interrupted=%t normal_exit=%t coverage=%+v", mode, e, run.Usable, len(run.Result.Advisories), run.Result.CandidateCount, run.Interrupted, cmd.ProcessState.Success(), run.Result.Coverage)
	if reject {
		if e == nil {
			t.Fatalf("accepted internally contradictory %s as coherent normal completion", mode)
		}
		if strings.HasPrefix(mode, "inventory-") && (run.Usable || len(run.Result.Advisories) != 0 || run.Result.CandidateCount != 0) {
			t.Fatal("contradicted job inventory retained", run)
		}
		if mode == "late-version-contradiction" && (!run.Usable || len(run.Result.Advisories) != 1 || run.Result.CandidateCount != 2 || run.Result.Coverage[0].Outcome != "incomplete") {
			t.Fatal("independently closed advisory lost or falsely completed", run)
		}
	} else if e != nil || !run.Usable || len(run.Result.Advisories) != 2 || run.Result.CandidateCount != 4 {
		t.Fatalf("healthy control failed: %+v %v", run, e)
	}
}
