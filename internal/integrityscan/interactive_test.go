package integrityscan

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestInteractiveViewRequiresFrozenAuthorityAndHonorsPrivacy(t *testing.T) {
	for _, privacy := range []string{"local", "portable"} {
		plan, inv, info, a := candidateReportFixture(t, privacy)
		r := BuildReportWithPolicy(plan, nil, Summary{}, Resources{}, false, false, &inv, &info, &a, nil, false, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
		before, e := Render(r, "json")
		if e != nil {
			t.Fatal(e)
		}
		v, e := BuildInteractiveView(r)
		if e != nil || len(v.Rows) == 0 || v.Exit != r.ExitCode {
			t.Fatal("viewer projection", e, v)
		}
		raw, _ := json.Marshal(v)
		if privacy == "portable" && strings.Contains(string(raw), "left-pad") {
			t.Fatal("portable viewer leaked identity")
		}
		if privacy == "local" && !strings.Contains(string(raw), "left-pad") {
			t.Fatal("local viewer lost identity")
		}
		after, _ := Render(r, "json")
		if string(before) != string(after) {
			t.Fatal("viewer mutated report")
		}
		var decoded Report
		if json.Unmarshal(before, &decoded) != nil {
			t.Fatal("report fixture")
		}
		if _, e := BuildInteractiveView(decoded); e == nil {
			t.Fatal("saved JSON reconstructed authority")
		}
	}
}
