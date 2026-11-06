package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestRequiredIntelligenceCasesNeedExactPositiveTerminalEvents(t *testing.T) {
	if len(requiredIntelligenceCases) != 15 || !strings.Contains(strings.Join(requiredIntelligenceCases, "\n"), "packtrace/internal/intelstore#TestChangedOriginalReusesEmptyPartitionsButStillRequiresTheirActualObject") {
		t.Fatal("missing required cross-platform lifecycle cases")
	}
	type event struct{ Action, Package, Test string }
	var rows []event
	for _, key := range requiredIntelligenceCases {
		parts := strings.Split(key, "#")
		rows = append(rows, event{"pass", parts[0], parts[1]})
	}
	encode := func(events []event) []byte {
		var data bytes.Buffer
		for _, item := range events {
			if e := json.NewEncoder(&data).Encode(item); e != nil {
				t.Fatal(e)
			}
		}
		return data.Bytes()
	}
	good := encode(rows)
	got, e := intelligenceCases(good)
	if e != nil || strings.Join(got, "\n") != strings.Join(requiredIntelligenceCases, "\n") {
		t.Fatal("complete cases not retained", got, e)
	}
	bad := [][]byte{good[:len(good)-1], append(append([]byte(nil), good...), encode(rows[:1])...)}
	for missing := range rows {
		remaining := append([]event(nil), rows[:missing]...)
		remaining = append(remaining, rows[missing+1:]...)
		bad = append(bad, encode(remaining))
	}
	for _, field := range []string{"skip", "wrong-package", "fail"} {
		changed := append([]event(nil), rows...)
		if field == "wrong-package" {
			changed[0].Package = field
		} else {
			changed[0].Action = field
		}
		bad = append(bad, encode(changed))
	}
	for _, data := range bad {
		if _, e := intelligenceCases(data); e == nil {
			t.Fatal("missing/skipped/forged/duplicate case became native acceptance")
		}
	}
}
