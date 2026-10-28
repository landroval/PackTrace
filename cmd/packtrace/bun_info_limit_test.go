package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Package-count and wire caps do not replace the independent INFO allowance.
func TestBunInfoRequirementLimit(t *testing.T) {
	advisory := json.RawMessage(`{"id":"PRIVATE-ADVISORY","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"example"},"versions":["1.2.3"]}]}`)
	for _, count := range []int{20000, 20001} {
		requirements := make(map[string]string, count)
		for i := 0; i < count; i++ {
			requirements[fmt.Sprintf("d%05d", i)] = "1"
		}
		text, err := json.Marshal(map[string]any{
			"lockfileVersion": 1, "workspaces": map[string]any{},
			"packages": map[string]any{"example": []any{"example@1.2.3", "", map[string]any{"dependencies": requirements}, "sha"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, command := range []string{"inspect-bun", "inspect-bun-batch"} {
			envelope := map[string]any{"lockfile_text": string(text)}
			if command == "inspect-bun" {
				envelope["advisory"] = advisory
			} else {
				envelope["advisories"] = []json.RawMessage{advisory}
			}
			input, err := json.Marshal(envelope)
			if err != nil {
				t.Fatal(err)
			}
			if len(input) >= 1<<20 {
				t.Fatal("fixture must remain below the wire cap")
			}
			for _, format := range []string{"terminal", "json"} {
				t.Run(fmt.Sprintf("%s/%d/%s", command, count, format), func(t *testing.T) {
					var out, diagnostic bytes.Buffer
					exit := runInput([]string{command, "--format", format}, bytes.NewReader(input), &out, &diagnostic)
					if count == 20001 {
						want := "inspect-bun: invalid-metadata\n"
						if command == "inspect-bun-batch" {
							want = "inspect-bun-batch: invalid-lockfile\n"
						}
						if exit != 2 || out.Len() != 0 || diagnostic.String() != want {
							t.Fatalf("INFO overflow: exit=%d stdout=%d stderr=%q", exit, out.Len(), diagnostic.String())
						}
						return
					}
					if exit != 3 || diagnostic.Len() != 0 || out.Len() == 0 {
						t.Fatalf("exact INFO cap: exit=%d stdout=%d stderr=%q", exit, out.Len(), diagnostic.String())
					}
					if strings.Contains(out.String(), "PRIVATE") || strings.Contains(out.String(), "example") || strings.Contains(out.String(), "d00000") {
						t.Fatal("portable report leaked input metadata")
					}
					if format == "json" {
						var report struct {
							Schema   string   `json:"schema"`
							ExitCode int      `json:"exit_code"`
							Findings []string `json:"findings"`
						}
						if err := json.Unmarshal(out.Bytes(), &report); err != nil {
							t.Fatal(err)
						}
						want := "packtrace.inspect.bun.v1"
						if command == "inspect-bun-batch" {
							want = "packtrace.inspect.bun-batch.v1"
						}
						if report.Schema != want || report.ExitCode != 3 || report.Findings == nil || len(report.Findings) != 0 {
							t.Fatal("incorrect partial-report contract", report)
						}
					}
				})
			}
		}
	}
}
