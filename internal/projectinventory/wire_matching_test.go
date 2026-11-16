package projectinventory

import (
	"strings"
	"testing"

	"packtrace/internal/inventory"
)

func TestBunMatchingOriginalContextWitness(t *testing.T) {
	const raw = `{"lockfileVersion":1,"workspaces":{"":{"name":"root"}},"packages":{"p":["p@1.0.0","",{},"sha512-placeholder"]}}`
	for _, tc := range []struct{ name, old, new, want string }{
		{"plain", "", "", "supported"},
		{"tuple-patch", `{},"sha512`, `{"patch":"hidden"},"sha512`, "unsupported"},
		{"unknown-info", `{},"sha512`, `{"newResolutionContext":true},"sha512`, "unsupported"},
		{"tuple-peer", `{},"sha512`, `{"peerDependencies":{"q":"1"}},"sha512`, "unsupported"},
		{"tuple-platform", `{},"sha512`, `{"os":"linux"},"sha512`, "unsupported"},
		{"root-peer", `"name":"root"`, `"name":"root","peerDependencies":{}`, "unsupported"},
		{"root-workspaces", `"name":"root"`, `"name":"root","workspaces":["packages/*"]`, "unsupported"},
		{"patch-table", `"packages":`, `"patchedDependencies":{},"packages":`, "unsupported"},
		{"unknown-top", `"packages":`, `"newContext":true,"packages":`, "unsupported"},
		{"nonroot-workspace", `"":{"name":"root"}`, `"packages/a":{"name":"root"}`, "unsupported"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := raw
			if tc.old != "" {
				data = strings.Replace(data, tc.old, tc.new, 1)
			}
			doc, err := inventory.ParseBunLock([]byte(data))
			if err != nil {
				t.Fatal(err)
			}
			p, err := inventory.ProjectBunLock(doc)
			if err != nil || len(p.Records) != 1 {
				t.Fatal(err)
			}
			if got := BunMatchingContext(doc, p.Records[0]); got != tc.want {
				t.Fatal(got, tc.want)
			}
		})
	}
}
