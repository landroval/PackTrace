package projectinventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"packtrace/internal/nativefs"
)

func TestBunCollectedOriginalMatchingContext(t *testing.T) {
	const original = `{"lockfileVersion":1,"workspaces":{"":{"name":"PRIVATE-root"}},"packages":{"PRIVATE-p":["PRIVATE-p@1.0.0","",{},"sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="]}}`
	for _, tc := range []struct{ name, old, replacement, want string }{
		{"plain", "", "", "supported"},
		{"unknown-info", `{},"sha512`, `{"PRIVATE-unknown":true},"sha512`, "unsupported"},
		{"patch-info", `{},"sha512`, `{"patch":"PRIVATE-patch"},"sha512`, "unsupported"},
		{"peer-info", `{},"sha512`, `{"peerDependencies":{"PRIVATE-peer":"1"}},"sha512`, "unsupported"},
		{"patch-table", `"packages":`, `"patchedDependencies":{"PRIVATE-p":"PRIVATE-patch"},"packages":`, "unsupported"},
		{"unknown-document", `"packages":`, `"PRIVATE-context":true,"packages":`, "unsupported"},
		{"root-peer", `"name":"PRIVATE-root"`, `"name":"PRIVATE-root","peerDependencies":{}`, "unsupported"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			raw := original
			if tc.old != "" {
				raw = strings.Replace(raw, tc.old, tc.replacement, 1)
			}
			for name, data := range map[string]string{"package.json": `{"name":"PRIVATE-root"}`, "bun.lock": raw} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			root, err := nativefs.OpenRoot(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			if tc.name == "plain" {
				ordinary, err := Collect(context.Background(), root, Options{Profile: "bun@1.3.x", ExplicitManager: true})
				if err != nil || len(ordinary.OriginalInputs) != 0 {
					t.Fatal("ordinary inventory retained unrequested original bytes")
				}
			}
			inv, err := Collect(context.Background(), root, Options{Profile: "bun@1.3.x", ExplicitManager: true, RetainBunOriginals: true})
			if err != nil {
				t.Fatal(err)
			}
			if len(inv.OriginalInputs) != 2 || ValidateOriginalBytes(inv) != nil || ValidateOriginalClaims(PortableMatching(inv)) != nil {
				t.Fatal("retained original bytes not verifiable")
			}
			count := 0
			sum := sha256.Sum256([]byte(raw))
			for _, o := range inv.Model.Observations {
				if o.Class != "locked" || o.Kind != "package" {
					continue
				}
				count++
				if o.Fields["matching-context"] != tc.want {
					t.Fatalf("collected context = %q, want %q", o.Fields["matching-context"], tc.want)
				}
				e := inv.Model.Evidence[o.Source-1]
				if e.SHA256 != sum || e.Location != "bun.lock" || !e.Complete {
					t.Fatal("not bound to original selected document", e)
				}
			}
			if count != 1 {
				t.Fatal("missing collected tuple", inv)
			}
			for _, public := range []PublicInventory{Portable(inv), PortableMatching(inv)} {
				if err := ValidatePublic(public); err != nil {
					t.Fatal(err)
				}
				data, err := json.Marshal(public)
				if err != nil {
					t.Fatal(err)
				}
				for _, secret := range []string{"PRIVATE", dir, "matching-context", "sha512-", hex.EncodeToString(sum[:])} {
					if strings.Contains(string(data), secret) {
						t.Fatalf("portable inventory leaked %q", secret)
					}
				}
			}
		})
	}
}
