package inventory

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func pnpmProject(t *testing.T, input string) PNPMLockProjection {
	t.Helper()
	doc, err := ParsePNPMLock([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	p, err := ProjectPNPMLock(doc)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestProjectPNPMLockImportersAndAliases(t *testing.T) {
	p := pnpmProject(t, "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      alias:\n        specifier: npm:@scope/actual@^1.0.0\n        version: '@scope/actual@1.0.0(peer@2.0.0)'\npackages:\n  '@scope/actual@1.0.0':\n    resolution: {integrity: sha512-claim, tarball: 'https://example.invalid/a.tgz'}\nsnapshots:\n  '@scope/actual@1.0.0(peer@2.0.0)': {}\n")
	ref := p.Importers[0].References[0]
	if ref.Group != "dependencies" || ref.InstallationName != "alias" || ref.Specifier.Value != "npm:@scope/actual@^1.0.0" || ref.Reference.Value != "@scope/actual@1.0.0(peer@2.0.0)" {
		t.Fatalf("alias lost: %+v", ref)
	}
	// Importer requirements are version references, not manifest specifiers.
	if p.Importers[0].Requirements[0].Entries[0].Requirement != ref.Reference.Value {
		t.Fatal("specifier became declaration")
	}
	r := p.Records[0]
	if r.Name.Value != "@scope/actual" || r.Version.Value != "1.0.0" || r.PackageKey != "@scope/actual@1.0.0" || r.SnapshotKey != "@scope/actual@1.0.0(peer@2.0.0)" || r.Kind != "package" || r.Unsupported {
		t.Fatalf("identity lost: %+v", r)
	}
}

func TestProjectPNPMLockPeerContextsAndMetadata(t *testing.T) {
	p := pnpmProject(t, pnpmEmpty+`packages:
  a@1.0.0:
    resolution: {integrity: sha512-metadata}
    peerDependencies: {peer: '*'}
  alone@2.0.0: {}
snapshots:
  a@1.0.0(peer@1.0.0): {dependencies: {peer: 1.0.0}}
  a@1.0.0(peer@2.0.0): {dependencies: {peer: 2.0.0}}
  missing@1.0.0: {}
`)
	if len(p.Records) != 4 {
		t.Fatal("records collapsed")
	}
	seen := map[string]PNPMLockedRecord{}
	for _, r := range p.Records {
		key := r.SnapshotKey
		if key == "" {
			key = r.PackageKey
		}
		seen[key] = r
	}
	for _, key := range []string{"a@1.0.0(peer@1.0.0)", "a@1.0.0(peer@2.0.0)"} {
		r := seen[key]
		if r.PackageKey != "a@1.0.0" || r.Integrity.Value != "sha512-metadata" {
			t.Fatalf("metadata lost: %+v", r)
		}
		found := false
		for _, g := range r.Requirements {
			if g.Name == "peerDependencies" && len(g.Entries) == 1 {
				found = true
			}
		}
		if !found {
			t.Fatal("lost metadata peer requirements")
		}
	}
	if seen["alone@2.0.0"].SnapshotKey != "" {
		t.Fatal("invented snapshot")
	}
	if !seen["missing@1.0.0"].Unsupported || seen["missing@1.0.0"].Problem == "" {
		t.Fatal("unmatched snapshot qualified")
	}
}

func TestProjectPNPMLockSnapshotStorageIsolation(t *testing.T) {
	doc, err := ParsePNPMLock([]byte(pnpmEmpty + "packages: {a@1.0.0: {peerDependencies: {peer: '*'}}}\nsnapshots: {a@1.0.0(peer@1.0.0): {}, a@1.0.0(peer@2.0.0): {}}\n"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := ProjectPNPMLock(doc)
	if err != nil {
		t.Fatal(err)
	}
	p.Records[0].Requirements[3].Entries[0].Requirement = "mutated"
	if p.Records[1].Requirements[3].Entries[0].Requirement != "*" {
		t.Fatal("peer contexts share mutable projection storage")
	}
	p2, err := ProjectPNPMLock(doc)
	if err != nil || p2.Records[0].Requirements[3].Entries[0].Requirement != "*" {
		t.Fatal("projection mutated owned nodes")
	}
}

func TestProjectPNPMLockUnsupportedSources(t *testing.T) {
	for _, key := range []string{"../secret@1.0.0", "a@file:../secret", "a@https://example.invalid/x", "a@1.0.0(patch_hash=secret)", "a@1.0.0(peer@1.0.0", "a@1.0.0()", "a@1.0.0(peer@1.0.0)tail", "a@1.0.0(../../peer@1.0.0)"} {
		p := pnpmProject(t, pnpmEmpty+fmt.Sprintf("packages:\n  %q: {}\nsnapshots:\n  %q: {}\n", key, key))
		for _, r := range p.Records {
			if !r.Unsupported || r.Problem == "" || strings.Contains(r.Problem, "secret") {
				t.Fatalf("unsupported key qualified: %+v", r)
			}
		}
	}
	p := pnpmProject(t, pnpmEmpty+"packages: {a@1.0.0: {resolution: {type: directory, directory: ../private}}}\nsnapshots: {a@1.0.0: {}}\n")
	if !p.Records[0].Unsupported || p.Records[0].Problem == "" {
		t.Fatal("unsupported resolution qualified")
	}
}

func TestProjectPNPMLockUnsafeResolutionAndConflicts(t *testing.T) {
	for _, body := range []string{
		"resolution: {tarball: 'file:../private'}", "resolution: {tarball: 'https://user:secret@example.invalid/a.tgz'}",
		"resolution: {tarball: ''}", "resolution: {tarball: 'git+ssh://example.invalid/a'}",
		"name: different", "version: 2.0.0", "patchHash: private",
	} {
		p := pnpmProject(t, pnpmEmpty+"packages: {a@1.0.0: {"+body+"}}\nsnapshots: {a@1.0.0: {}}\n")
		if !p.Records[0].Unsupported || p.Records[0].Problem == "" {
			t.Fatalf("unsupported semantics qualified: %+v", p.Records[0])
		}
	}
	for _, ref := range []string{"link:../private", "file:../private", "workspace:*", "https://example.invalid/a", "git+ssh://example.invalid/a"} {
		p := pnpmProject(t, pnpmEmpty+"packages: {a@1.0.0: {}}\nsnapshots: {a@1.0.0: {dependencies: {b: '"+ref+"'}}}\n")
		if !p.Records[0].Unsupported {
			t.Fatal("unsupported reference qualified")
		}
	}
	for _, metadata := range []string{"resolution: {}", "patched: true", "patchHash: private", "name: different", "version: 2.0.0"} {
		p := pnpmProject(t, pnpmEmpty+"packages: {a@1.0.0: {}}\nsnapshots: {a@1.0.0: {"+metadata+"}}\n")
		if !p.Records[0].Unsupported {
			t.Fatal("snapshot metadata qualified")
		}
	}
	p := pnpmProject(t, pnpmEmpty+"packages: {'': {}}\nsnapshots: {'': {}}\n")
	if len(p.Records) != 2 || !p.Records[0].Unsupported || !p.Records[1].Unsupported {
		t.Fatal("empty key qualified or discarded")
	}
}

func TestProjectPNPMLockDeterministicOrder(t *testing.T) {
	a := pnpmProject(t, pnpmEmpty+"packages: {z@1.0.0: {}, a@1.0.0: {}}\nsnapshots: {z@1.0.0: {}, a@1.0.0: {}}\n")
	b := pnpmProject(t, pnpmEmpty+"snapshots: {a@1.0.0: {}, z@1.0.0: {}}\npackages: {a@1.0.0: {}, z@1.0.0: {}}\n")
	a.SourceSHA256 = b.SourceSHA256
	if !reflect.DeepEqual(a, b) {
		t.Fatal("order depends on YAML ordering")
	}
}

func TestProjectPNPMLockExactRecordAndRequirementBounds(t *testing.T) {
	for _, n := range []int{19999, 20000} {
		var b strings.Builder
		b.WriteString(pnpmEmpty + "packages:\n")
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "  a%d@1.0.0: {}\n", i)
		}
		_, err := ParsePNPMLock([]byte(b.String()))
		if (err != nil) != (n > 19999) {
			t.Fatalf("record boundary %d: %v", n, err)
		}
	}
	for _, n := range []int{20000, 20001} {
		var b strings.Builder
		b.WriteString(pnpmEmpty + "packages:\n  a@1.0.0:\n    dependencies:\n")
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "      a%d: 1.0.0\n", i)
		}
		_, err := ParsePNPMLock([]byte(b.String()))
		if (err != nil) != (n > 20000) {
			t.Fatalf("requirement boundary %d: %v", n, err)
		}
	}
	for _, n := range []int{10000, 10001} {
		var b strings.Builder
		b.WriteString("lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n")
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "      a%d: {specifier: '*', version: 1.0.0}\n", i)
		}
		_, err := ParsePNPMLock([]byte(b.String()))
		if (err != nil) != (n > 10000) {
			t.Fatalf("reference boundary %d: %v", n, err)
		}
	}
}

func TestProjectPNPMLockAggregateLimits(t *testing.T) {
	var b strings.Builder
	b.WriteString(pnpmEmpty + "packages:\n  a@1.0.0:\n    peerDependencies:\n")
	for i := 0; i < 201; i++ {
		fmt.Fprintf(&b, "      peer%d: '*'\n", i)
	}
	b.WriteString("snapshots:\n")
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&b, "  a@1.0.0(peer@1.0.%d): {}\n", i)
	}
	pnpmParseCode(t, b.String(), "limit-exceeded") // Metadata fan-out is charged too.
}
