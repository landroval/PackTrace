package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

const pnpmEmpty = "lockfileVersion: '9.0'\nimporters: {.: {}}\n"

func pnpmParseCode(t *testing.T, data, code string) {
	t.Helper()
	_, err := ParsePNPMLock([]byte(data))
	var pe *ParseError
	if !errors.As(err, &pe) || pe.Code != code {
		t.Fatalf("want %s; got %v", code, err)
	}
	if err.Error() != "inventory: "+code {
		t.Fatal("unsafe diagnostic")
	}
}

func TestParsePNPMLockV9(t *testing.T) {
	for _, version := range []string{"'9.0'", "\"9.0\"", "9.0"} {
		doc, err := ParsePNPMLock([]byte(strings.Replace(pnpmEmpty, "'9.0'", version, 1)))
		if err != nil {
			t.Fatal(err)
		}
		p, err := ProjectPNPMLock(doc)
		if err != nil || len(p.Importers) != 1 || len(p.Records) != 0 {
			t.Fatalf("bad empty project: %+v %v", p, err)
		}
	}
	for _, version := range []string{"9", "9.00", "9e0", "'10.0'", "'9'", "|-\n  9.0", ">-\n  9.0"} {
		pnpmParseCode(t, strings.Replace(pnpmEmpty, "'9.0'", version, 1), "unsupported-version")
	}
}

func TestParsePNPMLockRejectsMalformedYAML(t *testing.T) {
	for _, input := range []string{"[", "x: \"unterminated", string([]byte{0xff})} {
		pnpmParseCode(t, input, "invalid-yaml")
	}
	for _, input := range []string{
		"[]", "null", "lockfileVersion: '9.0'\nimporters: {}\n---\n{}", pnpmEmpty + "---\n",
		pnpmEmpty + "unknown: {a: 1, a: 2}\n", pnpmEmpty + "unknown: {1: x}\n",
		pnpmEmpty + "unknown: {? [a, b]: x}\n", pnpmEmpty + "unknown: {<<: x}\n",
		pnpmEmpty + "unknown: &secret x\n", pnpmEmpty + "unknown: !!str x\n",
		pnpmEmpty + "unknown: !secret x\n", pnpmEmpty + "unknown: ! x\n",
		pnpmEmpty + "unknown: ! [a]\n", pnpmEmpty + "unknown: ! {a: x}\n",
		pnpmEmpty + "unknown: {é: value, b: ! x}\n",
		"\ufeff" + pnpmEmpty + "unknown: ! x\n",
		strings.ReplaceAll(pnpmEmpty+"unknown: ! x\n", "\n", "\r\n"), "lockfileVersion: !!float 9.0\nimporters: {}\n",
		pnpmEmpty + "unknown: &a [*a]\n",
	} {
		pnpmParseCode(t, input, "invalid-shape")
	}
}

func TestParsePNPMLockSectionShapes(t *testing.T) {
	for _, section := range []string{"importers", "packages", "snapshots"} {
		for _, value := range []string{"null", "[]", "true", "{x: null}"} {
			input := "lockfileVersion: '9.0'\n"
			if section != "importers" {
				input += "importers: {}\n"
			}
			pnpmParseCode(t, input+section+": "+value+"\n", "invalid-shape")
		}
	}
	for _, input := range []string{
		"lockfileVersion: '9.0'\n",
		pnpmEmpty + "packages: {a@1.0.0: {resolution: null}}\n",
		pnpmEmpty + "packages: {a@1.0.0: {resolution: {integrity: 5}}}\n",
		pnpmEmpty + "packages: {a@1.0.0: {peerDependencies: {b: 1}}}\n",
		pnpmEmpty + "snapshots: {a@1.0.0: {dependencies: {b: {version: x}}}}\n",
		"lockfileVersion: '9.0'\nimporters: {.: {dependencies: {a: '1.0.0'}}}\n",
		"lockfileVersion: '9.0'\nimporters: {.: {dependencies: {a: {specifier: '*', version: null}}}}\n",
		"lockfileVersion: '9.0'\nimporters: {.: {dependencies: {a: {specifier: '*'}}}}\n",
	} {
		pnpmParseCode(t, input, "invalid-shape")
	}
}

func TestParsePNPMLockKnownMetadataShapes(t *testing.T) {
	for _, metadata := range []string{"optional: null", "hasBin: x", "name: 1", "version: false", "cpu: null", "os: [1]", "libc: x", "bundledDependencies: true", "transitivePeerDependencies: [false]", "engines: []", "engines: {node: null}", "peerDependenciesMeta: null", "peerDependenciesMeta: {peer: false}", "peerDependenciesMeta: {peer: {optional: null}}"} {
		pnpmParseCode(t, pnpmEmpty+"packages: {a@1.0.0: {"+metadata+"}}\n", "invalid-shape")
	}
	for _, value := range []string{"null", "[]", "{autoInstallPeers: null}", "{excludeLinksFromLockfile: 'false'}"} {
		pnpmParseCode(t, pnpmEmpty+"settings: "+value+"\n", "invalid-shape")
	}
}

func TestParsePNPMLockUninterpretedEvidence(t *testing.T) {
	for _, extra := range []string{"unknown: '!literal'\n", "unknown: {value: 'a!b', flag: true, scalar: 123}\n", "unknown: [null, 2026-01-01, false]\n", "# !not-a-tag\n"} {
		if _, err := ParsePNPMLock([]byte(pnpmEmpty + extra)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestParsePNPMLockOriginalDigestAndOwnership(t *testing.T) {
	data := []byte(pnpmEmpty + "packages: {a@1.0.0: {resolution: {integrity: original}}}\nsnapshots: {a@1.0.0: {}}\n")
	sum := sha256.Sum256(data)
	doc, err := ParsePNPMLock(data)
	if err != nil {
		t.Fatal(err)
	}
	for i := range data {
		data[i] = 'x'
	}
	p, err := ProjectPNPMLock(doc)
	if err != nil || p.SourceSHA256 != sum || doc.SHA256 != sum || p.Records[0].Integrity.Value != "original" {
		t.Fatalf("ownership: %+v %v", p, err)
	}
	p.Records[0].Integrity.Value = "mutated"
	p2, _ := ProjectPNPMLock(doc)
	if p2.Records[0].Integrity.Value != "original" {
		t.Fatal("projection shares mutable storage")
	}
	commented, _ := ParsePNPMLock([]byte(pnpmEmpty + "# comment\n"))
	plain, _ := ParsePNPMLock([]byte(pnpmEmpty))
	if commented.SHA256 == plain.SHA256 {
		t.Fatal("digest is not over original bytes")
	}
	doc.SHA256[0] ^= 1
	for _, forged := range []PNPMLockDocument{{}, {SHA256: sum}, doc} {
		if _, err := ProjectPNPMLock(forged); err == nil {
			t.Fatal("forged document accepted")
		}
	}
}

func TestParsePNPMLockBudgets(t *testing.T) {
	pnpmParseCode(t, strings.Repeat(" ", (1<<20)+1), "limit-exceeded")
	// Exactly the raw ceiling is accepted, including comments.
	data := pnpmEmpty + "#" + strings.Repeat("x", (1<<20)-len(pnpmEmpty)-2) + "\n"
	if _, err := ParsePNPMLock([]byte(data)); err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{65536, 65537} {
		_, err := ParsePNPMLock([]byte(pnpmEmpty + "unknown: '" + strings.Repeat("a", n) + "'\n"))
		if (err != nil) != (n > 65536) {
			t.Fatalf("scalar bound %d: %v", n, err)
		}
	}
	pnpmParseCode(t, pnpmEmpty+"unknown: "+strings.Repeat("[", 65)+"x"+strings.Repeat("]", 65), "limit-exceeded")
	pnpmParseCode(t, pnpmEmpty+"unknown: ["+strings.Repeat("x,", 100000)+"]", "limit-exceeded")
	var b strings.Builder
	b.WriteString(pnpmEmpty + "packages:\n")
	for i := 0; i < 20000; i++ {
		fmt.Fprintf(&b, "  a%d@1.0.0: {}\n", i)
	}
	pnpmParseCode(t, b.String(), "limit-exceeded") // Includes the root importer.
}

func TestParsePNPMLockExactNodeAndDepthBounds(t *testing.T) {
	for _, n := range []int{99990, 99991} {
		input := pnpmEmpty + "unknown: [" + strings.Repeat("x,", n) + "]\n"
		_, err := ParsePNPMLock([]byte(input))
		if (err != nil) != (n > 99990) {
			t.Fatalf("node bound %d: %v", n, err)
		}
	}
	for _, depth := range []int{62, 63} {
		input := pnpmEmpty + "unknown: " + strings.Repeat("[", depth) + "x" + strings.Repeat("]", depth)
		_, err := ParsePNPMLock([]byte(input))
		if (err != nil) != (depth > 62) {
			t.Fatalf("depth bound %d: %v", depth, err)
		}
	}
	// The vendored decoder must also reject beyond its own recursion cap safely.
	pnpmParseCode(t, pnpmEmpty+"unknown: "+strings.Repeat("[", 10001)+"x"+strings.Repeat("]", 10001), "invalid-yaml")
}

func FuzzParsePNPMLock(f *testing.F) {
	for _, input := range []string{pnpmEmpty, pnpmEmpty + "unknown: ! x\n", pnpmEmpty + "packages: {a@1.0.0: {}}\nsnapshots: {a@1.0.0(peer@2.0.0): {}}\n", pnpmEmpty + "unknown: &a [*a]\n"} {
		f.Add([]byte(input))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		doc, err := ParsePNPMLock(data)
		if err != nil {
			var pe *ParseError
			if !errors.As(err, &pe) || err.Error() != "inventory: "+pe.Code {
				t.Fatal("unsafe error")
			}
			return
		}
		p, err := ProjectPNPMLock(doc)
		if err != nil {
			t.Fatal(err)
		}
		if p.SourceSHA256 != sha256.Sum256(data) {
			t.Fatal("digest mismatch")
		}
		p2, err := ProjectPNPMLock(doc)
		if err != nil || !reflect.DeepEqual(p, p2) {
			t.Fatal("unstable projection")
		}
	})
}

func TestProjectPNPMLockRealCorpus(t *testing.T) {
	data, err := os.ReadFile("../projectinventory/testdata/producer/pnpm-v9.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Captures []struct {
			Producer, Case string
			Expected       struct {
				LockedPackageMetadata, SnapshotContexts int
				ImporterLocations, ParentPeerContexts   []string
			}
			Entries []struct{ Path, Data, SHA256 string }
		}
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Captures) != 6 {
		t.Fatal("missing producer captures")
	}
	for _, capture := range corpus.Captures {
		t.Run(capture.Producer+"/"+capture.Case, func(t *testing.T) {
			for _, entry := range capture.Entries {
				if entry.Path != "pnpm-lock.yaml" {
					continue
				}
				doc, err := ParsePNPMLock([]byte(entry.Data))
				if err != nil {
					t.Fatal(err)
				}
				if hex.EncodeToString(doc.SHA256[:]) != entry.SHA256 {
					t.Fatal("capture digest mismatch")
				}
				p, err := ProjectPNPMLock(doc)
				if err != nil {
					t.Fatal(err)
				}
				if len(p.Records) != capture.Expected.SnapshotContexts {
					t.Fatalf("records %d", len(p.Records))
				}
				var locations []string
				for _, importer := range p.Importers {
					locations = append(locations, importer.Location)
				}
				if !reflect.DeepEqual(locations, capture.Expected.ImporterLocations) {
					t.Fatalf("importers: %v", locations)
				}
				packages := map[string]bool{}
				snapshots := map[string]bool{}
				for _, r := range p.Records {
					packages[r.PackageKey] = true
					snapshots[r.SnapshotKey] = true
					if r.Name.State != FieldValue || r.Version.State != FieldValue || r.Integrity.State != FieldValue {
						t.Fatalf("lost metadata: %+v", r)
					}
				}
				if len(packages) != capture.Expected.LockedPackageMetadata {
					t.Fatal("lost package metadata")
				}
				for _, key := range capture.Expected.ParentPeerContexts {
					if !snapshots[key] {
						t.Fatal("lost peer context")
					}
				}
			}
		})
	}
}
