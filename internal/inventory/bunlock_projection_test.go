package inventory

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func bunVal(s string) LockField[string] { return LockField[string]{State: FieldValue, Value: s} }

func bunState(s FieldState) LockField[string] { return LockField[string]{State: s} }

func TestSplitBunResolution(t *testing.T) {
	tests := []struct {
		name           string
		first          LockField[string]
		wantName, want LockField[string]
	}{
		{"plain", bunVal("pkg@1.0.0"), bunVal("pkg"), bunVal("1.0.0")},
		{"scoped", bunVal("@scope/pkg@1.0.0"), bunVal("@scope/pkg"), bunVal("1.0.0")},
		{"git with at", bunVal("pkg@git+ssh://git@github.com/o/r#abc"), bunVal("pkg"), bunVal("git+ssh://git@github.com/o/r#abc")},
		{"root", bunVal("@root:"), bunVal(""), bunVal("root:")},
		{"named root", bunVal("app@root:"), bunVal("app"), bunVal("root:")},
		{"empty resolution", bunVal("pkg@"), bunState(FieldInvalidType), bunState(FieldInvalidType)},
		{"no at", bunVal("pkg"), bunState(FieldInvalidType), bunState(FieldInvalidType)},
		{"scope only", bunVal("@scope/pkg"), bunState(FieldInvalidType), bunState(FieldInvalidType)},
		{"empty string", bunVal(""), bunState(FieldInvalidType), bunState(FieldInvalidType)},
		{"lone at", bunVal("@"), bunState(FieldInvalidType), bunState(FieldInvalidType)},
		{"absent", bunState(FieldAbsent), bunState(FieldAbsent), bunState(FieldAbsent)},
		{"null", bunState(FieldNull), bunState(FieldNull), bunState(FieldNull)},
		{"invalid type", bunState(FieldInvalidType), bunState(FieldInvalidType), bunState(FieldInvalidType)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, res := splitBunResolution(tt.first)
			if name != tt.wantName || res != tt.want {
				t.Fatalf("got (%+v, %+v), want (%+v, %+v)", name, res, tt.wantName, tt.want)
			}
		})
	}
}

func TestClassifyBunTuple(t *testing.T) {
	const obj, str = `{}`, `"s"`
	tests := []struct {
		name       string
		resolution string
		rest       []string
		want       BunResolutionKind
	}{
		{"npm", "1.0.0", []string{str, obj, str}, BunKindNPM},
		{"npm empty registry", "1.0.0", []string{`""`, obj, `""`}, BunKindNPM},
		{"npm non-string registry", "1.0.0", []string{`1`, obj, str}, BunKindUnknown},
		{"npm null registry", "1.0.0", []string{`null`, obj, str}, BunKindUnknown},
		{"npm non-object info", "1.0.0", []string{str, str, str}, BunKindUnknown},
		{"npm missing integrity", "1.0.0", []string{str, obj}, BunKindUnknown},
		{"npm non-string integrity", "1.0.0", []string{str, obj, obj}, BunKindUnknown},
		{"npm extra element", "1.0.0", []string{str, obj, str, str}, BunKindUnknown},
		{"npm no rest", "1.0.0", nil, BunKindUnknown},
		{"unrecognized form", "catalog:", []string{obj}, BunKindUnknown},
		{"git with integrity", "git+https://h/r.git#abc", []string{obj, str, str}, BunKindGit},
		{"git without integrity", "git+https://h/r.git#abc", []string{obj, str}, BunKindGit},
		{"git missing tag", "git+https://h/r.git#abc", []string{obj}, BunKindUnknown},
		{"git non-string integrity", "git+https://h/r.git#abc", []string{obj, str, obj}, BunKindUnknown},
		{"git extra", "git+https://h/r.git#abc", []string{obj, str, str, str}, BunKindUnknown},
		{"git ssh with at", "git+ssh://git@github.com/o/r#abc", []string{obj, str}, BunKindGit},
		{"github with integrity", "github:o/r#abc", []string{obj, str, str}, BunKindGitHub},
		{"github without integrity", "github:o/r#abc", []string{obj, str}, BunKindGitHub},
		{"github non-object info", "github:o/r#abc", []string{str, str}, BunKindUnknown},
		{"tarball https", "https://h/p.tgz", []string{obj, str}, BunKindTarball},
		{"tarball http no integrity", "http://h/p", []string{obj}, BunKindTarball},
		{"tarball upper scheme", "HTTPS://x/y", []string{obj}, BunKindTarball},
		{"tarball upper suffix", "./a.TAR.GZ", []string{obj, str}, BunKindTarball},
		{"tarball tgz path", "./a.tgz", []string{obj}, BunKindTarball},
		{"tarball tar path", "./a.tar", []string{obj}, BunKindTarball},
		{"tarball non-string integrity", "https://h/p", []string{obj, obj}, BunKindUnknown},
		{"tarball extra", "https://h/p", []string{obj, str, str}, BunKindUnknown},
		{"tarball no info", "https://h/p", nil, BunKindUnknown},
		{"folder", "file:./d", []string{obj}, BunKindFolder},
		{"folder tgz", "file:x.tgz", []string{obj}, BunKindFolder},
		{"folder extra", "file:./d", []string{obj, str}, BunKindUnknown},
		{"folder no info", "file:./d", nil, BunKindUnknown},
		{"link", "link:p", []string{obj}, BunKindLink},
		{"link non-object", "link:p", []string{str}, BunKindUnknown},
		{"link none", "link:p", nil, BunKindUnknown},
		{"workspace bare", "workspace:p", nil, BunKindWorkspace},
		{"workspace info", "workspace:p", []string{obj}, BunKindWorkspace},
		{"workspace non-object", "workspace:p", []string{str}, BunKindUnknown},
		{"workspace extra", "workspace:p", []string{obj, obj}, BunKindUnknown},
		{"root", "root:", []string{obj}, BunKindRoot},
		{"root none", "root:", nil, BunKindUnknown},
		{"root non-object", "root:", []string{str}, BunKindUnknown},
		{"root prefix only is not root", "root:x", []string{obj}, BunKindUnknown},
		{"npm null info", "1.0.0", []string{str, `null`, str}, BunKindUnknown},
		{"git null info", "git+https://h/r.git#abc", []string{`null`, str}, BunKindUnknown},
		{"tarball null info", "https://h/p", []string{`null`}, BunKindUnknown},
		{"link null info", "link:p", []string{`null`}, BunKindUnknown},
		{"workspace null info", "workspace:p", []string{`null`}, BunKindUnknown},
		{"root null object", "root:", []string{`null`}, BunKindUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rest []json.RawMessage
			for _, r := range tt.rest {
				rest = append(rest, json.RawMessage(r))
			}
			if got := classifyBunTuple(tt.resolution, rest); got != tt.want {
				t.Fatalf("got %d, want %d", got, tt.want)
			}
		})
	}
}

func parseBunProjectionInput(t *testing.T, src string) BunLockDocument {
	t.Helper()
	doc, err := ParseBunLock([]byte(src))
	if err != nil {
		t.Fatal("invalid synthetic fixture", err)
	}
	return doc
}

func bunRecordByKey(t *testing.T, records []BunLockedRecord, key string) BunLockedRecord {
	t.Helper()
	for _, record := range records {
		if record.Key == key {
			return record
		}
	}
	t.Fatalf("record %q missing", key)
	return BunLockedRecord{}
}

func TestProjectBunLockKinds(t *testing.T) {
	const fixture = `{"lockfileVersion":1,"workspaces":{"":{"name":"app"}},"packages":{
"npm":["npm@1.0.0","https://registry.example.invalid/",{"dependencies":{"x":"^1"}},"sha512-npm"],
"npm-default":["@s/npm@2.0.0","",{},"sha512-def"],
"git":["git@git+ssh://git@github.com/o/r#abc",{"a":1},"bun-tag","sha512-git"],
"git-noint":["gitn@git+https://h/r.git#abc",{},"bun-tag"],
"gh":["gh@github:o/r#abc",{},"gh-tag","sha512-gh"],
"gh-noint":["ghn@github:o/r#abc",{},"gh-tag"],
"tar-remote":["tr@https://h/p.tgz",{"k":true},"sha512-tar"],
"tar-noint":["trn@HTTPS://x/y",{}],
"tar-local":["tl@./a.TAR.GZ",{},"sha512-local"],
"folder":["f@file:./d",{"f":1}],
"folder-tgz":["ft@file:x.tgz",{}],
"link":["l@link:packages/l",{"l":1}],
"ws":["w@workspace:packages/w"],
"ws-info":["wi@workspace:packages/wi",{"w":1}],
"root":["@root:",{"bin":"b"}]
}}`
	doc := parseBunProjectionInput(t, fixture)
	got, err := ProjectBunLock(doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.SourceSHA256 != sha256.Sum256([]byte(fixture)) {
		t.Fatal("source digest lost")
	}
	if len(got.Records) != 15 {
		t.Fatalf("got %d records", len(got.Records))
	}
	absent := bunState(FieldAbsent)
	tests := []struct {
		key                      string
		kind                     BunResolutionKind
		name, resolution         LockField[string]
		registry, integrity, tag LockField[string]
		info                     string
	}{
		{"npm", BunKindNPM, bunVal("npm"), bunVal("1.0.0"), bunVal("https://registry.example.invalid/"), bunVal("sha512-npm"), absent, `{"dependencies":{"x":"^1"}}`},
		{"npm-default", BunKindNPM, bunVal("@s/npm"), bunVal("2.0.0"), bunVal(""), bunVal("sha512-def"), absent, `{}`},
		{"git", BunKindGit, bunVal("git"), bunVal("git+ssh://git@github.com/o/r#abc"), absent, bunVal("sha512-git"), bunVal("bun-tag"), `{"a":1}`},
		{"git-noint", BunKindGit, bunVal("gitn"), bunVal("git+https://h/r.git#abc"), absent, absent, bunVal("bun-tag"), `{}`},
		{"gh", BunKindGitHub, bunVal("gh"), bunVal("github:o/r#abc"), absent, bunVal("sha512-gh"), bunVal("gh-tag"), `{}`},
		{"gh-noint", BunKindGitHub, bunVal("ghn"), bunVal("github:o/r#abc"), absent, absent, bunVal("gh-tag"), `{}`},
		{"tar-remote", BunKindTarball, bunVal("tr"), bunVal("https://h/p.tgz"), absent, bunVal("sha512-tar"), absent, `{"k":true}`},
		{"tar-noint", BunKindTarball, bunVal("trn"), bunVal("HTTPS://x/y"), absent, absent, absent, `{}`},
		{"tar-local", BunKindTarball, bunVal("tl"), bunVal("./a.TAR.GZ"), absent, bunVal("sha512-local"), absent, `{}`},
		{"folder", BunKindFolder, bunVal("f"), bunVal("file:./d"), absent, absent, absent, `{"f":1}`},
		{"folder-tgz", BunKindFolder, bunVal("ft"), bunVal("file:x.tgz"), absent, absent, absent, `{}`},
		{"link", BunKindLink, bunVal("l"), bunVal("link:packages/l"), absent, absent, absent, `{"l":1}`},
		{"ws", BunKindWorkspace, bunVal("w"), bunVal("workspace:packages/w"), absent, absent, absent, ``},
		{"ws-info", BunKindWorkspace, bunVal("wi"), bunVal("workspace:packages/wi"), absent, absent, absent, `{"w":1}`},
		{"root", BunKindRoot, bunVal(""), bunVal("root:"), absent, absent, absent, `{"bin":"b"}`},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			r := bunRecordByKey(t, got.Records, tt.key)
			want := BunLockedRecord{Key: tt.key, Kind: tt.kind, Name: tt.name, Resolution: tt.resolution,
				Registry: tt.registry, Integrity: tt.integrity, GitTag: tt.tag}
			if tt.info != "" {
				want.Info = json.RawMessage(tt.info)
			}
			if !reflect.DeepEqual(r, want) {
				t.Fatalf("got %+v, want %+v", r, want)
			}
		})
	}
}

func TestProjectBunLockUnknownAndSplitFailures(t *testing.T) {
	const fixture = `{"lockfileVersion":1,"workspaces":{},"packages":{
"empty":[],
"null-first":[null,{}],
"num-first":[7,{}],
"no-at":["pkg",{}],
"empty-res":["pkg@",{}],
"empty-string":["",{}],
"bad-registry":["p@1.0.0",1,{},"sha"],
"no-integrity":["p@1.0.0","",{}],
"extra":["p@1.0.0","",{},"sha","more"],
"git-no-tag":["p@git+https://h/r#a",{}],
"link-str":["p@link:x","s"],
"catalog":["p@catalog:",{}],
"empty-values":["p@1.0.0","",{},""]
}}`
	got, err := ProjectBunLock(parseBunProjectionInput(t, fixture))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		key              string
		name, resolution LockField[string]
	}{
		{"empty", bunState(FieldAbsent), bunState(FieldAbsent)},
		{"null-first", bunState(FieldNull), bunState(FieldNull)},
		{"num-first", bunState(FieldInvalidType), bunState(FieldInvalidType)},
		{"no-at", bunState(FieldInvalidType), bunState(FieldInvalidType)},
		{"empty-res", bunState(FieldInvalidType), bunState(FieldInvalidType)},
		{"empty-string", bunState(FieldInvalidType), bunState(FieldInvalidType)},
		{"bad-registry", bunVal("p"), bunVal("1.0.0")},
		{"no-integrity", bunVal("p"), bunVal("1.0.0")},
		{"extra", bunVal("p"), bunVal("1.0.0")},
		{"git-no-tag", bunVal("p"), bunVal("git+https://h/r#a")},
		{"link-str", bunVal("p"), bunVal("link:x")},
		{"catalog", bunVal("p"), bunVal("catalog:")},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			want := BunLockedRecord{Key: tt.key, Name: tt.name, Resolution: tt.resolution}
			if r := bunRecordByKey(t, got.Records, tt.key); !reflect.DeepEqual(r, want) {
				t.Fatalf("got %+v, want %+v", r, want)
			}
		})
	}
	values := bunRecordByKey(t, got.Records, "empty-values")
	if values.Kind != BunKindNPM || values.Registry != bunVal("") || values.Integrity != bunVal("") {
		t.Fatalf("empty strings must be values: %+v", values)
	}
}

func TestProjectBunLockOrderAndEvidence(t *testing.T) {
	const fixture = `{"lockfileVersion":1,"workspaces":{},"packages":{
"z/a":["same@1.0.0","",{"k":"v"},"sha-z"],
"a":["same@1.0.0","",{"k":"v"},"sha-a"],
"":["@root:",{"bin":"x"}],
"B":["other@2.0.0","",{},"sha-b"]
}}`
	doc := parseBunProjectionInput(t, fixture)
	before, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ProjectBunLock(doc)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, r := range got.Records {
		keys = append(keys, r.Key)
	}
	if !reflect.DeepEqual(keys, []string{"", "B", "a", "z/a"}) {
		t.Fatalf("records must be sorted by Go string order of Key: %q", keys)
	}
	if got.Records[2].Name != got.Records[3].Name || got.Records[2].Integrity == got.Records[3].Integrity {
		t.Fatal("repeated names under different keys must stay separate records")
	}
	after, err := json.Marshal(doc)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("projection modified raw evidence")
	}
	projectionBefore, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range doc.Packages {
		for i := range raw {
			raw[i] = 'X'
		}
	}
	doc.Packages["a"] = json.RawMessage(`["changed"]`)
	delete(doc.Packages, "B")
	doc.SHA256[0] ^= 0xff
	projectionAfter, err := json.Marshal(got)
	if err != nil || !bytes.Equal(projectionBefore, projectionAfter) {
		t.Fatal("returned projection aliases input data")
	}
	if string(got.Records[0].Info) != `{"bin":"x"}` || string(got.Records[2].Info) != `{"k":"v"}` {
		t.Fatal("Info must be copied unchanged")
	}
}

func TestProjectBunLockGuards(t *testing.T) {
	array := json.RawMessage(`["a@1.0.0"]`)
	tests := []struct {
		name string
		doc  BunLockDocument
	}{
		{"nil fields", BunLockDocument{Packages: map[string]json.RawMessage{}}},
		{"nil packages", BunLockDocument{Fields: map[string]json.RawMessage{}}},
		{"nil entry", BunLockDocument{Fields: map[string]json.RawMessage{}, Packages: map[string]json.RawMessage{"a": nil}}},
		{"object entry", BunLockDocument{Fields: map[string]json.RawMessage{}, Packages: map[string]json.RawMessage{"a": json.RawMessage(`{}`)}}},
		{"scalar entry", BunLockDocument{Fields: map[string]json.RawMessage{}, Packages: map[string]json.RawMessage{"a": json.RawMessage(`"s"`)}}},
		{"null entry", BunLockDocument{Fields: map[string]json.RawMessage{}, Packages: map[string]json.RawMessage{"a": json.RawMessage(`null`)}}},
		{"mixed entries", BunLockDocument{Fields: map[string]json.RawMessage{}, Packages: map[string]json.RawMessage{"a": array, "b": json.RawMessage(`1`)}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertBunProjectionError(t, tt.doc, "invalid-shape")
		})
	}
}

func TestProjectBunLockEmptyPackages(t *testing.T) {
	got, err := ProjectBunLock(parseBunProjectionInput(t, `{"lockfileVersion":1,"workspaces":{},"packages":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	if got.Records == nil || len(got.Records) != 0 {
		t.Fatal("empty packages must return an empty non-nil slice")
	}
}

func TestProjectBunLockRecordBound(t *testing.T) {
	build := func(n int) BunLockDocument {
		packages := make(map[string]json.RawMessage, n)
		for i := range n {
			packages[fmt.Sprintf("p%05d", i)] = json.RawMessage(`["a@1.0.0","",{},"sha"]`)
		}
		return BunLockDocument{Fields: map[string]json.RawMessage{}, Packages: packages}
	}
	got, err := ProjectBunLock(build(maxProjectedRecords))
	if err != nil || len(got.Records) != maxProjectedRecords {
		t.Fatal("exact bound must succeed without truncation")
	}
	assertBunProjectionError(t, build(maxProjectedRecords+1), "limit-exceeded")
}

func assertBunProjectionError(t *testing.T, doc BunLockDocument, code string) {
	t.Helper()
	got, err := ProjectBunLock(doc)
	var parsed *ParseError
	if !errors.As(err, &parsed) || parsed.Code != code {
		t.Fatalf("got error %v, want %s", err, code)
	}
	if got.Records != nil || got.SourceSHA256 != ([32]byte{}) {
		t.Fatal("failure must return a zero projection")
	}
}
