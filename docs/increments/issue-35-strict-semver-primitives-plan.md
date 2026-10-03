# Issue 35 Strict SemVer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development for the agreed multi-agent method, or superpowers:executing-plans only if the owner changes that method. Steps use checkbox tracking. No agent or implementation execution is authorized by this draft.

**Goal:** Build one bounded strict concrete-SemVer parser and precedence comparator.

**Architecture:** I keep an opaque immutable value in the existing internal intel package. Canonical digit strings supply arbitrary-size numeric order; iterative ASCII identifier checks avoid normalization and recursive work. I reuse the existing private error type and change no consumer or shared reader.

**Tech Stack:** Go 1.27.1 baseline; standard library only; no downloads or go.sum.

**Spec:** [approved #35 specification](issue-35-strict-semver-primitives.md), approved local commit `6aedaa99558f1d562bd50d2bd01868d2e9bdfbd0`.

Status: **draft plan; approval/execution/publication pending**. The user approved the written specification and local plan drafting only. My base is integrated `76ef90daf36c4b4fae2b234369859108440fc24e`; this issue's workspace/bookmark is independent of #23. I have not compiled or executed any fragment below.

## Global constraints

- Exactly 1 MiB = 1,048,576 bytes per decoded text; byte guard before scanning/copying/decomposition; whole-zero private error on rejection.
- No integer-magnitude ceiling, trim, prefix cleaning, coercion, normalization, declaration resolution, event sentinels, range/list/OR evaluation or matching.
- Success owns exact text; private component views share that bounded owned text. Build metadata remains in Text but not precedence.
- Compare only qualified values; zero/failed parse is not equality. Return -1/0/+1 only with nil error.
- Allowed errors: existing `*ParseError`, fixed `intel: invalid-semver`, `intel: limit-exceeded`, `intel: invalid-shape`; never payload disclosure.
- Only two new Go files. Shared error/readers/projections/module/design/milestones and the other lane remain unchanged.
- No targets, package managers, optional candidate probes, dependencies/toolchains, native/producer/pilot/release claims or CI execution.
- Source snippets are documentary until separately authorized; syntax checks do not compile or establish behavior.

## Review focus

1. Numeric-looking nonnumeric prerelease identifiers such as `001x` must not be rejected or compared numerically.
2. Large canonical digits, release/prerelease order and late equal-prefix identifier sequences must retain exact mathematical order without machine conversion.
3. Exact 1 MiB / +1 and malformed oversized input must respect byte-first limits, not grammar-dependent resource work.
4. Zero operands, copied values and exact differing build spellings must preserve qualification and immutable source text.
5. Late malformed private markers must produce whole-zero fixed errors, not partial values, raw details or no-match.

## One independently reviewable task: primitives and independent tests

**Create:** `internal/intel/semver.go`, `internal/intel/semver_test.go`.

**Consumes:** unchanged `type ParseError struct{ Code string }` and its fixed prefix method; #15 S01–S34/O01–O16 and #35 P01–P26 as authored references, not runtime Markdown.

**Produces:** exactly `type SemVer` with private `text string`, `core [3]string`, `prerelease string`, `qualified bool`; `ParseSemVer(string) (SemVer,error)`; `(SemVer).Text() string`; `CompareSemVer(SemVer,SemVer) (int,error)`.

- [ ] **Step 1 — Revalidate authority/base/scope.** I inspect live ownership/PRs, approved spec, this complete plan and explicit execution permission before writing Go. The coordinator alone controls GitHub, jj and publication. I record unchanged shared-source fingerprints and run fresh owned offline baseline tests/vet only when authorized. The earlier integrated 2,709 count is history, not this future baseline result.
- [ ] **Step 2 — Write the complete initial independent tests first.** I use the following file, with literal expected outcomes and all source IDs. I do not print input/error payloads or infer expectations from production helpers.

```go
package intel

import (
	"errors"
	"strings"
	"testing"
)

func semverTestError(t *testing.T, err error, code string) {
	t.Helper()
	var e *ParseError
	if !errors.As(err, &e) || e.Code != code || err.Error() != "intel: "+code {
		t.Fatal("wrong fixed private error")
	}
}

func semverTestValue(t *testing.T, text string) SemVer {
	t.Helper()
	v, err := ParseSemVer(text)
	if err != nil || !v.qualified || v.Text() != text {
		t.Fatal("expected exact qualified value")
	}
	return v
}

func TestSemVerSyntax(t *testing.T) {
	cases := []struct{ id, text string; valid bool }{
		{"S01", "0.0.0", true}, {"S02", "1.2.3", true},
		{"S03", "1.2.3-alpha.1", true}, {"S04", "1.2.3-0", true},
		{"S05", "1.2.3-001x", true}, {"S06", "1.2.3--", true},
		{"S07", "1.2.3-Alpha", true}, {"S08", "1.2.3+001", true},
		{"S09", "1.2.3-alpha.1+build.001", true},
		{"S10", "18446744073709551616.0.0", true},
		{"S11", "1.0.0-18446744073709551616", true},
		{"S12", "", false}, {"S13", "0", false}, {"S14", "1.2", false},
		{"S15", "1.2.3.4", false}, {"S16", "01.2.3", false},
		{"S17", "1.02.3", false}, {"S18", "1.2.03", false},
		{"S19", "1.2.3-01", false}, {"S20", "1.2.3-alpha..1", false},
		{"S21", "1.2.3-", false}, {"S22", "1.2.3+", false},
		{"S23", "1.2.3+build..1", false}, {"S24", "1.2.3+one+two", false},
		{"S25", "v1.2.3", false}, {"S26", "=1.2.3", false},
		{"S27", " 1.2.3", false}, {"S28", "1.2.3\n", false},
		{"S29", "1.2.3-α", false}, {"S30", "1.2.3_alpha", false},
		{"S31", "^1.2.0", false}, {"S32", "*", false},
		{"S33", "-1.2.3", false}, {"S34", "1e2.0.0", false},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			if tc.valid { semverTestValue(t, tc.text); return }
			v, err := ParseSemVer(tc.text)
			semverTestError(t, err, "invalid-semver")
			if v != (SemVer{}) { t.Fatal("nonzero rejection") }
		})
	}
}

func TestSemVerPrecedence(t *testing.T) {
	cases := []struct{ id, left, right string; order int }{
		{"O01", "1.9.0", "1.10.0", -1}, {"O02", "2.0.0", "1.99.99", 1},
		{"O03", "1.0.0-alpha", "1.0.0-alpha.1", -1},
		{"O04", "1.0.0-alpha.1", "1.0.0-alpha.beta", -1},
		{"O05", "1.0.0-alpha.beta", "1.0.0-beta", -1},
		{"O06", "1.0.0-beta.2", "1.0.0-beta.11", -1},
		{"O07", "1.0.0-rc.1", "1.0.0", -1}, {"O08", "1.0.0-1", "1.0.0-alpha", -1},
		{"O09", "1.0.0-A", "1.0.0-a", -1}, {"O10", "1.0.0+one", "1.0.0+two", 0},
		{"O11", "1.0.0-alpha+001", "1.0.0-alpha", 0},
		{"O12", "18446744073709551615.0.0", "18446744073709551616.0.0", -1},
		{"O13", "1.0.0-18446744073709551615", "1.0.0-18446744073709551616", -1},
		{"O14", "1.0.0", "1.0.0", 0},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			a, b := semverTestValue(t, tc.left), semverTestValue(t, tc.right)
			n, err := CompareSemVer(a, b)
			if err != nil || n != tc.order { t.Fatal("wrong reference precedence") }
			if a.Text() != tc.left || b.Text() != tc.right { t.Fatal("source text changed") }
		})
	}
	t.Run("O15", func(t *testing.T) {
		v, err := ParseSemVer("v1.0.0"); semverTestError(t, err, "invalid-semver")
		if v != (SemVer{}) { t.Fatal("nonzero rejected spelling") }
		n, err := CompareSemVer(v, semverTestValue(t, "1.0.0"))
		semverTestError(t, err, "invalid-shape"); if n != 0 { t.Fatal("ordering on rejection") }
	})
	t.Run("O16", func(t *testing.T) {
		// Null/unavailable stays with the caller; no string coercion.
		n, err := CompareSemVer(SemVer{}, semverTestValue(t, "1.0.0"))
		semverTestError(t, err, "invalid-shape"); if n != 0 { t.Fatal("ordering unavailable evidence") }
	})
}

func TestSemVerBoundaries(t *testing.T) {
	cases := []struct{ id, text, code string }{
		{"P01", strings.Repeat("1", 1048572)+".0.0", ""},
		{"P02", strings.Repeat("1", 1048573)+".0.0", "limit-exceeded"},
		{"P03", "1.0.0-"+strings.Repeat("1", 1048570), ""},
		{"P04", "1.0.0+"+strings.Repeat("0", 1048570), ""},
		{"P05", strings.Repeat("!", 1048577), "limit-exceeded"},
		{"P06", strings.Repeat("1", 1048571)+".0.0", ""},
		{"P08", "1.0.0-a-b", ""}, {"P09", "1.0.0+001.000", ""},
		{"P10", "1.0.0-0.1", ""}, {"P11", "1.0.0-00", "invalid-semver"},
		{"P12", "1.0.0\x00", "invalid-semver"},
		{"P13", string([]byte{0x31,0x2e,0x30,0x2e,0x30,0x2d,0xff}), "invalid-semver"},
		{"P14", "１.0.0", "invalid-semver"},
		{"P15-extra-plus", "1.0.0++", "invalid-semver"},
		{"P15-empty-pre", "1.0.0-+x", "invalid-semver"},
		{"P24", "1.0.0-private-marker!", "invalid-semver"},
		{"P25", "1.0.0-"+strings.Repeat("a.", 524284)+"a", ""},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			if tc.code == "" { semverTestValue(t, tc.text); return }
			v, err := ParseSemVer(tc.text); semverTestError(t, err, tc.code)
			if v != (SemVer{}) { t.Fatal("partial rejected value") }
		})
	}
	pairs := []struct{ id, left, right string; order int }{
		{"P07", strings.Repeat("1",1048571)+".0.0", strings.Repeat("1",1048572)+".0.0", -1},
		{"P16", "1.0.0-x+build", "1.0.0-x+other", 0},
		{"P17", "1.0.0-001x", "1.0.0-1", 1},
		{"P18", "1.0.0--", "1.0.0-0", 1},
		{"P19", "1.0.0-a.1", "1.0.0-a.1.0", -1},
		{"P26", "1.0.0-"+strings.Repeat("a.",524284)+"a", "1.0.0-"+strings.Repeat("a.",524283)+"a", 1},
	}
	for _, tc := range pairs {
		t.Run(tc.id, func(t *testing.T) {
			a,b := semverTestValue(t,tc.left),semverTestValue(t,tc.right)
			n,err := CompareSemVer(a,b); if err != nil || n != tc.order { t.Fatal("wrong boundary precedence") }
			if a.Text()!=tc.left || b.Text()!=tc.right { t.Fatal("changed boundary text") }
		})
	}
	t.Run("P20",func(t *testing.T) {
		v:=semverTestValue(t,"0.0.0")
		for _,p:=range [][2]SemVer{{{},v},{v,{}},{{},{}}} {
			n,err:=CompareSemVer(p[0],p[1]); semverTestError(t,err,"invalid-shape")
			if n!=0 { t.Fatal("ordering unqualified operand") }
		}
	})
	t.Run("P21",func(t *testing.T) { if (SemVer{}).Text()!="" { t.Fatal("invented zero text") } })
	t.Run("P22",func(t *testing.T) {
		source:="1.0.0-alpha+original"; original:=semverTestValue(t,source); copied:=original
		source="different"; original=SemVer{}
		if source==copied.Text() || original.qualified || copied.Text()!="1.0.0-alpha+original" { t.Fatal("copy text lost") }
		n,err:=CompareSemVer(copied,semverTestValue(t,"1.0.0-alpha+original"))
		if err!=nil || n!=0 { t.Fatal("copy qualification lost") }
	})
	t.Run("P23",func(t *testing.T) {
		a,b:=semverTestValue(t,"1.0.0-beta.2"),semverTestValue(t,"1.0.0-beta.11")
		for i:=0;i<3;i++ {
			x:=semverTestValue(t,"1.0.0-beta.2"); if x!=a { t.Fatal("nondeterministic parse") }
			n,e:=CompareSemVer(a,b); r,f:=CompareSemVer(b,a)
			if e!=nil || f!=nil || n!=-1 || r!=1 { t.Fatal("nondeterministic directional order") }
		}
	})
}
```

For P23 I additionally check each successful O row repeatedly and reversed against its literal mathematical opposite (-1/+1 or 0), never against another production result. That augmentation belongs in `TestSemVerPrecedence` immediately after its forward assertion:

```go
for i := 0; i < 3; i++ {
	r, e := CompareSemVer(b, a)
	if e != nil || r != -tc.order { t.Fatal("wrong reversed reference") }
	fresh := semverTestValue(t, tc.left)
	if fresh != a { t.Fatal("unstable qualified value") }
}
```

- [ ] **Step 3 — Observe API compilation RED.** I run the focused offline test command below, inspect JSON build-output and stderr, and record missing `SemVer`/`ParseSemVer`/`CompareSemVer` API diagnostics. I do not count build failure as behavioral RED.
- [ ] **Step 4 — Add the exact shape and deliberately failing stub; observe behavioral RED.** I copy the approved struct declaration and these bodies into the production file. I fix test-only compilation mistakes before interpreting runtime failures; I record actual failed/passed reference IDs, not an invented universal count.

```go
func ParseSemVer(text string) (SemVer, error) { return SemVer{}, nil }
func (v SemVer) Text() string { return v.text }
func CompareSemVer(left, right SemVer) (int, error) { return 0, nil }
```

- [ ] **Step 5 — Replace the stub with this minimum complete GREEN module.** I preserve its input/output/guard contract; no dependency, extra public type or consumer adapter is added.

```go
package intel

import (
	"cmp"
	"strings"
)

type SemVer struct {
	text string
	core [3]string
	prerelease string
	qualified bool
}

func ParseSemVer(text string) (SemVer, error) {
	if len(text)>1<<20 { return SemVer{}, &ParseError{Code:"limit-exceeded"} }
	main,build,hasBuild:=strings.Cut(text,"+")
	if hasBuild && !semverIdentifiers(build,false) { return SemVer{}, &ParseError{Code:"invalid-semver"} }
	core,pre,hasPre:=strings.Cut(main,"-")
	parts:=strings.SplitN(core,".",4)
	if len(parts)!=3 { return SemVer{}, &ParseError{Code:"invalid-semver"} }
	for _,part:=range parts { if !semverNumeric(part) { return SemVer{}, &ParseError{Code:"invalid-semver"} } }
	if hasPre && !semverIdentifiers(pre,true) { return SemVer{}, &ParseError{Code:"invalid-semver"} }
	owned:=strings.Clone(text)
	main,_,_=strings.Cut(owned,"+"); core,pre,_=strings.Cut(main,"-"); parts=strings.SplitN(core,".",4)
	return SemVer{text:owned,core:[3]string{parts[0],parts[1],parts[2]},prerelease:pre,qualified:true},nil
}

func (v SemVer) Text() string { return v.text }

func semverNumeric(text string) bool {
	if text=="" || len(text)>1 && text[0]=='0' { return false }
	for i:=0;i<len(text);i++ { if text[i]<'0' || text[i]>'9' { return false } }
	return true
}

func semverIdentifiers(text string, prerelease bool) bool {
	for {
		id,rest,more:=strings.Cut(text,"."); if id=="" { return false }
		numeric:=true
		for i:=0;i<len(id);i++ {
			b:=id[i]; digit:=b>='0' && b<='9'
			if !digit && !(b>='A' && b<='Z') && !(b>='a' && b<='z') && b!='-' { return false }
			if !digit { numeric=false }
		}
		if prerelease && numeric && len(id)>1 && id[0]=='0' { return false }
		if !more { return true }; text=rest
	}
}

func semverNumericCompare(left,right string) int {
	if n:=cmp.Compare(len(left),len(right));n!=0 { return n }
	return strings.Compare(left,right)
}

func CompareSemVer(left,right SemVer) (int,error) {
	if !left.qualified || !right.qualified { return 0,&ParseError{Code:"invalid-shape"} }
	for i:=0;i<3;i++ { if n:=semverNumericCompare(left.core[i],right.core[i]);n!=0 { return n,nil } }
	a,b:=left.prerelease,right.prerelease
	if a==b { return 0,nil }; if a=="" { return 1,nil }; if b=="" { return -1,nil }
	for {
		x,ar,am:=strings.Cut(a,"."); y,br,bm:=strings.Cut(b,".")
		xn,yn:=semverNumeric(x),semverNumeric(y)
		if xn && !yn { return -1,nil }; if !xn && yn { return 1,nil }
		n:=strings.Compare(x,y); if xn && yn { n=semverNumericCompare(x,y) }
		if n!=0 { return n,nil }
		if am!=bm { if am { return 1,nil }; return -1,nil }
		if !am { return 0,nil }; a,b=ar,br
	}
}
```

- [ ] **Step 6 — Observe focused/root GREEN and vet.** I format the two Go files, use the owned offline environment and record actual selected tests/subtests from a single stream. I verify every S/O/P ID is represented and all five review classes are exercised. A successful example is not a native/RSS/profile qualification.

```nu
with-env {GOTOOLCHAIN: "local", GOPROXY: "off", GOWORK: "off", CGO_ENABLED: "0"} {
    go test -count=1 -json -run '^TestSemVer' ./internal/intel
}
with-env {GOTOOLCHAIN: "local", GOPROXY: "off", GOWORK: "off", CGO_ENABLED: "0"} {
    go test -count=1 -json ./...
}
with-env {GOTOOLCHAIN: "local", GOPROXY: "off", GOWORK: "off", CGO_ENABLED: "0"} {
    go vet ./...
}
```

- [ ] **Step 7 — Independently mutate, observe and restore.** I fingerprint the approved GREEN source first; apply only one mutant at a time; record actual targeted behavioral failures; restore and verify the fingerprint before the next mutant. I do not leave mutation source active.

| Mutant | Targeted independent discriminator |
| --- | --- |
| Strip/trim/coerce prefixes | S25–S28 and S31–S34 |
| Remove canonical leading-zero check | S16–S19/P11; build S08/P09 must remain valid |
| Compare numeric text lexically regardless of length | O01/O06/O12/O13/P07 |
| Use full text/build for precedence | O10/O11/P16 while retaining exact Text |
| Remove either qualified-operand guard | O16/P20 and rejected O15 |
| Change byte guard to `>=` or omit it | P01–P06; malformed oversized P05 still limit-exceeded |
| Return qualified/partial late rejection or disclose text | P24 and whole-zero fixed error helper |
| Ignore late equal-prefix identifier count | P25/P26 and O03/P19 |

- [ ] **Step 8 — Author/agent review and final checks.** I review the complete branch against the spec, not the initial RED stub. I inspect clone/component ownership, grammar/order, error privacy, base/source fingerprints, no go.sum and exact two-Go-file scope. Any reviewer fixes need observed regression evidence and another restored-source root/vet run. Agent criticism is not independent human GitHub approval.
- [ ] **Step 9 — Scoped local implementation/evidence commits, only if authorized.** I commit just the two Go files with `jj commit -m 'feat(intel): parse strict SemVer (#35)' internal/intel/semver.go internal/intel/semver_test.go` from this workspace. I record actual evidence in the issue documents through a separate scoped docs commit; shared milestone changes require additional approval. No push follows implicitly.
- [ ] **Step 10 — Publication/review handoff is separately gated.** The coordinator obtains explicit authority, pushes only this issue bookmark, reads back exact head/base/files, and separately requests final-head peer review. No merge/closure or sibling synchronization is implied; #6 remains open.

## Preparation verification and handoff

I self-review spec coverage, signatures, all literal IDs, exact arithmetic and five focus classes. Syntax-only Go/Nushell checks are permitted documentary checks; this plan has no compilation, behavioral RED/GREEN, mutation or root/vet execution evidence yet.

The agreed future method is disjoint multi-agent ownership with centralized coordination. I must resolve routing and prevent repeated full-context exploration through a bounded evidence packet before any new workflow is authorized; the earlier post-response token budget is not a spending cap. I request plan review and separate execution/publication authority rather than restart agents or write Go now.
