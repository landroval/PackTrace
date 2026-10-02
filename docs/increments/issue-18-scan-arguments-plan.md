# Issue 18 — pure scan argument requests implementation plan

> **For agentic workers:** use `superpowers:executing-plans` for the already selected inline method, task by task, only after written-plan approval and explicit execution authorization. Checkboxes are future steps, not work already performed. Do not start a subagent workflow or create another workspace by default.

**Goal:** implement and test the approved pure complete-argv request parser, without a command entry point, effective policy or investigation.

**Architecture:** one fixed eight-option lexer in `internal/cli`, using the standard library and scalar request/provenance masks. It returns four invocation intents or private whole-zero errors. Existing exit-selection, inventory and intelligence code remains unchanged.

**Tech stack:** root module `packtrace`, Go floor1.27.1, standard library only. The previously observed development toolchain is `go1.27.1-X:nodwarf5 linux/amd64`, not official/native qualification; record the actual compiler before any approved execution.

**Spec:** [approved issue-18 contract](issue-18-scan-arguments.md), published at `38c9069750edbbe2ac9130b307d0eb6b80e023b8`. That document is the authority for types, grammar, error order and52 reference rows.

## Status and authority

I prepare this **local, unapproved implementation plan** after written-specification/publication approval. I have no authority to publish this plan, create Go source/tests, run the planned tests/mutations, mark ready/request a reviewer, acquire dependencies/targets/corpus, activate native/CI work or merge.

The issue branch originated from integrated development235347cc and does not depend on PR #29. Its single published artifact is the specification. This plan changes no specification semantics; any discovered contract gap must return to specification review instead of being silently decided during implementation.

## Global constraints

- Only eventual new `internal/cli/arguments.go` and `internal/cli/arguments_test.go`; no shared model, existing exit-selector/source, root module, go.sum or probe change.
- Exact API `ParseArgs(args []string) (Invocation, error)`, input excludes executable name; no `os.Args`, stdin/stdout/stderr, process exit, environment, CWD, clock, policy/target/state/output/network access.
- Four nonzero intents: scan, general help, scan help, general version; non-scan whole-zero Scan and fatal whole-zero Invocation.
- Eight exact long options; split/attached values; no aliases/trim/case-fold, repeats or trailing options; exactly one literal PATH.
- Three category bits1/2/4; eight origin bits1/2/4/8/16/32/64/128; preserve explicit values even when equal to defaults. No enum-layout or mask expectation inferred from implementation.
- Requests are not effective policy, manager/producer qualification, safe destinations, coverage completion, findings or execution permission. Default StateDir stays empty/deferred; default stdout request is `-`.
- Error code, zero-based locator and a known option bit only; no raw argv/secret/underlying errors, partial defaults or fallback. Follow all11 fixed code texts and unknown-code fallback in the specification.
- Path bytes remain literal except empty/NUL rejection; category parsing allocates no input-proportional split array; accepted grammar allows at most19 tokens, not an invented arbitrary byte quota/hard-RSS guarantee.
- Existing [exit selector](../../internal/cli/exits.go) remains a separate pure decision. Parsing cannot call it to manufacture scan success.
- Existing workspace/issue bookmark and scoped jj commits; explicit publication permissions and second-person review remain separate. [Engineering](../development-guidelines.md#12-development-and-review-loop) and [collaboration](../github-collaboration.md) apply.

## Review focus

1. Help/version cannot bypass unknown/extra arguments; a terminated literal root `--help` must remain scan data. Pin this in Reference and Boundaries.
2. A missing split value cannot swallow the next option; attached dash-prefixed paths and first-`=` splitting remain literal. Pin this in Options and Boundaries.
3. Explicit default-valued flags must set their own origin bits, not disappear as defaults. Pin each of the eight in Options and Defaults.
4. Relative/Windows/non-UTF-8/control-containing paths must not be normalized, expanded or disclosed in errors; partial valid flags before an error must not leak. Pin this in Boundaries, Privacy and Ownership.
5. Local enforcement-subset checks are not effective-policy validation; explicit policy/local-privacy requests stay unqualified and forged error codes cannot expose values. Pin this in Scope, Privacy and Separation.

## File and interface map

| File | Responsibility |
| --- | --- |
| `internal/cli/arguments.go` (new) | Exact types/constants, fixed private error formatter, lexer/defaults/provenance, category/option validation and fatal zero return |
| `internal/cli/arguments_test.go` (new) | Independent literal reference/option/boundary/ownership/privacy/separation expectations; no target/native fixtures |
| `docs/increments/issue-18-scan-arguments.md` | Approved unchanged contract during code/test execution; completion evidence only under later authorized scope |
| `docs/increments/issue-18-scan-arguments-plan.md` | Written plan; approval/execution/evidence records are documentary, not new runtime behavior |

Named production interfaces are exactly `ArgumentAction`, `ArgumentChecks`, `ArgumentOptions`, `ScanArgumentRequest`, `Invocation`, `ArgumentErrorCode`, `ArgumentError`, `ParseArgs` and `(*ArgumentError).Error`. Their members and constants are defined in the linked specification; introduce no unreviewed fields or generic parser abstraction.

## Task 1 — one cohesive parser, one reviewed deliverable

**Create:** only the two Go files above after permission. **Consumes:** argv strings and the immutable written contract, no evidence/policy/runtime inputs. **Produces:** `ParseArgs([]string) (Invocation,error)` and the specified fixed error formatter; no display/scanner integration.

### Step 1 — authorize and establish baseline

- [ ] Obtain this written plan's approval, plus explicit inline implementation, offline-test/mutation and publication/evidence scope. Record that authorization before the first source file, as done for preceding increments; assignment or generic continuation is insufficient.
- [ ] Refresh issue18 owner/comments, PR30 head/files/draft/review state and branch/base; preserve sibling work. If any shared signature/contract or ownership changed, stop and agree the change rather than rebase/rewrite automatically.
- [ ] Keep the existing jj workspace and issue-18 bookmark. Verify no uncommitted unrelated bytes. Record actual compiler and module metadata; no toolchain acquisition or dependency preparation.
- [ ] Run the approved offline root baseline, save output externally, and count actual JSON test pass events. Historical development235347cc passed1,231 tests/subtests, but that is not a fresh result or a promised current count.

### Step 2 — literal tests, API RED, behavioral RED

- [ ] Create `arguments_test.go` first. Copy all52 independent P01-P20/E01-E32 argv/outcome expectations from the approved specification into a named `TestParseArgsReference` table, expanding each successful scan against the literal baseline. Do not parse the document at runtime or derive expected values from production helpers. Example runnable assertion shape follows; it pins P07, E11 and E21 and must be supplemented by the remaining49 exact rows.

```go
func TestParseArgsRedPins(t *testing.T) {
    cases := []struct {
        name string
        args []string
        want Invocation
        code ArgumentErrorCode
        index int
        option ArgumentOptions
    }{
        {
            name: "P07-explicit-default-origins",
            args: []string{"scan", "--manager", "auto", "--checks=malicious,vulnerability,integrity", "--fail-on", "none", "--format=terminal", "--privacy", "portable", "--output=-", "p"},
            want: Invocation{Action: ArgumentAction(1), Scan: ScanArgumentRequest{
                Path: "p", Manager: "auto", Checks: ArgumentChecks(7), FailOn: ArgumentChecks(0),
                Format: "terminal", Privacy: "portable", PolicyPath: "", StateDir: "", Output: "-", Provided: ArgumentOptions(159),
            }},
        },
        {
            name: "E11-do-not-swallow-option",
            args: []string{"scan", "--policy", "--checks=integrity", "p"},
            code: ArgumentErrorCode(6), index: 1, option: ArgumentOptions(32),
        },
        {
            name: "E21-local-enforcement-subset",
            args: []string{"scan", "--checks", "malicious", "--fail-on", "integrity", "p"},
            code: ArgumentErrorCode(11), index: 3, option: ArgumentOptions(4),
        },
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            got, err := ParseArgs(tc.args)
            if tc.code == 0 {
                if err != nil || got != tc.want {
                    t.Fatal("literal request or default-origin expectation lost")
                }
                return
            }
            e, ok := err.(*ArgumentError)
            if !ok || e == nil || e.Code != tc.code || e.ArgIndex != tc.index || e.Option != tc.option || got != (Invocation{}) {
                t.Fatal("private fatal classification, locator or whole-zero result lost")
            }
        })
    }
}
```

- [ ] Define focused tests named `TestParseArgsOptions`, `TestParseArgsDefaults`, `TestParseArgsBoundaries`, `TestParseArgsScope`, `TestParseArgsPrivacy`, `TestParseArgsOwnership`, `TestParseArgsSeparation` and `TestArgumentErrorLayout`. Use the complete case matrix below, with literal expectations and no production formatter/mask used to construct an oracle.
- [ ] Run the focused test command before production declarations; confirm missing API compilation failure and retain it separately. Add only the exact type/constant declarations and fixed `Error` formatter from the contract, plus this deliberate temporary RED stub:

```go
func ParseArgs(_ []string) (Invocation, error) {
    return Invocation{}, nil
}
```

- [ ] Re-run focused tests, inspect and save genuine assertion failures. All52 reference rows must fail against the zero/nil stub; layout/formatter checks may already pass. Record observed rows/parents, not an invented future total. A compile failure alone is not behavioral RED.

### Step 3 — minimal GREEN lexer

- [ ] Replace the RED stub with the bounded grammar in this order, preserving the specification rather than adopting standard-library parser permissiveness:

| Order | Exact implementation action |
| --- | --- |
| Command | Empty args returns missing-command/-1/0; unsupported first token returns unsupported-command/0/0 |
| Controls | Exact sole `--help`/`--version` succeeds with zero Scan; their extra operands yield control-arguments/index1; exact `scan --help` succeeds or its extra operands yield control-arguments/index2 |
| Defaults | Initialize one local scan request to the literal baseline; keep the fail-on option-token index for the final relation check |
| Option lexer | Start at index1. `--` consumes one terminator and ends options; a non-option or exact `-` begins root. Otherwise split only the first `=` and recognize the eight exact names |
| Known option guard | Unknown name returns unsupported-option/index/0. Repeat returns repeated-option at the repeated option token before checking its value |
| Value locator | Attached value locates its option token. Split value locates the next token; missing/end/next-prefix-`--` returns missing-option-value at the option token without swallowing the next token |
| Value qualification | Validate exact manager/format/privacy domains, bounded category membership or nonempty/NUL-free literal path. Failure returns invalid-option-value at the value locator and known bit |
| Assignment | Assign only the accepted field, OR its Provided bit, record fail-on option-token index when applicable; advance past only consumed tokens |
| Root | Require one remaining token; empty/NUL root-invalid precedes extra-argument. Preserve bytes exactly; extra token locates the first index after root |
| Local scope | After root success, `FailOn &^ Checks != 0` returns enforcement-outside-checks at the recorded fail-on option-token index and bit4 |
| Output | Return scan intent plus local request; every fatal branch returns zero Invocation and a newly allocated typed fixed-code error |

- [ ] Use a small exact-name switch, not a configurable flag registry. Category membership can use this complete private helper; it recognizes only fixed members and creates no split slice:

```go
func parseArgumentChecks(text string, allowNone bool) (ArgumentChecks, bool) {
    if allowNone && text == "none" {
        return 0, true
    }
    var set ArgumentChecks
    for {
        part, rest, more := strings.Cut(text, ",")
        var bit ArgumentChecks
        switch part {
        case "malicious":
            bit = ArgumentCheckMalicious
        case "vulnerability":
            bit = ArgumentCheckVulnerability
        case "integrity":
            bit = ArgumentCheckIntegrity
        default:
            return 0, false
        }
        if set&bit != 0 {
            return 0, false
        }
        set |= bit
        if !more {
            return set, true
        }
        text = rest
    }
}
```

- [ ] Implement `(*ArgumentError).Error()` as a fixed switch over all11 code constants/texts in the spec, defaulting to `cli: invalid-arguments`. Neither formatting nor error construction may accept/retain a rejected string. No generic wrapped lexer error or partial result.
- [ ] Keep production imports restricted to `strings`; no `flag`, `fmt`, `os`, `io`, `filepath`, native/network packages, global mutable state, `init`, goroutines, subprocesses or built-in print/println. Only local private scalar helpers are justified; no framework/extra files/cache/context scaffold.
- [ ] Run focused GREEN checks, then the whole root tests/vet. Read the output, including any unchanged-package regression. A new scope/contract requirement stops execution for approval rather than broadening this helper.

### Additional literal/parameterized case matrix

| Test owner | Exact cases / independent expectations |
| --- | --- |
| Reference | Every P01-P20/E01-E32, full scalar output or exact typed code/index/bit and whole-zero result |
| Options | Each of the eight names with valid literal value in split/attached form, repeated same/different form, repeated before missing-value, missing-at-end, next token `--`, next token `--online`, empty split/attached and NUL split/attached; fixed known bit and locators from the spec |
| Defaults | Omitted baseline versus separately explicit default manager/checks/fail-on/format/privacy/output; literal masks1/2/4/8/16/128. Explicit policy/state-dir literal values set32/64 without resolving; selecting policy is not applying policy |
| Layout | Literal action values0..4, checks1/2/4, options1/2/4/8/16/32/64/128, errors0..11 and every fixed error string; unknown codes0/255 render the same fixed fallback |
| Boundaries | All eight split options plus terminator/root: exactly19 tokens and Provided255. `scan -- --`, `scan -- -x`, `scan -- --help`, bare `scan -`, `scan --` and extra root; options after root never become controls |
| Boundaries | Category permutations all bits7; empty members at beginning/middle/end, repeated members, a fourth member, `inventory`, `none` in checks, mixed `none` enforcement, uppercase/whitespace/NUL all rejected without unbounded splitting |
| Boundaries | Literal `./a/../ p`, `$HOME/p`, `~/p`, `C:\\p`, `https://example.invalid/p`, whitespace/non-ASCII/newline and `string([]byte{255})` paths preserved; only empty/NUL rejected. No URL/expansion/normalization/opening interpretation |
| Scope | Literal `scan --policy=p --privacy=local --fail-on=none root` succeeds as requested values with Provided52, not effective-policy approval. Narrowed checks/enforcement mismatch fails only after root is valid; missing/invalid/extra root keeps its earlier error |
| Privacy | Synthetic credentials/ANSI/newlines in unsupported command/option, invalid manager/category/path, plus a valid policy option before a later error. Assert exact fixed Error text/locator/known bit and whole-zero output; fmt-style rendering contains no rejected marker |
| Ownership | Snapshot argv; successful/failed calls never change it. Replace every caller slice element after success and retain exact result; repeated calls do not share mutable state or change earlier output |
| Separation | Parse the owned production source AST in the test: imports only strings; no global mutable var/init/GoStmt, print/println or scan-exit calls. Inspect types for only the specified fields; no raw argv/value/error extension. This is owned-source review, not a target fixture/native probe |

The URI-looking and non-UTF-8 strings are literal in-memory test inputs, not acquired/accessed targets. Synthetic credential markers must not be real tokens. All bit/index/text expectations are independently literal; loops may form argv permutations but must not query the production parser to choose expected outputs.

### Step 4 — mutation and focused self-review

- [ ] Temporarily omit setting a Provided bit for an explicit default; the corresponding Defaults/P07 expectations must fail. Restore exactly before proceeding.
- [ ] Temporarily allow a repeated option to overwrite instead of error; E08/E09 and per-option repetition cases must fail. Restore.
- [ ] Temporarily let help ignore trailing arguments or reinterpret terminated `--help` as help; E04/P05/Boundaries must fail. Restore.
- [ ] Temporarily include a rejected synthetic string in Error formatting; Privacy must fail. Restore. Mutations are local short-lived changes only, not commits/PRs or permission to weaken final protections.
- [ ] Verify source fingerprints before/after restoration, then self-review the five focus classes, zero-result/error priority, category allocation, unchanged existing exits and absence of I/O/authority expansion. Author review is not the agreed second-person review.

### Step 5 — fresh verification and scoped evidence

- [ ] Format only the two new Go files. Run fresh focused/root checks and vet after every mutation is removed, recording actual compiler, baseline/new/current test pass events, errors and exact tested tree. No sum across branches or addition of52 documentary rows to Go counts.
- [ ] Compare every preexisting Go/module/probe byte to the agreed execution base; check only approved new files and separately authorized documentary evidence. No go.sum, unexpected import, producer/native/coverage claim or top-level shipping-parent closure.
- [ ] If execution/evidence publication is authorized, commit only the two Go files with jj and publish only the issue bookmark. Update specification/plan completion evidence and the nested shared milestone only if those exact documentary paths are included in that later authority; otherwise request it first. No automatic ready/reviewer or merge action.
- [ ] Obtain separate review-handoff authorization, agree the second-person reviewer and verify the final PR head is what that reviewer approves. Keep issue/parent gates open until their own reviewed acceptance/integration. Subsequent integrated-tree verification/queue cleanup is separately authorized.

## Future commands — not executed here

These are Nushell examples for separately authorized tests. Environment is command-scoped; no module/toolchain/download fallback:

```nu
with-env {GOTOOLCHAIN: local, GOPROXY: off, GOWORK: off, CGO_ENABLED: "0"} {
    go version
    go test -count=1 ./internal/cli -run 'TestParseArgs|TestArgumentError'
    go test -count=1 -json ./...
    go vet ./...
}
```

Formatting is confined to the new files:

```nu
gofmt -w internal/cli/arguments.go internal/cli/arguments_test.go
jj diff --stat
```

This plan does not authorize execution of these snippets. Store RED/GREEN/mutation outputs outside the repository, inspect exit status and results before subsequent commits, and retain only approved scoped evidence. The normal isolated/native/producer/pilot gates remain unqualified.

## Plan self-review — documentary, not implementation

- [x] Match every spec requirement and all52 IDs to the single task and focused matrix; no contract coverage gap identified in author self-review.
- [x] Check API/type/field/error constant names against the unchanged specification; check scalar masks/locators independently, including Provided52, maximal19-token grammar and error codes6/11 in the example.
- [x] Parse the three Go snippets with gofmt (syntax only, no type checking/compilation/execution of proposed code) and both Nushell examples with nu-check (parse only, commands not run).
- [x] Check four local links/anchors, no placeholder/reference gaps, unchanged existing tracked bytes and only this new document. Go's legitimate ./... command wildcard is not a placeholder.
- [ ] Obtain user written-plan approval and publication decision. Explicit execution authority, its precise files/tests/evidence scope and independent review still follow separately.
