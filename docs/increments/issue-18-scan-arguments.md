# Issue 18 — pure scan argument requests

## Status and authority

- Issue: [#18](https://github.com/landroval/PackTrace/issues/18); owner: landroval.
- Design agreed: complete argv without the executable name; request/default/provenance output, not effective policy; a bounded lexer for the eight approved options.
- Written specification: **approved by the user for documentary publication in a draft PR**; independent peer review is pending.
- Base: integrated `development` at `235347cc0be03e3cc5019db40a1e3b710920be9b`, independently of PR #29. The existing CLI exit selector is retained unchanged.
- The user separately approved the [implementation plan](issue-18-scan-arguments-plan.md), inline two-file execution, owned offline tests/four restored mutations and scoped documentary evidence publication. I pushed pre-code authorization `9cb7874c6293ac3344b7ef91cb13c2675868dc89` before source creation. I have no ready/reviewer-request, target access, acquisition, native/CI or merge authority.

## Purpose and boundaries

I propose one pure internal parser for the approved command syntax. It accepts caller-supplied strings and returns an invocation intent and scan requests. It does not execute that intent, print help/version/errors, choose a process exit, collect inventory, run package managers or prove that a target is safe.

This increment is not `cmd/packtrace`, an operational scanner or a public SDK. It opens no target, policy, state, output or network resource. It reads no invocation directory, environment, cache directory, clock or process-global `os.Args`. No policy/schema, destination safety, filesystem normalization, no-clobber publication, producer qualification, worker or report implementation is introduced.

The future caller must qualify policy/effective settings, resolve paths against the invocation directory, validate native containment/aliases and destinations, and prepare the applicable inputs before investigation. A syntactically valid request is not permission to bypass those gates. Missing native safeguards remain blocking for operations that require them, not for this in-memory parser.

## Existing contracts and integration

The following versioned contracts remain authoritative:

- [Scan syntax, profiles and validation](../design-decisions.md#28-core-scan-command-and-argument-validation).
- [Default state location and path resolution](../design-decisions.md#29-default-state-directory-and-cli-path-resolution).
- [Policy authority and output routing](../design-decisions.md#6-configuration-policy-authority-and-output).
- [Scan defaults and exit semantics](../design-decisions.md#5-scan-defaults-and-exit-codes).
- Existing [exit selector](../../internal/cli/exits.go) and [its checks](../../internal/cli/exits_test.go).
- [Collaboration and separate approvals](../github-collaboration.md).

I do not alter the existing exit selector or call it from parsing. Invocation errors are eventual code-2 conditions under the command contract; a caller decides how to display/exit. Successful help/version is not a completed scan or a scan-exit-0 assertion.

## Proposed files and API

Only these eventual production/test files are intended, after separate approvals:

- `internal/cli/arguments.go`
- `internal/cli/arguments_test.go`

The only entry point is `ParseArgs(args []string) (Invocation, error)` in `internal/cli`.

| Type / member | Contract |
| --- | --- |
| `ArgumentAction uint8` | `ArgumentActionUnknown = 0`, then `ArgumentActionScan`, `ArgumentActionHelp`, `ArgumentActionScanHelp`, `ArgumentActionVersion` |
| `ArgumentChecks uint8` | `ArgumentCheckMalicious = 1`, `ArgumentCheckVulnerability = 2`, `ArgumentCheckIntegrity = 4`; zero is the empty set; parser emits no other bits |
| `ArgumentOptions uint16` | `ArgumentOptionManager = 1`, `ArgumentOptionChecks = 2`, `ArgumentOptionFailOn = 4`, `ArgumentOptionFormat = 8`, `ArgumentOptionPrivacy = 16`, `ArgumentOptionPolicy = 32`, `ArgumentOptionStateDir = 64`, `ArgumentOptionOutput = 128`; zero means none explicitly supplied |
| `ScanArgumentRequest` | `Path`, `Manager`, `Format`, `Privacy`, `PolicyPath`, `StateDir`, `Output` are strings; `Checks`, `FailOn` are `ArgumentChecks`; `Provided` is `ArgumentOptions` |
| `Invocation` | `Action ArgumentAction`; `Scan ScanArgumentRequest` |
| `ArgumentErrorCode uint8` | `ArgumentErrorUnknown = 0`, followed by the exact error constants in the error table below |
| `ArgumentError` | `Code ArgumentErrorCode`, `ArgIndex int`, `Option ArgumentOptions`; implements `error` |

For scan, `Provided` identifies operator-supplied options even when their values equal defaults. The target is always explicit and needs no default-origin bit. Category order is set membership, not execution order; duplicates are rejected rather than silently deduplicated. Manager/format/privacy values remain exact accepted texts.

For the three non-scan actions, the whole `Scan` member is zero. On every error, the whole `Invocation` is zero, including defaults, and the error is `*ArgumentError`. No partial request survives. Unknown zero action/error values are never successful/emitted classifications.

Output owns its scalar values and emits no slice/map aliases to the argv container. Strings follow Go's immutable-string contract; changing caller slice elements cannot alter a successful result. No unsafe mutation/concurrent mutation of input storage is supported.

This result is internal request data, not a public report/IPC schema. Successful path fields may contain sensitive text; they must not be serialized/logged without the later privacy layer. Raw argv and rejected values are never returned in an error/result side channel.

## Action grammar

Exactly these non-scan forms are accepted:

| Argv, excluding program name | Action |
| --- | --- |
| `["--help"]` | `ArgumentActionHelp` |
| `["scan","--help"]` | `ArgumentActionScanHelp` |
| `["--version"]` | `ArgumentActionVersion` |

These forms take no additional operands/options. There is no `help`/`version` command alias, `-h`/`-v`, `scan --version` or help-anywhere escape. Unknown arguments are not ignored because help/version is present. Literal root `--help` after `scan --` is a scan path, not a display action.

Scan syntax is `scan [options] PATH`, with optional `--` before the path. Exactly one nonempty PATH is required; current-directory substitution is forbidden. An explicit literal `.` is permitted but not opened or resolved here.

### Scan options

| Option | Accepted value and scan default | Provenance |
| --- | --- | --- |
| `--manager` | Exact `auto`, `npm`, `bun`, `npm@8.19.4`, `npm@10.9.4`, `npm@11.6.2`, `bun@1.3.2`, `bun@1.4.2`; default `auto` | manager bit |
| `--checks` | Nonempty CSV of exact `malicious`, `vulnerability`, `integrity`; default all three / bits 7 | checks bit |
| `--fail-on` | Exact `none` alone or nonempty CSV of those categories; default empty set / bits 0 | fail-on bit |
| `--format` | Exact `terminal`, `json`, `sarif`; default `terminal` | format bit |
| `--privacy` | Exact `portable`, `local`; default `portable` | privacy bit |
| `--policy` | Nonempty literal path; default empty/no operator-selected file | policy bit |
| `--state-dir` | Nonempty literal path; default empty/deferred managed-location request | state-dir bit |
| `--output` | Nonempty literal destination; default `-` / stdout request | output bit |

Each option takes a value using either `--name value` or `--name=value`, splitting only the first `=`. There are no bare boolean values, single-dash long forms, short aliases, abbreviations, case-folding, trimming or automatic spelling correction. Each known option may appear once, irrespective of split/attached spelling or equal repeated values.

For split values, end of argv or a following token beginning `--` is a missing value; that next token is not swallowed. A path value beginning `--` can be supplied attached (`--policy=--file`) or through an explicit relative spelling (`--policy ./--file`). Single-dash path values, including `-`, are literal values; only output's exact `-` denotes a stdout request. Policy/state-dir `-` is not stdin or a default request.

Empty attached/split values and NUL-containing consumed values/paths are invalid. Other path text is opaque: spaces, non-ASCII, non-UTF-8 Go string bytes and POSIX-legal controls are not stripped or normalized. No percent/URI decoding, tilde/environment expansion, separator conversion, `filepath.Clean`/`Abs` or platform-specific path validation occurs here. An error is private even when the input contains credentials/control characters.

Before `--`, an ASCII-dash-prefixed root other than exact `-` must use the terminator; otherwise it is treated as an unsupported option. After `--`, one literal path, including a dash-prefixed path, is required. `--` does not allow additional positional arguments. After the first path, any further token is an extra argument, never another option or help action.

### Category and local-scope rules

Category names are case-sensitive and untrimmed. Empty lists/members, duplicates, `inventory`, unknown names and `none` in checks are invalid. `none` cannot be mixed with enforcement categories. Permutations of the same three distinct names yield the same set, not a reordered execution plan.

After successful lexical parsing and root-count validation, `FailOn` must be a subset of requested `Checks`. This is a local flag-consistency check, not effective policy validation. A syntactically valid `--privacy local` likewise does not mean a policy permits local disclosure.

### Deferred policy and operational gates

I return defaults as requests with explicit-origin bits, never as evidence that policy requirements were checked. Omitted/default `--fail-on none` cannot disable a later mandatory enforcement requirement. Explicit flags that weaken a supplied policy must fail the future effective-setting validation; omitted flags may be strengthened by that policy. Invalid/unavailable selected policy must not silently fall back.

An explicit policy path proves only operator selection, not organizational approval. The parser cannot prevent policy omission. Policy digest, freshness, resource ceilings, exceptions and policy trust are outside this slice.

Empty/default StateDir means the later caller must resolve `os.UserCacheDir()/packtrace` under the approved section-29 contract; it is not a usable empty path, cache-existence observation or fallback to target/CWD/temp. The parser does not read those environment defaults.

Manager selection is an interpretation request, not producer proof, installed observation, resolution or a manager invocation. Target-dependent auto/family ambiguity is deferred. A valid profile cannot rescue incompatible target semantics.

Output is an unchecked destination request. Existing/in-target/unsafe destinations must later fail without overwrite or stdout fallback; no-clobber races remain native work. No destination exists/is-safe/not-in-target claim is made here. Parsing never initializes state or downloads missing intelligence/references.

## Private errors and deterministic order

| Error constant, after unknown zero | `Error()` fixed text | Meaning |
| --- | --- | --- |
| `ArgumentErrorMissingCommand` | `cli: missing-command` | No argv entry |
| `ArgumentErrorCommandUnsupported` | `cli: unsupported-command` | First token is not scan or an accepted top-level control |
| `ArgumentErrorControlArguments` | `cli: control-arguments` | Extra tokens with a leading top-level control or immediate scan help |
| `ArgumentErrorOptionUnsupported` | `cli: unsupported-option` | Unknown/malformed option or unsupported control/alias in scan |
| `ArgumentErrorOptionRepeated` | `cli: repeated-option` | Previously supplied known option |
| `ArgumentErrorOptionMissingValue` | `cli: missing-option-value` | No split value, or next split token starts `--` |
| `ArgumentErrorOptionValueInvalid` | `cli: invalid-option-value` | Empty, unusable or outside the option's accepted domain |
| `ArgumentErrorRootMissing` | `cli: missing-root` | Scan ends without PATH |
| `ArgumentErrorRootInvalid` | `cli: invalid-root` | Empty or NUL-containing consumed PATH |
| `ArgumentErrorExtraArgument` | `cli: extra-argument` | Token following the one root |
| `ArgumentErrorEnforcementOutsideChecks` | `cli: enforcement-outside-checks` | Requested enforcement exceeds requested checks |

Errors disclose only the fixed code text, a zero-based argv locator, and a known option bit (or zero). `Error()` must not append indexes, raw names/values, paths or underlying lexer text. An independently fabricated unknown error code must render `cli: invalid-arguments`, never user text.

Order is deterministic:

1. Missing/unsupported command first. A leading top-level control with extra tokens reports control-arguments at index 1. Immediate `scan --help` with extra tokens reports control-arguments at index 2.
2. Scan tokens left-to-right. Option recognition precedes repeated detection; repeated detection precedes missing/invalid value. Missing split value locates the option token. Invalid attached value locates that token; invalid split value locates its value token.
3. Unsupported option has `Option=0`; repeated/missing/invalid known options carry their one known bit. Empty/NUL path is root-invalid at its own token. Extra argument locates the first token after root, `Option=0`, regardless of that token's spelling.
4. Root-missing uses `ArgIndex=-1`, `Option=0`. Only after an otherwise complete scan does enforcement-outside-checks locate the `--fail-on` option token and its bit. This does not supersede earlier lexical/root errors.

No generic parser stderr/stdout or wrapped underlying error is exposed. There is no partial-success/fallback mode.

## Literal reference cases, not executed tests

These are author-proposed documentary expectations. In scan successes, unspecified fields mean the literal baseline below, not values queried from production code. Future tests must instantiate independent literal expected results; control successes have whole-zero Scan, and all errors have whole-zero Invocation. The compact outcome keys in this table are documentary notation, not JSON/report API field names.

Literal scan baseline: Manager=`auto`, Checks=7, FailOn=0, Format=`terminal`, Privacy=`portable`, PolicyPath=``, StateDir=``, Output=`-`, Provided=0. Path is the exact table operand.

| ID | Literal argv | Literal outcome |
| --- | --- | --- |
| P01 | `["--help"]` | `{"action":"help"}` |
| P02 | `["scan","--help"]` | `{"action":"scan-help"}` |
| P03 | `["--version"]` | `{"action":"version"}` |
| P04 | `["scan","."]` | `{"action":"scan","path":".","provided":0}` |
| P05 | `["scan","--","--help"]` | `{"action":"scan","path":"--help","provided":0}` |
| P06 | `["scan","--manager=npm@11.6.2","--checks","integrity,malicious","--fail-on=malicious","--format","json","--privacy=local","--policy","p.json","--state-dir=s","--output","r.json","root"]` | `{"action":"scan","path":"root","manager":"npm@11.6.2","checks":5,"failOn":1,"format":"json","privacy":"local","policy":"p.json","stateDir":"s","output":"r.json","provided":255}` |
| P07 | `["scan","--manager","auto","--checks=malicious,vulnerability,integrity","--fail-on","none","--format=terminal","--privacy","portable","--output=-","p"]` | `{"action":"scan","path":"p","provided":159}` |
| P08 | `["scan","--checks=integrity,vulnerability,malicious","p"]` | `{"action":"scan","path":"p","checks":7,"provided":2}` |
| P09 | `["scan","--checks=vulnerability","--fail-on=vulnerability","p"]` | `{"action":"scan","path":"p","checks":2,"failOn":2,"provided":6}` |
| P10 | `["scan","--policy=--file","--state-dir","-","--output","./-","p"]` | `{"action":"scan","path":"p","policy":"--file","stateDir":"-","output":"./-","provided":224}` |
| P11 | `["scan","--policy=a=b.json","./a/../ p"]` | `{"action":"scan","path":"./a/../ p","policy":"a=b.json","provided":32}` |
| P12 | `["scan","C:\\work\\project"]` | `{"action":"scan","path":"C:\\work\\project","provided":0}` |
| P13 | `["scan","-"]` | `{"action":"scan","path":"-","provided":0}` |
| P14 | `["scan","--manager=bun@1.4.2","p"]` | `{"action":"scan","path":"p","manager":"bun@1.4.2","provided":1}` |
| P15 | `["scan","--manager=npm","p"]` | `{"action":"scan","path":"p","manager":"npm","provided":1}` |
| P16 | `["scan","--manager=bun","p"]` | `{"action":"scan","path":"p","manager":"bun","provided":1}` |
| P17 | `["scan","--manager=npm@8.19.4","p"]` | `{"action":"scan","path":"p","manager":"npm@8.19.4","provided":1}` |
| P18 | `["scan","--manager=npm@10.9.4","p"]` | `{"action":"scan","path":"p","manager":"npm@10.9.4","provided":1}` |
| P19 | `["scan","--manager=bun@1.3.2","p"]` | `{"action":"scan","path":"p","manager":"bun@1.3.2","provided":1}` |
| P20 | `["scan","--format=sarif","p"]` | `{"action":"scan","path":"p","format":"sarif","provided":8}` |
| E01 | `[]` | `{"code":"missing-command","index":-1,"option":0}` |
| E02 | `["sync"]` | `{"code":"unsupported-command","index":0,"option":0}` |
| E03 | `["--help","secret-path"]` | `{"code":"control-arguments","index":1,"option":0}` |
| E04 | `["scan","--help","--online"]` | `{"code":"control-arguments","index":2,"option":0}` |
| E05 | `["scan","--version"]` | `{"code":"unsupported-option","index":1,"option":0}` |
| E06 | `["scan","--online","p"]` | `{"code":"unsupported-option","index":1,"option":0}` |
| E07 | `["scan","-manager","npm","p"]` | `{"code":"unsupported-option","index":1,"option":0}` |
| E08 | `["scan","--manager=npm","--manager","npm","p"]` | `{"code":"repeated-option","index":2,"option":1}` |
| E09 | `["scan","--manager=auto","--manager"]` | `{"code":"repeated-option","index":2,"option":1}` |
| E10 | `["scan","--policy"]` | `{"code":"missing-option-value","index":1,"option":32}` |
| E11 | `["scan","--policy","--checks=integrity","p"]` | `{"code":"missing-option-value","index":1,"option":32}` |
| E12 | `["scan","--manager=npm@12","p"]` | `{"code":"invalid-option-value","index":1,"option":1}` |
| E13 | `["scan","--manager","NPM","p"]` | `{"code":"invalid-option-value","index":2,"option":1}` |
| E14 | `["scan","--checks=","p"]` | `{"code":"invalid-option-value","index":1,"option":2}` |
| E15 | `["scan","--checks","malicious,","p"]` | `{"code":"invalid-option-value","index":2,"option":2}` |
| E16 | `["scan","--checks=malicious,malicious","p"]` | `{"code":"invalid-option-value","index":1,"option":2}` |
| E17 | `["scan","--checks=inventory","p"]` | `{"code":"invalid-option-value","index":1,"option":2}` |
| E18 | `["scan","--checks= malicious","p"]` | `{"code":"invalid-option-value","index":1,"option":2}` |
| E19 | `["scan","--checks=none","p"]` | `{"code":"invalid-option-value","index":1,"option":2}` |
| E20 | `["scan","--fail-on=none,integrity","p"]` | `{"code":"invalid-option-value","index":1,"option":4}` |
| E21 | `["scan","--checks","malicious","--fail-on","integrity","p"]` | `{"code":"enforcement-outside-checks","index":3,"option":4}` |
| E22 | `["scan","--checks=malicious","--fail-on=integrity"]` | `{"code":"missing-root","index":-1,"option":0}` |
| E23 | `["scan"]` | `{"code":"missing-root","index":-1,"option":0}` |
| E24 | `["scan","--"]` | `{"code":"missing-root","index":-1,"option":0}` |
| E25 | `["scan",""]` | `{"code":"invalid-root","index":1,"option":0}` |
| E26 | `["scan","x\u0000y"]` | `{"code":"invalid-root","index":1,"option":0}` |
| E27 | `["scan","p","--format=json"]` | `{"code":"extra-argument","index":2,"option":0}` |
| E28 | `["scan","--","p","q"]` | `{"code":"extra-argument","index":3,"option":0}` |
| E29 | `["scan","--policy="]` | `{"code":"invalid-option-value","index":1,"option":32}` |
| E30 | `["scan","--output","x\u0000y","p"]` | `{"code":"invalid-option-value","index":2,"option":128}` |
| E31 | `["scan","--checks=Malicious","p"]` | `{"code":"invalid-option-value","index":1,"option":2}` |
| E32 | `["scan","--checks=malicious","--help"]` | `{"code":"unsupported-option","index":2,"option":0}` |

These 52 rows are not a complete native/operational acceptance suite. Future tests must additionally cover every option's split/attached/repeated/missing/empty forms, category permutations/duplicates, whole-zero results, caller-container mutation, exact error privacy with hostile values, separator/root controls and forged-error formatting. Such tests remain separately planned/executed; this table is not an implemented parser oracle.

## Resource and ownership limits

No new arbitrary pathname-byte quota or operational scan-budget flag is invented. Work is linear in consumed argv text; accepted invocations contain at most 19 tokens (command, eight split option/value pairs, terminator and root). Invalid repeated/root/control forms stop without traversing an arbitrary trailing argument list.

Category parsing must inspect at most three members for a successful list and reject excess/invalid members without allocating an unbounded `strings.Split` result. The parser emits fixed-size scalar structs/masks and creates no input-proportional diagnostic, raw argv clone or path normalization buffer. These are algorithm/output bounds, not hard RSS, OS argv-size/native pathname qualification or protection against preexisting caller input allocation.

## Documentary review and next approvals

I self-reviewed the grammar, 52 literal expectations, privacy/zero-output rules, defaults/origins and source-independent boundaries against the approved design. I checked unique IDs, JSON syntax, seven local links/anchors, mask arithmetic and unchanged existing tracked bytes; I identified no critical/important documentary issue. The user then approved this written specification and its separate draft publication. These are documentary/author checks, not independent peer approval, semantic parser execution, new Go test results or native qualification.

## Implementation evidence — bounded development result

I implemented only `internal/cli/arguments.go` and `arguments_test.go`, code commit `1804884ec9033e3a0130b9dd761468a3ec0df2b9`, after separately approved plan/execution. Existing exit/inventory/intelligence code, modules and probes remained byte-for-byte unchanged against pre-code authorization. No dependency or go.sum was introduced.

I observed missing-API compilation RED, then zero/nil-stub behavioral RED with221 failing/15 passing new tests/subtests, including all52 failing reference rows. I implemented the strings-only lexer and strengthened repeated-different/invalid-value and non-suppressing default/policy test grouping during author review. Four temporary default-origin/repetition/help/private-error mutations failed the expected tests and were restored to the original source fingerprint.

Fresh final root verification: **1,543 tests/subtests**, including **312 new CLI cases/parents**, plus offline vet and gofmt. Baseline was1,231. I used `go1.27.1-X:nodwarf5 linux/amd64` with GOTOOLCHAIN=local, GOPROXY=off, GOWORK=off, CGO_ENABLED=0; these are owned development checks, not official/native toolchain qualification. The52 documentary rows are included through real reference tests, not added again to the count.

I self-reviewed the five plan focus classes and found no critical/important source issue; that is author review, not independent peer approval. PR #30 remains draft, and the issue/capability/shipping gates remain open pending separately authorized review/integration. No scanner/entry point, display, effective policy, target/environment/state access, output publication or native/producer qualification was implemented. Specification/plan/execution/evidence approvals do not authorize ready/reviewer/merge actions.
