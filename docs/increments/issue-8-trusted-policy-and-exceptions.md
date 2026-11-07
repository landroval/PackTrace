# Issue 8 — effective policy, evidence-bound exceptions and report routing

This operational increment uses the existing offline scanner. It does not grant
publisher authentication, package-content authenticity, unrestricted feed or
platform coverage, or release qualification. Historical supplied-input tools and
report builders keep their contracts; operational reports use schema **1.7**.

## Defaults and explicit authority

`--policy FILE` is optional. Without it, compiled defaults select all three checks,
no finding enforcement, portable output and lockfile-consistent minimum assurance.
Explicit `--checks` narrowing and `--fail-on` strengthening remain available.
Built-ins grant no references, registry/origin authority, candidate lookup or
exceptions. Inventory still runs as a prerequisite. Missing evidence is a gap,
not a successful empty result.

No project/user policy discovery, executable configuration, target `.npmrc`
credentials, target execution, network request, initialization or repair occurs.
An exact supported root `packageManager` value may supply a parser interpretation
for built-in `auto`/family selection. It is target evidence, **not** authenticated
producer identity or policy authority. Missing/unsupported/conflicting hints stay
incomplete; no newest producer version is guessed. An explicit supported profile
remains an operator interpretation choice. Existing lock conflict, shrinkwrap and
unsupported binary rules still apply.

An explicitly selected policy remains strict static version-1 JSON. Invalid
policy never falls back to built-ins. Present typed fields cannot use alternate
case spellings or duplicate aliases to change enforcement. Policy-required checks,
mandatory enforcement and portable privacy cannot be weakened by explicit flags;
conflicts return 2. Omission inherits mandatory enforcement; explicit
`--fail-on none` cannot erase it. Effective source, selected masks, explicit-option
origins, manager, privacy and assurance are recorded in the policy result.

A separate `--trusted-policy-digest` is required for independently anchored
references, npm namespace/candidate grants, exceptions or a lifetime override.
Both actual stable external policy reads retain the existing pin, physical
separation and continuity checks. No-policy invocations cannot name a policy pin.
A pin and asserted owner/timestamps are not organizational or publisher approval.
Sensitive source selectors/pins/origins are not report fields.

## Exception schema

Optional policy fields:

- `exceptions`: at most 64 entries, unique bounded `id` values.
- `maxExceptionDays`: explicit positive elapsed-day limit, at most 365; omitted
  means 30 days. The override requires a separately pinned policy.

Every exception has exactly these fields:

| Field | Meaning |
| --- | --- |
| `id`, `reason`, `owner` | Bounded review assertions, not cryptographic approval |
| `approvedAt`, `expiresAt` | Canonical UTC RFC3339 timestamps ending in `Z` |
| `scope` | Exact finding selector below, never a wildcard |
| `acceptance` | Canonical SHA-256 SRI of the reviewed evidence |

`scope` has `project`, `category`, `rule`, `class`, `package`, `version`, `origin`,
`instance`, `path`, `advisory`, and `change`. Empty category-inapplicable fields
mean literal absence, not an unrestricted selector:

- Advisory: malicious/vulnerability category, `osv-npm` rule, locked/installed
  class, exact supported npm identity/version/origin and relative instance,
  exact original advisory ID; empty `path` and `change`.
- Integrity: integrity category, `integrity-drift` rule, installed class, exact
  selected reference identity/version/origin and relative instance/file;
  `modified`, `missing`, `added` or `type-changed`; empty `advisory`.

The lifetime runs from approval to expiry, never scan time. Expiry is exclusive;
future approvals and expired or evidence-mismatched exceptions accept nothing.
Malformed exceptions invalidate the selected policy. Valid but inapplicable
entries retain controlled dispositions. Portable reports refer to exception
ordinals, not potentially identifying review text.

Accepted findings stay in counts, terminal/JSON and SARIF alerts. Only their
contribution to selected finding enforcement changes. Candidates cannot be
accepted or promoted into alerts; exceptions cannot waive a coverage gap.

## Canonical content binding

Hashes use `sha256-` plus canonical padded base64 of SHA-256. The encoding is the
UTF-8 compact JSON array of `"packtrace-policy-v1"`, a domain string, then the
ordered typed values below. Object-shaped file sides have fixed field order
`state`, `type`, `size`, `sha256`, `linkSHA256` with explicit empty values.

- **Project**, domain `project`: root manifest original-byte SHA-256 (lowercase
  hex), selected lock original-byte SHA-256, supported interpretation profile,
  controlled relative selected-lock filename. Complete stable reads and qualified
  input semantics are required. Root relocation does not change this identity;
  any change inside the selected lock may. Ignored sibling locks are not hashed
  as the effective selected input.
- **Tracking**, domain `tracking`: project fingerprint, category, rule, class,
  exact package, version, origin, relative instance, relative file, advisory ID,
  change kind.
- **Acceptance**, domain `acceptance`: tracking fingerprint, project fingerprint,
  observation-source SHA-256, selected-lock SHA-256, original advisory SHA-256,
  affected slot, interpretation profile, relative physical target, directory kind,
  link-object SHA-256, expected file side, observed file side, expected reference
  SRI, actually verified reference SRI, assurance, reference context.

Empty expected/observed file sides are distinct from a zero-length regular file.
An absent side has explicit `absent`/`none` state and no digest. Directories do not
receive content hashes or incidental filesystem sizes. A link digest commits to
the link object text, never referent bytes. Existing unsupported-link gaps remain.

No whole-policy hash/pin/path, exception text/times/list, scan-local sequence or
IDs, snapshot/generation/catalog/block identity, freshness timestamp or resource
sample enters these stable fingerprints. Adding an exception is not circular.
A changed evaluated original revokes old acceptance; an unchanged original in a
snapshot-only refresh neither invalidates nor renews it. Freshness is independent.
Internal record/difference commitments bind transported material to separately
admitted opaque endpoints; they are not public/stable finding fingerprints.

## Evidence and privacy

The physical worker projects already-read original/manifest/reference/installed
facts. The supervisor validates bounded shapes and graph/record associations,
computes fingerprints, evaluates time and policy, and derives enforcement. This
is structural admission of trusted same-executable receipts, **not** independent
parent reexecution or resistance to a worker rewriting every graph and receipt.

Policy material is private even during portable scans. New material and integrity
witnesses share a 4096-material/8 MiB smaller ceiling and the unchanged 1 MiB frame /
64 MiB total transport limits. Missing, unsupported or exhausted material accepts
nothing and never removes a finding. It cannot manufacture detection completeness.

Only explicit `--privacy local` exposes bounded identities/relative file paths,
tracking and acceptance fingerprints, project/input/original hashes, typed file
sides and actual reference evidence. Raw origins are represented by a review
fingerprint; use the independently reviewed policy origin when authoring the exact
exception. No raw files, credentials, absolute host paths or authority pins are
exported. Local is presentation permission, never upload permission. Portable
remains opaque, and `requirePortable` still prevents local output.

## Coverage, exits and output

The operational outer model derives required coverage and unaccepted enforcement
across all selected categories; the CLI consumes the same comparison conditions.
Precedence is interruption 130, report-preventing/output failure 2, incomplete
required coverage 3, enforced unaccepted finding 1, then 0. Genuine native,
reference, index, freshness, inventory, ownership and resource gaps remain. Current
bounded scans can legitimately remain 3 even after every finding is accepted;
selector tests of 0/1 do not prove a current real scan is complete.

The report is a **pre-output comparison snapshot**. It cannot predict later
writer/sync/commit/close/reap success. A late failure can correctly make process
exit 2/130 after comparison bytes with a different comparison exit were emitted.

Default output is stdout; diagnostics remain stderr. Explicit `--output FILE`
uses an existing report directory physically **disjoint** from the original
project, state and reference roots. Ancestor/common-parent directories, in-root,
linked/unprovable/unsupported destinations and existing files are refused.
There is no overwrite, parent creation, target write, raw temporary-path reopen,
or automatic deletion of failed/uncertain publication residues. The bounded
file-publication profile initially uses the existing Linux native mechanism;
unsupported platforms fail closed rather than falling back to path-based writes.

Read-only original-root/ancestry admission occurs before acquisition and creates
no report file. Acquisition binds its actual roots to that retained plan. Only
the observed terminable same-executable writer, after validating the complete
approved byte transfer/hash/EOF, creates/writes/syncs/commits publication. Original
source guards and generation pins remain through confirmed reap and `Finish`.
Shell redirection remains the caller's responsibility: PackTrace cannot control
a shell opening redirected stdout before it starts.

## Verification boundary

Authored parser, engine, evidence, privacy and stdout process acceptance checks
exercise this increment. Final source review, full-suite receipts and compiled
file-output acceptance must be checked against the delivered exact tree; an early
stdout-only integration overlay or a publication building-block test is not proof
of complete output integration. No live-corpus/source/SDK/native qualification
campaign is renewed by this increment. Historical failed attempts remain evidence.
