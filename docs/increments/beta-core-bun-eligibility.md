# Beta core: bounded Bun eligibility and original-byte validation

**Unreleased implementation increment, not beta or native qualification.**
Application release versions/tags and installed setup/policies are unchanged.
See the [beta plan](public-beta-readiness-plan.md) and
[policy guide](../user-guide.md#exact-bun-namespace-grants-development).

## Implemented behavior

- New strictly parsed, independently pinned `bunOrigins` rules explicitly map up
  to64 exact root tuples to reviewed npm namespaces. All five fields are required;
  the raw registry claim, including an explicitly designated empty Bun default,
  remains separate from the normalized operator mapping. Old npm/candidate/cache
  policies and saved pins acquire no authority.
- Supported simple root tuples can produce eligible malicious/vulnerability
  decisions. Installed association additionally requires its own complete manifest,
  native directory metadata and unique original correspondence. Workspaces, aliases,
  peers, unknown/patch context, mismatches and ambiguous instances stay unqualified.
  Relations are not relabelled as general package-manager resolution evidence.
- Collector support is derived while the original Bun document/INFO still exists,
  not inferred from fields remaining after projection. The parent binds each rule,
  endpoint and material to the separately admitted acquisition witness.
- Copies of already-read root manifest, governing lock and own installed manifest
  bytes permit independent parent hashing/reparsing of governing declarations,
  selected tuple context and installed identities. No target reread or new role is
  introduced. Same-receipt hidden-context, endpoint, manifest and material
  substitutions are rejected; frozen policy inputs retain independent private copies.
- Operational inventory coverage now consumes real selected-input/native metadata
  receipts in portable integrity-only scans too. `reference-comparison` describes
  only the complete selected-reference list, not every installed instance.
  Report adjudication checks the frozen parent seal and rejects tampered coverage,
  findings, schema/exit changes and authority reconstructed from public JSON.

Namespace mapping, installed correspondence and equal bytes do not authenticate
publishers, prove benignness or show execution. A fully malicious acquisition child
fabricating both original bytes and matching receipts remains outside the existing
native acquisition boundary; parent parsing does not independently authenticate
filesystem acquisition or an immutable target.

## Limits, privacy and compatibility

Private capture is explicit for Bun grants with advisory checks, limited to
**512 KiB cumulative raw bytes /4096 raw rows**. Overflow clears the capture and
latches off, never authorizing an incomplete prefix. The complete private witness
must also fit the existing **1 MiB frame**, **8 MiB cumulative private encoded-byte
allowance** and channel limits. Original observations/evidence, raw inputs and
policy-material rows share4096; historical integrity witness lists retain their
separate4096-per-batch cap and share private bytes/channel traffic. There is no
claimed4096 global total for all witness kinds. Oversized, missing or incomplete
proof withholds Bun authority with coverage gaps, not an increased allowance.

Original bytes/private hashes remain outside public inventory/report JSON and
content-free errors. Local detail retains its explicit privacy contract. Repeated
parent validation is bounded but has not been worst-case benchmark-qualified.

Operational schema **1.8** distinguishes the new Bun origin marker and additive
scoped coverage from historical1.7. Old builders keep their contracts; new Bun
markers cannot silently render as an old schema. Public JSON cannot reconstruct
private rendering/policy authority. Published alpha.2/schema1.7 stays immutable.

## Regression checks

The source includes actual supervised CLI cases for both Bun categories, explicit
and absent/old grants, invalid old pins, unsupported contexts, own-manifest
conflicts, local/portable privacy and unchanged targets. Independent-reference Bun
cases cover equality, drift and wrong digest/origin/archive refusal. Causal scans
cover corrected ranges, changed-original exception invalidation, withdrawal and
retained old-generation behavior; unchanged acceptance is demonstrated on the
unchanged retained generation, not invented inside the corrected fixture.

Owned byte/endpoint/protocol regressions include fixed-receipt context and identity
substitution, cross-grant material, missing/corrupt/duplicate/oversized raw inputs,
copy/freeze mutation, capture exhaustion and private byte-slice transport. Baseline
source checks remain `go test ./...` and `go vet ./...` with the approved pinned
offline toolchain. Race checks cover inventory/matching, private execution admission
and actual CLI cases. The long existing execution compatibility test and remaining
execution tests can run as separate complete race partitions under the same
per-command deadline; a timed-out aggregate command is not reported as passing.

## Remaining beta gates

Whole-installed-scope reference accounting, both advisory categories' source/index
completeness, trusted native/source/artifact/platform acceptance and lifetime
resident observation still have incomplete required obligations. This increment
**does not deliver aggregate operational0/1**; preserve130>2>3>1>0 and actual late
output/close/query/reap failure adjudication. The report remains a pre-output
comparison snapshot, not a prediction of successful future finalization.

No new Windows runtime, native/performance campaign, producer acquisition, real
pilot, rights/security/signing change, publication or merge follows from these
source checks. Pnpm stays experimental and macOS deferred. Remaining beta work
continues under the plan; these limits cannot be removed to manufacture success.
