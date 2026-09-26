# Increment 4: manifests and declared dependencies

Status: written specification approved, including the declaration bound and
neutral error prefix. The [implementation plan](04-manifest-declarations-plan.md)
and explicit execution authorization remain to be approved. Authority:
[design decisions](../design-decisions.md).

## Deliverable and interfaces

Read `package.json` bytes and project dependency declarations as a distinct evidence
class, never as resolved or installed versions. Standard library only, no I/O.
Reuse the existing strict JSON validation and [field states](03-npm-locked-records.md).

```go
type ManifestDocument struct {
    SHA256 [32]byte
    Fields map[string]json.RawMessage
}

type DeclaredDependency struct {
    Name        string
    Requirement string
    State       FieldState
}

type DependencyGroup struct {
    Name    string
    State   FieldState
    Entries []DeclaredDependency
}

type ManifestProjection struct {
    SourceSHA256 [32]byte
    Groups       []DependencyGroup
}

func ParseManifest(data []byte) (ManifestDocument, error)
func ProjectManifest(doc ManifestDocument) (ManifestProjection, error)
```

These are internal types, not the public report/IPC schema. `DeclaredDependency.State`
applies to the requirement's JSON type, not validity of its name or requirement syntax.

## Reader contract

- Accept exactly one JSON object, including `{}`. No required name/version and no
  lockfile-version interpretation. Preserve every field as `json.RawMessage`,
  including unknown fields, scripts, peer metadata, precise numbers, nulls, and
  package-manager hints. Never execute or discover configuration from those fields.
- Enforce the approved **2 MiB manifest byte bound** and **128-container nesting**
  limit; reject duplicate keys at every level, malformed/trailing JSON, invalid
  UTF-8, and unpaired Unicode surrogates exactly as the lockfile reader does.
- Preserve SHA-256 of the original bytes and ownership independence from later
  input mutation. Caller must not mutate input concurrently. Failure returns a
  zero document and a controlled `ParseError`, never partial evidence or raw errors.
- Factor the existing strict object decoding into one private shared function;
  no copied Unicode/duplicate/depth validator or parser framework. The lockfile
  reader retains its 64 MiB bound and v2/v3 acceptance behavior.
- Generalize `ParseError.Error()` from `npm lockfile: CODE` to **`inventory: CODE`**
  for both readers and projections. Existing categories and `Code` stay unchanged.
  This explicitly supersedes the earlier internal error-prefix contract; no other
  existing API/type name changes or compatibility wrappers are needed.

## Declaration projection

- Consume an unchanged successful `ParseManifest` result, with no concurrent
  mutation. Basic guards are not authentication or revalidation of forged documents.
- Always return four groups, in this order: `dependencies`, `devDependencies`,
  `optionalDependencies`, `peerDependencies`. A missing group is `FieldAbsent`,
  JSON null is `FieldNull`, an object is `FieldValue`, and another JSON type is
  `FieldInvalidType`. Non-value groups have nil entries; a valid empty object has
  a non-nil empty entries slice. A bad group does not erase usable other groups.
- For object groups, emit one entry per decoded key, sorted by Go string order.
  Preserve each name exactly. Requirement strings become `FieldValue`, including
  empty strings. Null becomes `FieldNull`; other types become `FieldInvalidType`.
  Non-value requirements have an empty string value. A present declaration cannot
  be `FieldAbsent`; that state describes missing groups, not invented entries.
- Reuse the existing scalar decoder internally. Do not resolve SemVer ranges,
  aliases (`npm:`), file/workspace/Git/URL requirements, or infer concrete versions,
  origins, installed locations, optional availability, or execution.
- Preserve the same name appearing in multiple groups as distinct declarations.
  No optional/dev/peer precedence or merging; peer metadata remains raw evidence.
- Copy the source digest; evidence locators are the group and exact declaration key.
  Do not mutate the raw document or duplicate its unknown fields in the projection.
  Returned strings/groups must be independent of later input-document mutation.
- Nil `Fields` returns `ParseError{Code: "invalid-shape"}` and a zero projection.
  Empty parsed `{}` succeeds with four absent groups, not a safety/completeness claim.

## Additional work bound

Project at most **20,000 declarations total per manifest across all four groups**.
Count each membership, including null/wrong-type requirements and repeated names
in different groups. Decode each raw group object under the 2 MiB input bound,
then check its count against the remaining allowance before sorting/allocating its
output entries. Exceeding the bound returns `limit-exceeded` and a zero projection,
never a usable prefix. The reader itself still accepts larger declaration counts
within its byte/depth limits. This does not redefine the installed-instance budget
or promise hard memory/runtime limits.

## Acceptance and exclusions

Require synthetic RED/GREEN and root tests/vet covering: both readers' preserved
strict validation; exact 2 MiB/128-depth boundaries; raw retention/digests/ownership;
all group/requirement states; malformed fields beside usable groups; stable ordering;
repeated names, aliases and non-registry strings without interpretation; raw scripts
and peer metadata untouched; nil versus empty; and combined 20,000/20,001 counts,
including repeated names across groups and invalid/null memberships.

No target access, discovery/workspace expansion, package-manager execution, CLI,
matching, origin validation, installed inventory, report/redaction implementation,
new dependency, native probe, SCALIBR change, or producer/native qualification.
