# Checkout commit/tree metadata bootstrap Acquisition Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans only after separate approval of this actual procedure and exact transfer permission. No new agents or acquired-code execution are authorized.

Status: **local procedure draft; no acquisition permission**.

**Goal:** I obtain two bounded public metadata objects to prepare the later exact
raw-file assessment manifest, without acquiring the Action bundle or qualifying it.

**Architecture:** I use one proposed external, one-off Python standard-library
collector, with anonymous fixed-URL HTTPS, no redirects/proxies/retries or credentials.
I retain opaque response bytes and a compact operation receipt outside the repository;
commit/tree relations are checked as metadata claims, not build/publisher proof.

**Tech Stack:** Existing Python 3 standard library and existing system TLS trust.
No installation, Node/Go/package manager, runner, repository clone/archive or CI.

**Spec:** [Approved assessment scope](issue-38-checkout-assessment-scope.md).
This procedure narrows its ceilings; it does not approve the entire assessment's
40-request/48-MiB potential allowance or grant any follow-up acquisition.

## Exact manifest and boundaries

Candidate commit: `3d3c42e5aac5ba805825da76410c181273ba90b1`.
Expected tree from historical named-text consultation:
`150e70ecad5ebf06a559a01ea3a56d9a3236d2b1`. A different relation stops the procedure;
I do not substitute a new tree, tag, branch or candidate.

| Order | Fixed GET URL | Fixed output name |
| --- | --- | --- |
| 1 | `https://api.github.com/repos/actions/checkout/git/commits/3d3c42e5aac5ba805825da76410c181273ba90b1` | `commit.json` |
| 2 | `https://api.github.com/repos/actions/checkout/git/trees/150e70ecad5ebf06a559a01ea3a56d9a3236d2b1?recursive=1` | `tree.json` |

- Exactly two possible GETs, in order; the second is reached only after valid commit metadata. No HEAD, retries, redirects, pagination, raw-file/subtree requests or authenticated fallback.
- Each retained response <=1 MiB; an EOF-detection read may consume one additional byte before rejecting excess. Maximum body bytes read <=2 MiB+2, within the approved scope's larger response/cumulative ceilings. I count rejected/error responses too.
- 10-second socket operations, 30-second acquisition/parse deadline per object, 120-second outer control deadline; timeout/cancellation is not completion. Signals/deadlines are operational limits, not native hard real-time containment.
- At most 10,000 tree entries; `truncated` must explicitly be false. Missing/partial metadata cannot establish file absence or full-bundle coverage.
- Fresh owned directory under `/tmp`, mode 0700, fixed data/receipt names mode 0600, no overwrite/reuse; retained data plus receipt <4 MiB. No input path is used as a filesystem destination.
- <=64 KiB receipt, no raw headers/environment/authentication values or commit-author personal fields printed. Public candidate commit metadata may contain publisher author/signature fields; I retain it as opaque local data, not a public report.
- Anonymous HTTPS to `api.github.com` only, verified by default TLS; no token, `.netrc`, proxy, custom client certificate/insecure option, browser/profile, `gh` authenticated fallback or account-setting change.
- I do not run acquired bytes. The only later executable is the separately approved owned collector; no acquired bundle, Git/Node/Go/test/fixture/workflow is invoked.

## Review focus

1. Wrong pin/tree binding: reject before requesting an unapproved replacement URL.
2. Size/status/timeout failures: count work, preserve partial phase state, never continue by retry or claim completed collection.
3. Duplicate JSON keys, malformed/partial JSON or truncated tree: leave metadata incomplete, never infer an absent dependency/distribution.
4. Redirect/proxy/authentication temptation on 403/429: stop without broadening permission.
5. A successful metadata collection: no dependency/license/security/runtime adoption verdict or automatic raw-file transfer.

## Proposed complete collector — not executed

Save this block only after separate permission, outside the repository, as
`/tmp/packtrace-checkout-metadata-collector.py`. I do not create/run that script during
documentary preparation. It has no target or caller-supplied URL argument.

```python
import hashlib, http.client, json, os, re, signal, sys, tempfile, time
import urllib.error, urllib.request
from pathlib import Path

COMMIT = '3d3c42e5aac5ba805825da76410c181273ba90b1'
TREE = '150e70ecad5ebf06a559a01ea3a56d9a3236d2b1'
CAP = 1024 * 1024
MANIFEST = [
    ('commit', 'https://api.github.com/repos/actions/checkout/git/commits/'+COMMIT, 'commit.json'),
    ('tree', 'https://api.github.com/repos/actions/checkout/git/trees/'+TREE+'?recursive=1', 'tree.json')]

class Blocked(Exception):
    pass

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None

def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Blocked('duplicate-json-key')
        result[key] = value
    return result

def expired(signum, frame):
    raise Blocked('operation-timeout')

def owned_write(root, name, raw):
    fd = os.open(root/name, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as output:
        output.write(raw)

root = Path(tempfile.mkdtemp(prefix='packtrace-checkout-metadata-', dir='/tmp'))
receipt = {'candidate': COMMIT, 'expectedTree': TREE, 'state': 'incomplete',
           'requests': [], 'rawFilesAcquired': False, 'qualification': 'not-performed'}
client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
started = time.monotonic()
signal.signal(signal.SIGALRM, expired)
success = False
try:
    for role, url, filename in MANIFEST:
        remaining = 120-(time.monotonic()-started)
        if remaining <= 0:
            raise Blocked('outer-timeout')
        signal.setitimer(signal.ITIMER_REAL, min(30, remaining))
        row = {'role': role, 'url': url, 'state': 'incomplete', 'bodyBytesRead': 0}
        receipt['requests'].append(row)
        req = urllib.request.Request(url, headers={
            'User-Agent': 'PackTrace-pinned-metadata-review',
            'Accept': 'application/vnd.github+json',
            'Accept-Encoding': 'identity', 'X-GitHub-Api-Version': '2022-11-28'})
        try:
            response = client.open(req, timeout=min(10, remaining))
        except urllib.error.HTTPError as error:
            response = error
        raw = bytearray()
        with response:
            row['status'] = response.status
            length = response.headers.get('Content-Length')
            if length is not None:
                if len(length) > 10 or not re.fullmatch(r'[0-9]+', length) or int(length) > CAP:
                    raise Blocked('declared-length-unqualified')
                row['declaredBodyBytes'] = int(length)
            while True:
                chunk = response.read(min(65536, CAP+1-len(raw)))
                if not chunk:
                    break
                row['bodyBytesRead'] += len(chunk)
                if len(raw)+len(chunk) > CAP:
                    raise Blocked('response-limit')
                raw.extend(chunk)
            if length is not None and len(raw) != int(length):
                raise Blocked('incomplete-declared-body')
            if response.status != 200 or response.geturl() != url:
                raise Blocked('http-status-or-redirect')
        data = bytes(raw)
        row['bytesRetained'] = len(data)
        row['sha256'] = hashlib.sha256(data).hexdigest()
        owned_write(root, filename, data)
        obj = json.loads(data.decode('utf-8'), object_pairs_hook=unique)
        if not isinstance(obj, dict):
            raise Blocked('metadata-not-object')
        if role == 'commit':
            if obj.get('sha') != COMMIT or not isinstance(obj.get('tree'), dict) or obj['tree'].get('sha') != TREE:
                raise Blocked('commit-tree-relation-mismatch')
        else:
            entries = obj.get('tree')
            if obj.get('sha') != TREE or obj.get('truncated') is not False or not isinstance(entries, list):
                raise Blocked('tree-shape-or-truncation')
            if len(entries) > 10000 or not all(isinstance(e, dict) for e in entries):
                raise Blocked('tree-entry-limit-or-shape')
            paths = set()
            modes = {'tree': {'040000'}, 'commit': {'160000'},
                     'blob': {'100644', '100755', '120000'}}
            for entry in entries:
                path, kind, mode, sha = (entry.get(k) for k in ('path', 'type', 'mode', 'sha'))
                if (not isinstance(path, str) or not path or '\x00' in path
                    or path in paths or not isinstance(kind, str) or kind not in modes
                    or not isinstance(mode, str) or mode not in modes[kind]
                    or not isinstance(sha, str)
                    or not re.fullmatch(r'[0-9a-f]{40}', sha)):
                    raise Blocked('unqualified-tree-entry')
                if kind == 'blob' and (type(entry.get('size')) is not int or entry['size'] < 0):
                    raise Blocked('unqualified-declared-blob-size')
                path.encode('utf-8')
                paths.add(path)
            row['entryCount'] = len(entries)
        row['state'] = 'completed-metadata'
        signal.setitimer(signal.ITIMER_REAL, 0)
    receipt['state'] = 'completed-metadata-only'
    success = True
except (Blocked, OSError, ValueError, RecursionError, http.client.HTTPException):
    receipt['failure'] = 'blocked-or-incomplete-metadata'
finally:
    signal.setitimer(signal.ITIMER_REAL, 0)
receipt['elapsedSeconds'] = time.monotonic()-started
encoded = json.dumps(receipt, sort_keys=True).encode('utf-8')
if len(encoded) > 65536:
    encoded = b'{"state":"incomplete","failure":"receipt-limit","qualification":"not-performed"}'
    success = False
owned_write(root, 'receipt.json', encoded)
print(json.dumps({'ownedEvidenceDirectory': str(root), 'receipt': json.loads(encoded)}))
sys.exit(0 if success else 1)
```

I retain malformed/identity-rejected metadata files as unqualified local observations;
no consumer reads them as a complete manifest. On excess/status/network failure a
body may not be retained; its row remains incomplete. A missing receipt/write failure
is also incomplete, not success. No cleanup/prune/delete permission is bundled here.
The directory is an owned evidence location, not scanner/native-safe-storage evidence.

## Approval and future operation steps

- [ ] Obtain approval of this exact two-URL manifest, collector, limits and evidence semantics. Written approval alone does not make a request.
- [ ] Obtain explicit transfer/owned-collector execution permission for these two anonymous metadata GETs only. No bundle/raw source or actual Action/runner execution is included.
- [ ] Verify candidate/collector text still equals the approved proposal and local output space is available. Do not change URLs, trust settings or authentication to bypass a failure.
- [ ] If authorized, save the exact block to the external filename and run only:

```nu
python3 /tmp/packtrace-checkout-metadata-collector.py
```

- [ ] Read actual exit/status/receipt, request count, received/retained bytes and hashes; independently inspect the two saved JSON objects and relations. Never manufacture a completed second response after first-phase failure.
- [ ] Use completed tree metadata to propose the next explicit raw-file URL/size/blob manifest for owner review. Do not follow entry `url` fields, fetch blobs, execute scripts or incrementally consume the rest of the assessment allowance automatically.
- [ ] Preserve PR39/sibling/default/checkpoint/routing identities and record the limited outcome without GitHub/public status mutations or adoption claims.

## Documentary acceptance table

These conditions are review expectations, **not executed collector tests**.

| ID | Condition | Required result |
| --- | --- | --- |
| M01 | Wrong commit/tree relation | First phase rejected; second fixed GET not made |
| M02 | Excess/status/network/TLS/deadline | Work counted; incomplete receipt; no retry/auth/proxy fallback |
| M03 | Redirect or different effective URL | Rejected; no new destination/request |
| M04 | Duplicate/malformed/partial JSON or non-object | Rejected metadata; no qualified manifest |
| M05 | Truncation missing/true, wrong tree, excessive/duplicate/malformed entries or declared-length mismatch | Incomplete tree/body; no absence/coverage inference |
| M06 | Two objects satisfy all bounded checks | Completed metadata only; no raw bundle/license/runtime qualification |
| M07 | Missing/oversized/unwritten receipt | Incomplete evidence, never a successful qualification |
| M08 | New raw-file manifest proposed after tree | Separate review/transfer permission before any next request |

Preparation checks are local links/whitespace, Python syntax only, exact manifest,
M01-M08 mapping and preserved workspaces/bookmarks. No behavioral fixture, HTTP
request, raw file, distribution, agent, runner, publication or acquisition was
performed by drafting this procedure.
