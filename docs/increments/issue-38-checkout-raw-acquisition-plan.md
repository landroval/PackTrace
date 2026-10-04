# Selected checkout raw-file Acquisition Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans only after explicit approval of this actual manifest/procedure and its transfer permission. No agents, acquired-code execution or CI changes.

Status: **local draft; no raw-file acquisition authorized**.

**Goal:** I collect a bounded, identified corpus for later static assessment of the
pinned Action, without treating acquisition as dependency/license/security adoption.

**Architecture:** I use one external owned Python standard-library collector and a
frozen 37-file manifest. I fetch anonymous immutable raw URLs, compare actual byte
counts/Git blob identities to observed tree declarations, record measured SHA-256,
and retain each verified file under a fixed ordinal name outside the checkout.

**Tech Stack:** Existing Python standard library/TLS trust; no installed dependency,
package manager, Node/Go, Git clone/archive, runner or acquired-script invocation.

**Spec:** [Approved scope](issue-38-checkout-assessment-scope.md).
**Preceding evidence:** [Completed metadata bootstrap](issue-38-checkout-metadata-bootstrap-plan.md).
This artifact does not revise those approved documents or PR39's published head.

## Frozen selection, omissions and cumulative permission boundary

I select seven distribution/declaration/root-license files, six source files spanning
main/post/input/auth/Git operations, and all 24 publisher `.licenses/npm/` blob records
listed in the observed 113-entry tree. I do not select all source helpers, tests,
workflows, build/package-manager scripts, SDK sources, archives or new advisory queries.
The actual distribution contains additional compiled helpers; omitting their raw
source does not establish absence, coverage or source-to-bundle equivalence.

The candidate remains `3d3c42e5aac5ba805825da76410c181273ba90b1`, expected tree
`150e70ecad5ebf06a559a01ea3a56d9a3236d2b1`. Observed tree JSON SHA-256 is
`3bb7bedde1040f22b4afc6a731006c2a88d1f0a05314b837c8aa600d8381b402`.
Each exact GET URL is **the literal BASE plus its literal FILES path below**, in the
shown order; no response/caller-supplied path or URL is followed. The list is the
entire manifest, not a pattern or a directory-expansion permission.

| Budget | Consumed bootstrap / proposed raw phase |
| --- | --- |
| Requests | 2 already used + at most 37 new GET attempts = 39 of 40; no HEAD/retry/redirect |
| Raw expected bytes | 1,865,014 total; 1,452,503 bundle and 412,511 other text/metadata |
| Overall expected payload | 29,251 already read + 1,865,014 = 1,894,265 bytes |
| Error/overflow accounting | Read at most declared file size + one EOF-detection byte per attempt; <=1,865,051 new bytes |
| Scope text/metadata ceiling | 29,251 + 412,511 = 441,762 expected bytes of the 12-MiB ceiling; unsuccessful work counted too |
| Scope distribution/overall ceiling | Bundle <16 MiB; overall owned payload work remains <48 MiB, including sentinel bytes |
| Time | <=30 seconds per attempt, 10-second socket operations, <=1,200 seconds new phase; bootstrap 2.222604 seconds keeps combined collector elapsed <30 minutes |
| Retention | <=8 MiB new directory/script/receipt and bounded temporary file copy, within 128-MiB scope ceiling; no archive/extraction |
| Receipt | <=64 KiB; no raw source/header/environment/credential values printed |

**Only one request remains after 37 successful GETs.** This is not enough to promise
arbitrary dependency/advisory/source follow-up coverage. I cannot reset the 40-request
budget, use a new authentication/host, retry errors or declare full security coverage
by inference. Any needed expansion requires a scope revision and separate permission.
No new advisory query or allocation of that final request is part of this proposal.

Publisher `.dep.yml` filenames/content are claims, not an independently verified
actual bundled graph or complete license/notice compliance. I do not parse or execute
YAML/package scripts, follow lockfile URLs, resolve ranges, install dependencies,
generate notices, regenerate the bundle or acquire other content during collection.
Git blob SHA-1 agreement is content identity against received metadata declarations;
actual SHA-256 is retained separately. Neither proves publisher authentication,
reproducible build, current advisory completeness, safety or runtime cleanup.

## Review focus

1. Wrong identity/size: fail that file and stop; never qualify a prefix or change the pin.
2. Hidden transfer/auth fallback: fixed raw host, no proxy/credentials, redirects/retries/lockfile URLs.
3. Partial/error work: count attempts/received bytes independently; stop without reacquiring earlier successful files.
4. Resource ceilings: declared sizes plus sentinels, cumulative prior work and bounded retention/time/receipt; no claimed hard wire/RSS/native containment.
5. Notice/source omissions: acquired bytes are a future review corpus, not proof of complete bundling/licensing/security/platform qualification.

## Proposed complete collector and exact manifest — not executed

Only after approval, save the following block outside the repository as
`/tmp/packtrace-checkout-raw-collector.py`. It accepts no URL/path argument, reads no
credential/profile/private-key files, uses anonymous HTTPS and default verified TLS
trust, and disables environment proxies and redirects. It never imports/evaluates
acquired JavaScript/TypeScript/YAML/JSON as code or starts a child process.

```python
import hashlib, http.client, json, os, re, signal, sys, tempfile, time
import urllib.error, urllib.request
from pathlib import Path

COMMIT = '3d3c42e5aac5ba805825da76410c181273ba90b1'
BASE = 'https://raw.githubusercontent.com/actions/checkout/'+COMMIT+'/'
FILES = [
    ('action.yml', 5144, '5b0524f730db83f9513c18ab31a6c086c7239076'),
    ('LICENSE', 1097, 'a67dca8b4f65d6bd351f6b1e333ce2cd84d843a5'),
    ('package.json', 1580, '9b02e96595db9e2d3a735a8adbda17a61e56fd5f'),
    ('package-lock.json', 294209, 'faf0e22120b3e68dd2d480968fe3ae5227079ad4'),
    ('dist/index.js', 1452503, '06ae5d221b3dc83259d396ec60027972181e51b9'),
    ('dist/package.json', 23, '3dbc1ca591c0557e35b6004aeba250e6a70b56e3'),
    ('dist/problem-matcher.json', 253, '071f2cb4441a02d54d7e07af9145a8f4fb79ceca'),
    ('src/main.ts', 1169, 'f5f5f68234e25a4233eb041a32af6a8ad7cb401a'),
    ('src/git-source-provider.ts', 12701, 'b9c1d3575135fcb2aa0fac36662c400efeb6d8e3'),
    ('src/git-command-manager.ts', 21381, '8431658989171114643993ce31b6691fa9b5a410'),
    ('src/git-auth-helper.ts', 21925, 'dd7e6fbdb5387908190676a6ec9c4a828a044dea'),
    ('src/input-helper.ts', 7318, '9a98b8675e51ac5a9abbeca7703b0ce3f76031a2'),
    ('src/state-helper.ts', 1804, 'aa3eecc75f4f4078f60278ea3350eace0a4fb4c9'),
    ('.licenses/npm/@actions/core.dep.yml', 1303, '081715159ecd03858a85fe9ba117a92f70e374f2'),
    ('.licenses/npm/@actions/exec.dep.yml', 1303, '003562f8bc30ef3a98ef8fe4a8a931a1a42b88ab'),
    ('.licenses/npm/@actions/github.dep.yml', 1309, '2c221d7ee7c53a5477057832381996e6fb8564f8'),
    ('.licenses/npm/@actions/http-client-3.0.2.dep.yml', 1408, 'dd1f80dd78460715005f2049c59e272b69955eaa'),
    ('.licenses/npm/@actions/http-client-4.0.1.dep.yml', 1408, 'dc741537d30ae7aecfcc7579d03a43dcc7e20e42'),
    ('.licenses/npm/@actions/io.dep.yml', 1297, 'dadddb4ed5dd55c150cb912fb396d0e12d1534e7'),
    ('.licenses/npm/@actions/tool-cache.dep.yml', 1321, 'e7bf5bf0f0e814593117d1e9ee827a810593b84a'),
    ('.licenses/npm/@octokit/auth-token.dep.yml', 1393, '27b25043fb191ad878f135751d2e4f6b720e1fe0'),
    ('.licenses/npm/@octokit/core.dep.yml', 1381, '0d7056b20c9564f95efe3b805925a3112d00b983'),
    ('.licenses/npm/@octokit/endpoint.dep.yml', 1389, '62d348e3658eda297d225f79870bf06988d809ec'),
    ('.licenses/npm/@octokit/graphql.dep.yml', 1381, 'b407006cd517053b3d25cd1940622e5d6d057eb5'),
    ('.licenses/npm/@octokit/openapi-types.dep.yml', 1359, '5619d7b61f9eaf4d132abadd163af205b0946459'),
    ('.licenses/npm/@octokit/plugin-paginate-rest.dep.yml', 1376, 'd7afbb9e603cae8fbe0724f61455aadfe6d527ac'),
    ('.licenses/npm/@octokit/plugin-rest-endpoint-methods.dep.yml', 1407, 'a7ade1fa73ff8201bd3545e95ac156c5b43552ce'),
    ('.licenses/npm/@octokit/request-error.dep.yml', 1378, '021cab3ac1f55826fa34fc7768faec68a2099e7a'),
    ('.licenses/npm/@octokit/request.dep.yml', 1426, '2f10b29b296036312a49e05cbca9a81b0fb0bfe4'),
    ('.licenses/npm/@octokit/types.dep.yml', 1357, '5b37005a991a9e6fe4537cb94a767e2f295c0ef9'),
    ('.licenses/npm/before-after-hook.dep.yml', 12308, 'd47933488ce7aaa48ae27f1ba679388fb5f87c08'),
    ('.licenses/npm/content-type.dep.yml', 2087, '6fd1ccc9bbe1333b0fe12531406558c132d5a075'),
    ('.licenses/npm/json-with-bigint.dep.yml', 1364, 'ac5904459e13b100d7eff12a3c5779a1ce4b5728'),
    ('.licenses/npm/semver.dep.yml', 980, '1d9e9566aa17be7706b4996c8faa5459efd5be7d'),
    ('.licenses/npm/tunnel.dep.yml', 1488, '9a7111da96a36c81dd1160453ab32caa08c8707f'),
    ('.licenses/npm/undici.dep.yml', 1396, 'c46a5c7bff13518993f1b33ce194be381f516fde'),
    ('.licenses/npm/universal-user-agent.dep.yml', 1088, 'f49f39a32fcb440355efb483dd37c69d0bdd7d76')]

class Blocked(Exception):
    pass

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None

def expired(signum, frame):
    raise Blocked('deadline')

def owned_write(root, name, raw):
    fd = os.open(root/name, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as output:
        output.write(raw)

if len(FILES) != 37 or sum(size for path, size, sha in FILES) != 1865014:
    raise Blocked('manifest-not-approved')
root = Path(tempfile.mkdtemp(prefix='packtrace-checkout-raw-', dir='/tmp'))
receipt = {'candidate': COMMIT, 'state': 'incomplete', 'requests': [],
           'priorRequests': 2, 'priorBodyBytes': 29251, 'priorElapsedSeconds': 2.222604,
           'qualification': 'not-performed', 'acquiredCodeExecuted': False}
client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
started = time.monotonic()
signal.signal(signal.SIGALRM, expired)
success = False
try:
    for i, (path, size, blob) in enumerate(FILES, 1):
        remaining = 1200-(time.monotonic()-started)
        if remaining <= 0:
            raise Blocked('outer-deadline')
        signal.setitimer(signal.ITIMER_REAL, min(30, remaining))
        url = BASE+path
        row = {'id': i, 'url': url, 'expectedBytes': size, 'expectedGitBlobSHA1': blob,
               'state': 'incomplete', 'bodyBytesRead': 0}
        receipt['requests'].append(row)
        req = urllib.request.Request(url, headers={
            'User-Agent': 'PackTrace-pinned-static-corpus', 'Accept-Encoding': 'identity'})
        try:
            response = client.open(req, timeout=min(10, remaining))
        except urllib.error.HTTPError as error:
            response = error
        raw = bytearray()
        with response:
            row['status'] = response.status
            if response.status != 200 or response.geturl() != url:
                raise Blocked('status-or-redirect')
            if response.headers.get('Content-Encoding') not in (None, 'identity'):
                raise Blocked('encoded-body')
            length = response.headers.get('Content-Length')
            if length is not None:
                if len(length) > 10 or not re.fullmatch(r'[0-9]+', length):
                    raise Blocked('unqualified-declared-length')
                row['declaredBodyBytes'] = int(length)
                if int(length) != size:
                    raise Blocked('declared-size-mismatch')
            while True:
                try:
                    chunk = response.read(min(65536, size+1-len(raw)))
                except http.client.IncompleteRead as error:
                    row['bodyBytesRead'] += len(error.partial)
                    raise Blocked('incomplete-response')
                if not chunk:
                    break
                row['bodyBytesRead'] += len(chunk)
                if len(raw)+len(chunk) > size:
                    raise Blocked('actual-size-excess')
                raw.extend(chunk)
        if len(raw) != size:
            raise Blocked('actual-size-short')
        data = bytes(raw)
        actual = hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
        row['observedGitBlobSHA1'] = actual
        row['observedSHA256'] = hashlib.sha256(data).hexdigest()
        if actual != blob:
            raise Blocked('blob-identity-mismatch')
        name = f'{i:03}.data'
        owned_write(root, name, data)
        row.update({'filename': name, 'bytesRetained': len(data), 'state': 'verified-acquired-data'})
        signal.setitimer(signal.ITIMER_REAL, 0)
    receipt['state'] = 'completed-acquisition-only'
    success = True
except (Blocked, OSError, ValueError, http.client.HTTPException):
    receipt['failure'] = 'blocked-or-incomplete-acquisition'
finally:
    signal.setitimer(signal.ITIMER_REAL, 0)
receipt['elapsedSeconds'] = time.monotonic()-started
receipt['cumulativeRequests'] = receipt['priorRequests']+len(receipt['requests'])
receipt['cumulativeBodyBytesRead'] = receipt['priorBodyBytes']+sum(
    row['bodyBytesRead'] for row in receipt['requests'])
encoded = json.dumps(receipt, sort_keys=True).encode('utf-8')
if len(encoded) > 65536:
    encoded = b'{"state":"incomplete","failure":"receipt-limit","qualification":"not-performed"}'
    success = False
owned_write(root, 'receipt.json', encoded)
receipt = json.loads(encoded)
print(json.dumps({'ownedEvidenceDirectory': str(root), 'state': receipt['state'],
                  'cumulativeRequests': receipt.get('cumulativeRequests'),
                  'cumulativeBodyBytesRead': receipt.get('cumulativeBodyBytesRead')}))
sys.exit(0 if success else 1)
```

The proposed 30-minute cumulative acquisition-duration accounting counts active
collector phases, not owner-review/idle intervals, file age or freshness. A phase
cannot reset prior requests/read-byte work when it fails; later permission decisions
must review that actual cumulative evidence rather than assume a fresh allowance.

The collector's counters measure owned application payload reads, not HTTP headers,
TLS/DNS traffic, buffering outside its reader, service logs or hard peak RSS. Remaining
work/retention is conservative relative to scope ceilings; a nominal success is not
native hostile-code/archive/storage isolation. Partial or receipt/write failure
leaves the corpus incomplete. Earlier verified file rows survive a later failure;
I do not erase them, automatically prune/delete, restart the phase or replay GETs.

## Task: approve, acquire and verify this corpus only

- [ ] Approve this exact procedure/manifest and explicitly allocate up to 37 raw GET attempts from the remaining 38 scope requests. This does not grant the last request or any scope expansion.
- [ ] Obtain separate raw-transfer/owned-collector execution permission. Acquired-code execution, credential probes, static-review verdicts, agents, CI/publication/merge are absent.
- [ ] Before transferring, compare the actual candidate/tree receipt and every selected path/size/blob to the literal manifest, and verify no other assessment request has consumed budget since the two bootstrap GETs. Any missing evidence/changed manifest/additional consumption blocks automatic execution pending owner clarification.
- [ ] Save the unchanged approved collector block externally, confirm space for <=8 MiB, and execute only:

```nu
python3 /tmp/packtrace-checkout-raw-collector.py
```

- [ ] Independently read actual exit/receipt and each retained file; recompute byte counts, actual SHA-256 and Git blob SHA-1. Record completed-file counts separately from attempted requests/whole-corpus state; never sum reruns or infer missing files.
- [ ] Record acquisition-only outcome and remaining budget. Do not automatically parse lock/YAML into effective inventory, trace runtime credentials, visit embedded URLs, claim complete notice/security qualification or start the remaining request.
- [ ] Preserve approved assessment/bootstrap docs and published sibling bookmarks, checkpoint, global routing and unrelated default `.pi/todos` changes. Make only this local documentary change; no push, GitHub status mutation, workflow or source edit.

## Documentary acceptance expectations

No row is a fixture run, negative security finding or qualification claim.

| ID | Condition | Required observation/outcome |
| --- | --- | --- |
| D01 | Metadata pin/path/blob/size or remaining budget differs | Stop before raw GET; no replacement candidate/manifest or implicit allowance |
| D02 | HTTP error/redirect/proxy/auth suggestion | Count attempt, stop; no retry/new host/auth fallback |
| D03 | Declared/actual size excess/short, incomplete framing or encoded body | Count read work, reject that file; whole corpus incomplete |
| D04 | Correct byte size but Git blob mismatch | Reject identity; no qualified retained file row |
| D05 | Timeout/cancellation/write or receipt failure | Missing/incomplete evidence retained as such; no success from a prefix |
| D06 | Later request fails after valid earlier files | Preserve earlier row evidence without converting it to whole-corpus success or replay |
| D07 | All 37 files acquired and identities agree | Acquisition-only corpus; actual SHA-256 distinct from expected metadata/Git claim |
| D08 | License cache/source/package-lock omissions or conflicting claims | Defer actual assessment; no inferred complete graph/notice/safety verdict |
| D09 | 39 cumulative attempts after normal completion | One unallocated scope request remains; any need beyond it requires explicit scope revision |

Preparation verification: Python syntax only, all 37 literal triples/full URLs
compared locally to received tree metadata, roles/counts/expected sums, D01-D09
coverage and workspace preservation. No owned collector, transfer, behavioral test,
raw-source/notice/bundle review, agent or runtime/CI action has run while drafting.
