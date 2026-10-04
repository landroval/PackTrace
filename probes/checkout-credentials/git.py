import json, os, sys
from pathlib import Path

TASK = json.loads(Path('/case/task.json').read_text())
args = sys.argv[1:]
kind = TASK['kind']
post = TASK['post']

def event(name):
    path = Path('/case/events')
    data = (name + '\n').encode('ascii')
    if path.exists() and path.stat().st_size + len(data) > 65536:
        raise SystemExit(125)
    with open(path, 'ab') as out:
        out.write(data)

# The actual candidate fetch includes this exact global -c prefix.
prefix = args[:2] if args[:2] == ['-c', 'protocol.version=2'] else []
operation = args[2:] if prefix else args
if not operation or operation[0] not in {'--version', 'version', 'config', 'rev-parse', 'branch',
        'checkout', 'clean', 'reset', 'log', 'show', 'init', 'remote', 'submodule',
        'sparse-checkout', 'cat-file', 'for-each-ref', 'fetch'}:
    raise SystemExit(125)
lower = [a.lower() for a in operation]
include_write = (operation[0] == 'config' and any(a.startswith('includeif.') for a in lower)
                 and not any(a.startswith('--get') or a.startswith('--unset') for a in lower))
written = Path('/case/includes-written')
linked = written.exists()
if kind == 'git-missing' or (kind == 'post-no-git' and post):
    event('git-unavailable'); raise SystemExit(1)
if include_write:
    if kind == 'first-include' and not linked:
        event('first-include-denied'); raise SystemExit(1)
    event('include')
    written.write_text('true')
if (kind in {'enumeration', 'post-enumeration'} and linked and operation[0] == 'config'
        and '--name-only' in operation and '--get-regexp' in operation and any('includeif' in a for a in lower)):
    event('enumeration-denied'); raise SystemExit(2)
if (kind == 'unset' and linked and operation[0] == 'config'
        and '--unset-all' in operation and any(a.startswith('includeif.') for a in lower)):
    event('unset-denied'); raise SystemExit(5)
if (operation[0] == 'config' and '--file' in operation
        and any('/git-credentials-' in a and a.endswith('.config') for a in operation)
        and not any(a.startswith('--get') or a.startswith('--unset') for a in operation)):
    event('credential-file')
if operation[0] == 'fetch':
    if 'origin' not in operation or any(a.startswith(('http:', 'https:', 'ssh:', 'git@')) for a in operation):
        raise SystemExit(125)
    operation[operation.index('origin')] = '/case/remote'
    event('fetch-local')
# Sterile env/namespace and fixture remote are required: exec is not host authorization.
os.execve('/usr/bin/git', ['/usr/bin/git', *prefix, *operation], dict(os.environ))
