#!/usr/bin/env python3
"""Audit the supplied representation, including every reachable Git snapshot.

This catches accidental distribution of source/book artifacts. It is an explicit
inventory and content heuristic, not a security barrier against hidden data or
someone changing this checker. Recovery independently verifies signed outputs.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


TEXT_PATHS = frozenset({
    '.gitignore', 'AGENTS.md', 'README.md', 'LICENSE', 'NOTICE',
    'provenance.json', 'route.json', 'shadow-manifest.json', 'recover.py',
    'recovery/__init__.py', 'recovery/common.py', 'recovery/compare.py',
    'recovery/engine.py', 'recovery/pdf.py', 'recovery/route.py',
    'recovery/signature.py', 'recovery/source.py',
    'scripts/check_repository.py', 'tests/__init__.py',
    'tests/test_repository.py', 'tests/test_source.py', 'tests/test_engine.py',
    'tests/test_integration.py',
})
SHADOW_IDS = frozenset('shadow-%03d' % n for n in range(1, 122))
ASSET_PATHS = frozenset('shadows/' + name + '.pdf' for name in SHADOW_IDS)
ALLOWED_PATHS = TEXT_PATHS | ASSET_PATHS
FORBIDDEN_SUFFIXES = frozenset({
    '.tex', '.ltx', '.sty', '.cls', '.dtx', '.pdf', '.doc', '.docx', '.odt',
    '.rtf', '.zip', '.tar', '.gz', '.tgz', '.bz2', '.xz', '.7z', '.rar',
    '.png', '.jpg', '.jpeg', '.pgm', '.ppm', '.txt', '.log', '.aux',
})
MAX_TEXT_BYTES = 512 * 1024
SHA256 = re.compile(r'[0-9a-f]{64}')


class InventoryError(ValueError):
    """An unexpected artifact or incomplete historical audit."""


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise InventoryError('Duplicate JSON key: ' + key)
        value[key] = item
    return value


def _allowed_path(name):
    if name in ASSET_PATHS:
        return
    if Path(name).suffix.lower() in FORBIDDEN_SUFFIXES:
        raise InventoryError('Standalone manuscript/book/archive artifact: ' + name)
    if name not in TEXT_PATHS:
        raise InventoryError('Unexpected distribution path: ' + repr(name))


def _inspect_text(name, raw):
    if len(raw) > MAX_TEXT_BYTES:
        raise InventoryError('Oversized code/documentation/metadata file: ' + name)
    if b'\x00' in raw:
        raise InventoryError('Binary content in text file: ' + name)
    try:
        text = raw.decode('utf-8')
    except UnicodeError as exc:
        raise InventoryError('Non-UTF-8 content in text file: ' + name) from exc
    # Construct markers so the guard does not match its own source or tests.
    commands = ('document' + 'class', 'begin' + '{document}', 'end' + '{document}')
    if any(('\\' + marker) in text for marker in commands):
        raise InventoryError('TeX manuscript marker in text file: ' + name)
    tex_blocks = re.findall(r'\\(?:chapter|section|subsection|begin)\s*\{', text)
    if len(tex_blocks) >= 8:
        raise InventoryError('Repeated TeX manuscript blocks in text file: ' + name)
    magic = (b'%P' + b'DF-', b'P' + b'K\x03\x04', b'\x1f\x8b',
             b'BZ' + b'h', b'\xfd7zXZ\x00', b'Rar!\x1a\x07',
             b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1')
    if raw.startswith(magic) or raw[257:262] == b'ustar':
        raise InventoryError('Document/archive signature in text file: ' + name)
    if re.search(r'[A-Za-z0-9+/]{2048,}={0,2}', text):
        raise InventoryError('Large encoded payload in text file: ' + name)


def inspect_snapshot(entries, read, context):
    """entries maps paths to regular-file modes; read returns that snapshot's bytes."""
    for name, mode in entries.items():
        if mode not in (0o100644, 0o100755):
            raise InventoryError(context + ': symlink/submodule/nonregular path: ' + name)
        _allowed_path(name)
    missing = ASSET_PATHS - entries.keys()
    if missing:
        raise InventoryError(context + ': missing shadow PDFs: ' + ', '.join(sorted(missing)[:4]))
    if not {'shadow-manifest.json', 'route.json'} <= entries.keys():
        raise InventoryError(context + ': missing asset manifest or route')
    for name in sorted(entries.keys() & TEXT_PATHS):
        _inspect_text(name, read(name))
    try:
        manifest = json.loads(read('shadow-manifest.json'), object_pairs_hook=_pairs)
        records = manifest['records']
        if not isinstance(records, dict) or set(records) != SHADOW_IDS:
            raise InventoryError('Manifest must list exactly shadow-001 through shadow-121')
        route_hash = manifest['route_sha256']
        if not isinstance(route_hash, str) or not SHA256.fullmatch(route_hash):
            raise InventoryError('Invalid route hash')
        if hashlib.sha256(read('route.json')).hexdigest() != route_hash:
            raise InventoryError('Route bytes differ from the snapshot manifest')
        for shadow_id in sorted(SHADOW_IDS):
            expected = records[shadow_id]['shadow_sha256']
            if not isinstance(expected, str) or not SHA256.fullmatch(expected):
                raise InventoryError('Invalid shadow hash: ' + shadow_id)
            raw = read('shadows/' + shadow_id + '.pdf')
            if not raw.startswith(b'%PDF-'):
                raise InventoryError('Expected PDF shadow: ' + shadow_id)
            if hashlib.sha256(raw).hexdigest() != expected:
                raise InventoryError('Shadow bytes differ from the snapshot manifest: ' + shadow_id)
    except (KeyError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
        raise InventoryError(context + ': malformed shadow manifest') from exc
    return {'files': len(entries), 'shadow_pdfs': len(ASSET_PATHS)}


def inspect_filesystem(root):
    entries = {}
    pending = [root]
    while pending:
        directory = pending.pop()
        for path in directory.iterdir():
            name = path.relative_to(root).as_posix()
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode):
                raise InventoryError('Working tree symlink rejected: ' + name)
            if name == '.git':
                if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                    raise InventoryError('Invalid Git administration path')
                continue
            if stat.S_ISDIR(mode):
                pending.append(path)
            elif stat.S_ISREG(mode):
                entries[name] = 0o100755 if mode & 0o111 else 0o100644
            else:
                raise InventoryError('Working tree nonregular path: ' + name)
    return inspect_snapshot(entries, lambda name: (root / name).read_bytes(), 'working tree')


def _git(root, *args, optional=False):
    env = dict(os.environ, GIT_NO_REPLACE_OBJECTS='1', GIT_NO_LAZY_FETCH='1')
    result = subprocess.run(['git', '--no-replace-objects', '-C', str(root), *args],
                            capture_output=True, env=env, timeout=120)
    if result.returncode:
        if optional:
            return None
        raise InventoryError('Git audit failed: ' + result.stderr.decode(errors='replace').strip())
    return result.stdout


def _git_entries(raw, index=False):
    entries, objects = {}, {}
    for record in raw.split(b'\x00'):
        if not record:
            continue
        header, path = record.split(b'\t', 1)
        fields = header.decode('ascii').split()
        name = path.decode('utf-8')
        if index:
            mode, oid, stage = fields
            if stage != '0':
                raise InventoryError('Unmerged Git index: ' + name)
        else:
            mode, kind, oid = fields
            if kind != 'blob':
                raise InventoryError('Git submodule/nonblob path: ' + name)
        if name in entries:
            raise InventoryError('Duplicate Git path: ' + name)
        entries[name], objects[name] = int(mode, 8), oid
    return entries, objects


def inspect_history(root):
    if not (root / '.git').exists():
        raise InventoryError('--history requires an initialized Git repository at the audited root')
    top = _git(root, 'rev-parse', '--show-toplevel').decode().strip()
    if Path(top).resolve() != root:
        raise InventoryError('Git root differs from audited root')
    if _git(root, 'rev-parse', '--is-shallow-repository').strip() != b'false':
        raise InventoryError('Shallow history cannot provide a complete audit')
    if _git(root, 'config', '--get-regexp', r'^(extensions\.partialclone|remote\..*\.promisor)$', optional=True):
        raise InventoryError('Partial/promisor history cannot provide a complete audit')
    refs = _git(root, 'for-each-ref', '--format=%(refname)').decode().splitlines()
    for ref in refs:
        if ref.startswith('refs/replace/'):
            raise InventoryError('Replacement refs cannot provide a complete audit')
        target = _git(root, 'rev-parse', '--verify', ref).decode().strip()
        while _git(root, 'cat-file', '-t', target).strip() == b'tag':
            raw_tag = _git(root, 'cat-file', 'tag', target)
            _inspect_text('annotated tag ' + target, raw_tag)
            target = raw_tag.splitlines()[0].decode().removeprefix('object ')
        oid = _git(root, 'rev-parse', '--verify', ref + '^{}').decode().strip()
        if _git(root, 'cat-file', '-t', oid).strip() != b'commit':
            raise InventoryError('Noncommit ref may carry uninspected content: ' + ref)
    grafts = _git(root, 'rev-parse', '--git-path', 'info/grafts').decode().strip()
    grafts_path = Path(grafts)
    if not grafts_path.is_absolute():
        grafts_path = root / grafts_path
    if grafts_path.exists() and grafts_path.stat().st_size:
        raise InventoryError('Git grafts cannot provide a complete audit')
    commits = set(_git(root, 'rev-list', '--all').decode().splitlines())
    head = _git(root, 'rev-parse', '--verify', 'HEAD', optional=True)
    if head:
        commits.update(_git(root, 'rev-list', head.decode().strip()).decode().splitlines())
    # Cache by immutable blob ID; each tree still checks its own manifest/assets.
    cache = {}
    def check(raw, context, index=False):
        entries, objects = _git_entries(raw, index=index)
        def read(name):
            oid = objects[name]
            if oid not in cache:
                cache[oid] = _git(root, 'cat-file', 'blob', oid)
            return cache[oid]
        return inspect_snapshot(entries, read, context)
    staged = _git(root, 'ls-files', '--stage', '-z')
    if staged:
        check(staged, 'index', index=True)
    for commit in sorted(commits):
        try:
            _inspect_text('commit metadata ' + commit, _git(root, 'cat-file', 'commit', commit))
            check(_git(root, 'ls-tree', '-r', '-z', '--full-tree', commit), commit)
        except InventoryError as exc:
            raise InventoryError('Historical commit ' + commit + ': ' + str(exc)) from exc
    return {'reachable_commits_checked': len(commits), 'index_checked': bool(staged),
            'scope': 'all refs and HEAD ancestry; excludes unreachable objects and reflogs'}


def audit(root, history=False):
    root = Path(root).resolve()
    report = {'schema_version': 1, 'root': str(root), 'working_tree': inspect_filesystem(root)}
    if history:
        report['history'] = inspect_history(root)
    report['pass'] = True
    report['limit'] = ('Explicit inventory and accidental-content heuristics; '
                       'not proof against deliberate encoding or a modified checker.')
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--history', action='store_true')
    args = parser.parse_args(argv)
    try:
        print(json.dumps(audit(args.root, args.history), indent=2))
    except (InventoryError, OSError, UnicodeError, ValueError, subprocess.SubprocessError) as exc:
        print('error: ' + str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
