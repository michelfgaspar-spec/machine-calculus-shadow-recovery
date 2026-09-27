"""Verify every supplied shadow before reconstructing and accepting the book."""
import ctypes
import errno
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile

from .common import (BuildError, _destination, _unique_pairs, check_hash, digest,
                     encoded, read_bytes, read_json, safe_path)
from .compare import compare
from .pdf import _merge_payloads, run
from .route import validate_plan
from .signature import MANIFEST, SIGNATURE, PUBLIC_KEY, _bundle
from .source import SourceCollector, MAX_PART_BYTES


ATTACHMENTS = {
    'watermark-manifest.json': MANIFEST,
    'watermark-signature.sig': SIGNATURE,
    'watermark-key.pub': PUBLIC_KEY,
    'reconstruction-route.json': 'routes/shadows-v1.json',
    'reference-fingerprint.json': 'checks/reference-fingerprint.json',
}


def load_inputs(root):
    """Check the entire asset inventory before calling an external tool."""
    root = Path(root)
    plan = validate_plan(read_json(root, 'route.json'), expected_pages=242)
    if plan['frontmatter_pages'] != 15:
        raise BuildError('The canonical edition requires 15 frontmatter pages')
    manifest = read_json(root, 'shadow-manifest.json')
    fields = {'schema_version', 'record_kind', 'edition', 'page_count',
              'receipt_signed', 'route_sha256', 'source_manifest_sha256',
              'source_map_sha256', 'records'}
    if (set(manifest) != fields or manifest['record_kind'] != 'shadow-recovery-assets-v1'
            or manifest['edition'] != 'structural-2026-09-26'
            or type(manifest['page_count']) is not int or manifest['page_count'] != 242
            or manifest['receipt_signed'] is not False):
        raise BuildError('Invalid recovery asset manifest')
    check_hash(read_bytes(root, 'route.json'), manifest['route_sha256'], 'route')
    for key in ('source_manifest_sha256', 'source_map_sha256'):
        if not isinstance(manifest[key], str) or not re.fullmatch(r'[0-9a-f]{64}', manifest[key]):
            raise BuildError('Invalid inventory SHA-256: ' + key)
    records = manifest['records']
    ids = {item['id'] for item in plan['shadows']}
    if not isinstance(records, dict) or set(records) != ids:
        raise BuildError('Manifest must name exactly the 121 planned shadows')
    expected_names = {name + '.pdf' for name in ids}
    if {path.name for path in (root / 'shadows').iterdir()} != expected_names:
        raise BuildError('Shadow directory must contain exactly the 121 planned PDFs')
    for name in sorted(ids):
        record = records[name]
        if (not isinstance(record, dict)
                or set(record) != {'shadow_sha256', 'payload_sha256', 'page_count',
                                   'source_part_sha256', 'source_part_bytes'}
                or type(record['page_count']) is not int or record['page_count'] != 2
                or type(record['source_part_bytes']) is not int
                or not 0 < record['source_part_bytes'] <= MAX_PART_BYTES
                or not isinstance(record['source_part_sha256'], str)
                or not re.fullmatch(r'[0-9a-f]{64}', record['source_part_sha256'])):
            raise BuildError('Invalid two-page shadow record: ' + name)
        check_hash(read_bytes(root, 'shadows/' + name + '.pdf'),
                   record['shadow_sha256'], name)
    return plan, manifest


def _json(raw, context):
    try:
        value = json.loads(raw, object_pairs_hook=_unique_pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise BuildError('Invalid JSON in ' + context) from exc
    if not isinstance(value, dict):
        raise BuildError('Expected JSON object in ' + context)
    return value


def extract_verified(root, folder, expected_fingerprint=None, progress=None):
    """Authenticate source bytes and PDF payloads carried by every shadow."""
    plan, inventory = load_inputs(root)
    payloads = {}
    common_bundle = None
    manifest = None
    collector = None
    for index, entry in enumerate(plan['shadows'], 1):
        name = entry['id']
        record = inventory['records'][name]
        # Snapshot the checked bytes so all tool calls see the same package.
        raw = read_bytes(root, 'shadows/' + name + '.pdf')
        check_hash(raw, record['shadow_sha256'], name)
        shadow = folder / 'current-shadow.pdf'
        shadow.write_bytes(raw)
        if int(run(['qpdf', '--show-npages', shadow])) != 2:
            raise BuildError('Shadow preview must contain two pages: ' + name)
        metadata = {key: run(['qpdf', '--show-attachment=' + key, shadow])
                    for key in ATTACHMENTS}
        if common_bundle is None:
            common_bundle = metadata
            for key, relative in ATTACHMENTS.items():
                target = safe_path(folder, relative)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(metadata[key])
            manifest, _files, fingerprint = _bundle(folder, expected_fingerprint)
            check_hash(metadata['watermark-manifest.json'],
                       inventory['source_manifest_sha256'], 'source manifest')
            for relative in ('routes/shadows-v1.json', 'checks/reference-fingerprint.json'):
                check_hash(read_bytes(folder, relative),
                           manifest['source_files'].get(relative), relative)
            if metadata['reconstruction-route.json'] != read_bytes(root, 'route.json'):
                raise BuildError('Recovery route differs from the signed source route')
        elif metadata != common_bundle:
            raise BuildError('Shadows carry different signed source bundles: ' + name)
        source_map = run(['qpdf', '--show-attachment=source-map.json', shadow])
        if collector is None:
            collector = SourceCollector(source_map, inventory, manifest)
        source_part = run(['qpdf', '--show-attachment=source-part.bin', shadow])
        collector.add(name, source_map, source_part)
        origin = _json(run(['qpdf', '--show-attachment=origin.json', shadow]), name)
        identity = {
            'shadow_id': name, 'source_pages': entry['pages'],
            'watermark_id': manifest['watermark_id'],
            'repository_url': manifest['repository_url'],
            'public_key_fingerprint': manifest['signing']['public_key_fingerprint'],
            'canonical_source_commit': manifest['canonical_source_commit'],
            'source_manifest_sha256': digest(common_bundle['watermark-manifest.json']),
        }
        if any(origin.get(key) != value for key, value in identity.items()):
            raise BuildError('Shadow identity differs from its signed route: ' + name)
        payload = run(['qpdf', '--show-attachment=recovery.pdf', shadow])
        check_hash(payload, record['payload_sha256'], name + ' payload')
        check_hash(payload, origin.get('payload_sha256'), name + ' embedded payload')
        target = folder / (name + '.pdf')
        target.write_bytes(payload)
        if int(run(['qpdf', '--show-npages', target])) != 2:
            raise BuildError('Recovery payload must contain two pages: ' + name)
        payloads[name] = target
        if progress and (index % 20 == 0 or index == len(plan['shadows'])):
            progress('Verified %d/121 shadows, PDF payloads and source parts' % index)
    sources = collector.finish()
    identity = {
        'SourceRepository': manifest['repository_url'],
        'SourceWatermark': manifest['watermark_id'],
        'SourceManifestSHA256': digest(common_bundle['watermark-manifest.json']),
        'SourceKeyFingerprint': fingerprint,
    }
    summary = {
        'schema_version': 1, 'shadow_count': len(payloads), 'page_count': 242,
        'source_signature_verified': True, 'public_key_fingerprint': fingerprint,
        'fingerprint_pinned': expected_fingerprint is not None,
        'trust_scope': ('Matched caller-supplied fingerprint' if expected_fingerprint else
                        'Bundled key consistency; no independent identity authentication'),
        'all_shadow_and_payload_hashes_match': True,
        'all_embedded_source_bundles_match': True,
        'all_embedded_source_maps_match': True,
        'canonical_output_count': len(sources),
        'canonical_source_hashes_match_signed_manifest': True,
        'source_stream_sha256': collector.mapping['source_stream_sha256'],
        'source_stream_bytes': collector.mapping['source_stream_bytes'],
        'canonical_outputs': {path: digest(raw) for path, raw in sorted(sources.items())},
    }
    return plan, payloads, identity, summary, sources


def verify(root, expected_fingerprint=None, progress=None):
    with tempfile.TemporaryDirectory(prefix='shadow-verify-') as temporary:
        return extract_verified(root, Path(temporary), expected_fingerprint, progress)[3]


def external_output(root, output):
    destination = _destination(output)
    root = Path(root).resolve()
    if destination == root or root in destination.parents:
        raise BuildError('Recovered artifacts must remain outside this repository')
    if any(os.path.lexists(parent / '.git') for parent in destination.parents):
        raise BuildError('Recovered artifacts must remain outside any Git worktree')
    return destination


def output_paths(root, output):
    destination = external_output(root, output)
    if destination.suffix.lower() != '.pdf':
        raise BuildError('Choose an output filename ending in .pdf')
    return (destination,
            _destination(destination.with_name(destination.stem + '-comparison.json')),
            _destination(destination.with_name(destination.stem + '-navigation.json')))


def _publish(items):
    """Link complete checked files exclusively, placing the accepted PDF last."""
    created = []
    try:
        for source, destination in items:
            os.link(source, destination)
            created.append((source, destination))
    except BaseException:
        for source, destination in reversed(created):
            if destination.exists() and os.path.samestat(source.stat(), destination.lstat()):
                destination.unlink()
        raise


def _publish_directory(source, destination):
    """One exclusive rename exposes the complete checked tree, never a prefix."""
    if sys.platform == 'win32':
        os.rename(source, destination)  # Windows rename refuses an existing target.
        return
    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform == 'darwin':
        function = library.renamex_np
        function.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        function.restype = ctypes.c_int
        result = function(os.fsencode(source), os.fsencode(destination), 4)  # RENAME_EXCL
    elif sys.platform.startswith('linux') and hasattr(library, 'renameat2'):
        function = library.renameat2
        function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                             ctypes.c_char_p, ctypes.c_uint]
        function.restype = ctypes.c_int
        result = function(-100, os.fsencode(source), -100, os.fsencode(destination), 1)
    else:
        raise BuildError('Exclusive directory publication requires macOS, Linux or Windows')
    if result:
        code = ctypes.get_errno()
        if code in (errno.EEXIST, errno.ENOTEMPTY):
            raise BuildError('Output appeared during recovery; preserved existing destination')
        raise OSError(code, os.strerror(code), str(destination))


def _require_tools(book=True):
    tools = ('qpdf', 'ssh-keygen') + (('pdfinfo', 'pdftotext', 'pdftoppm') if book else ())
    for tool in tools:
        if shutil.which(tool) is None:
            raise BuildError('Required recovery tool unavailable: ' + tool)


def _checked_book(folder, plan, payloads, identity, summary, progress):
    candidate = folder / 'candidate.pdf'
    if progress:
        progress('Assembling 242 pages and restoring navigation')
    navigation = _merge_payloads(payloads, plan, candidate, folder, identity)
    if progress:
        progress('Comparing extracted text and all 242 page renders')
    comparison = compare(folder / 'checks/reference-fingerprint.json', candidate, render=True)
    if not comparison['pass']:
        raise BuildError('Recovered book differs from signed reference fingerprints: ' +
                         json.dumps(comparison))
    comparison['shadow_verification'] = summary
    comparison['recovery_inputs'] = '121 shadow PDFs; no external TeX, full-book PDF, or network input'
    checked_report = folder / 'comparison.json'
    checked_report.write_bytes(encoded(comparison))
    checked_navigation = folder / 'navigation-report.json'
    checked_navigation.write_bytes(encoded(navigation))
    return candidate, checked_report, checked_navigation


def reconstruct(root, output, expected_fingerprint=None, progress=None):
    destination, comparison_path, navigation_path = output_paths(root, output)
    _require_tools()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='shadow-recover-', dir=destination.parent) as temporary:
        folder = Path(temporary)
        plan, payloads, identity, summary, _sources = extract_verified(
            root, folder, expected_fingerprint, progress)
        candidate, checked_report, checked_navigation = _checked_book(
            folder, plan, payloads, identity, summary, progress)
        _publish([(checked_report, comparison_path), (checked_navigation, navigation_path),
                  (candidate, destination)])
    return destination


def reconstruct_directory(root, output, expected_fingerprint=None, progress=None, book=False):
    """Recover source-only or all artifacts as one exclusively published directory."""
    destination = external_output(root, output)
    _require_tools(book=book)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='shadow-recover-', dir=destination.parent) as temporary:
        folder = Path(temporary)
        plan, payloads, identity, summary, sources = extract_verified(
            root, folder, expected_fingerprint, progress)
        ready = folder / 'ready'
        ready.mkdir()
        source_root = ready / 'source' if book else ready
        for relative, raw in sources.items():
            target = safe_path(source_root, relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        report = dict(summary, record_kind='canonical-tex-recovery-v1')
        (ready / 'source-verification.json').write_bytes(encoded(report))
        if book:
            candidate, comparison, navigation = _checked_book(
                folder, plan, payloads, identity, summary, progress)
            candidate.rename(ready / 'book.pdf')
            comparison.rename(ready / 'comparison.json')
            navigation.rename(ready / 'navigation.json')
        _publish_directory(ready, destination)
    return destination
