"""Decode bounded source fragments against the inherited signed TeX hashes."""
import base64
import binascii
import json
from pathlib import PurePosixPath
import re

from .common import BuildError, _unique_pairs, check_hash, relative_path


MAX_STREAM_BYTES = 32 * 1024 * 1024
MAX_MAP_BYTES = 128 * 1024
MAX_PART_BYTES = 2 * 1024 * 1024
MAX_FILE_BYTES = 16 * 1024 * 1024


def strict_json(raw, context, limit):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= limit:
        raise BuildError('Invalid or oversized JSON: ' + context)
    def invalid_constant(value):
        raise BuildError('Non-finite JSON constant: ' + context)
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_pairs,
                           parse_constant=invalid_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise BuildError('Invalid JSON: ' + context) from exc
    if not isinstance(value, dict):
        raise BuildError('Expected a JSON object: ' + context)
    return value


def canonical_paths(paths):
    """Reject ambiguous paths even on case-insensitive target filesystems."""
    if not isinstance(paths, (list, dict)) or len(paths) != 29:
        raise BuildError('The canonical edition requires exactly 29 TeX paths')
    prefixes, files = {}, set()
    for path in paths:
        relative_path(path)
        if (not path.endswith('.tex') or len(path) > 512
                or any(ord(char) < 32 or ord(char) > 126 for char in path)):
            raise BuildError('Invalid canonical TeX path: ' + path)
        parts = path.split('/')
        for part in parts:
            if (len(part) > 255 or part.endswith((' ', '.'))
                    or re.search(r'[<>:"|?*]', part)
                    or part.casefold() == '.git'
                    or re.fullmatch(r'(?i)(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?', part)):
                raise BuildError('Unsafe canonical path component: ' + path)
        for index in range(1, len(parts) + 1):
            prefix = '/'.join(parts[:index])
            key = prefix.casefold()
            if key in prefixes and prefixes[key] != prefix:
                raise BuildError('Case-colliding canonical paths: ' + path)
            prefixes[key] = prefix
        key = path.casefold()
        if key in files:
            raise BuildError('Duplicate canonical path: ' + path)
        files.add(key)
    for path in paths:
        if any(str(parent).casefold() in files for parent in PurePosixPath(path).parents):
            raise BuildError('Conflicting canonical file and directory: ' + path)
    return set(paths)


def decode_stream(raw, canonical_outputs):
    expected = canonical_paths(canonical_outputs)
    value = strict_json(raw, 'canonical source stream', MAX_STREAM_BYTES)
    if (set(value) != {'schema_version', 'record_kind', 'files'}
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['record_kind'] != 'canonical-tex-stream-v1'
            or not isinstance(value['files'], list) or len(value['files']) != 29):
        raise BuildError('Invalid canonical source stream schema or file count')
    for item in value['files']:
        if not isinstance(item, dict) or set(item) != {'path', 'data_base64'}:
            raise BuildError('Invalid canonical source file record')
    paths = canonical_paths([item['path'] for item in value['files']])
    if paths != expected:
        raise BuildError('Canonical source file set differs from the signed manifest')
    result = {}
    for item in value['files']:
        path, data = item['path'], item['data_base64']
        if not isinstance(data, str) or len(data) > 4 * ((MAX_FILE_BYTES + 2) // 3):
            raise BuildError('Invalid or oversized source file: ' + path)
        try:
            decoded = base64.b64decode(data, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise BuildError('Invalid source base64: ' + path) from exc
        if len(decoded) > MAX_FILE_BYTES or base64.b64encode(decoded).decode('ascii') != data:
            raise BuildError('Noncanonical or oversized source base64: ' + path)
        check_hash(decoded, canonical_outputs[path], 'signed canonical source ' + path)
        result[path] = decoded
    return result


class SourceCollector:
    """Require all 121 distinct, consistent, hash-bound source fragments."""

    def __init__(self, raw_map, inventory, manifest):
        check_hash(raw_map, inventory['source_map_sha256'], 'source map')
        self.raw_map = raw_map
        self.mapping = strict_json(raw_map, 'source map', MAX_MAP_BYTES)
        value = self.mapping
        if (set(value) != {'schema_version', 'record_kind', 'source_manifest_sha256',
                          'source_stream_sha256', 'source_stream_bytes',
                          'canonical_output_count', 'parts'}
                or type(value['schema_version']) is not int or value['schema_version'] != 1
                or value['record_kind'] != 'canonical-tex-parts-v1'
                or type(value['canonical_output_count']) is not int
                or value['canonical_output_count'] != 29
                or type(value['source_stream_bytes']) is not int
                or not 121 <= value['source_stream_bytes'] <= MAX_STREAM_BYTES
                or value['source_manifest_sha256'] != inventory['source_manifest_sha256']
                or not isinstance(value['source_stream_sha256'], str)
                or not re.fullmatch(r'[0-9a-f]{64}', value['source_stream_sha256'])
                or not isinstance(value['parts'], dict)
                or set(value['parts']) != set(inventory['records'])
                or len(value['parts']) != 121):
            raise BuildError('Invalid canonical source map')
        indices, size = [], 0
        for name, part in value['parts'].items():
            record = inventory['records'][name]
            if (not isinstance(part, dict) or set(part) != {'index', 'sha256', 'bytes'}
                    or type(part['index']) is not int or not 0 <= part['index'] < 121
                    or type(part['bytes']) is not int or not 0 < part['bytes'] <= MAX_PART_BYTES
                    or not isinstance(part['sha256'], str)
                    or not re.fullmatch(r'[0-9a-f]{64}', part['sha256'])
                    or part['sha256'] != record['source_part_sha256']
                    or part['bytes'] != record['source_part_bytes']):
                raise BuildError('Invalid or inconsistent source part record: ' + name)
            indices.append(part['index'])
            size += part['bytes']
        if sorted(indices) != list(range(121)) or size != value['source_stream_bytes']:
            raise BuildError('Source parts do not form a complete stream partition')
        canonical_paths(manifest['canonical_outputs'])
        self.outputs = manifest['canonical_outputs']
        self.parts = {}

    def add(self, name, raw_map, part):
        if raw_map != self.raw_map:
            raise BuildError('Shadows carry different source maps: ' + name)
        if name not in self.mapping['parts'] or name in self.parts:
            raise BuildError('Unknown or duplicate source part: ' + name)
        expected = self.mapping['parts'][name]
        if len(part) != expected['bytes']:
            raise BuildError('Source part size drift: ' + name)
        check_hash(part, expected['sha256'], 'source part ' + name)
        self.parts[name] = part

    def finish(self):
        if set(self.parts) != set(self.mapping['parts']):
            raise BuildError('All 121 source parts are required')
        names = sorted(self.parts, key=lambda name: self.mapping['parts'][name]['index'])
        raw = b''.join(self.parts[name] for name in names)
        if len(raw) != self.mapping['source_stream_bytes']:
            raise BuildError('Source stream size drift')
        check_hash(raw, self.mapping['source_stream_sha256'], 'source stream')
        return decode_stream(raw, self.outputs)
