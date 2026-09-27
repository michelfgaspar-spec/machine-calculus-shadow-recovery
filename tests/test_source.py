"""Requirement-based cases for authenticated, bounded source recovery."""
import base64
import copy
import unittest

from recovery.common import BuildError, digest, encoded
from recovery.source import (SourceCollector, canonical_paths, decode_stream,
                             strict_json, MAX_STREAM_BYTES)


def fixture(files=None, outputs=None):
    files = files or {'main.tex': b'synthetic main\n', **{
        'chapters/part-%02d.tex' % index: ('synthetic part %d\n' % index).encode()
        for index in range(28)}}
    value = {'schema_version': 1, 'record_kind': 'canonical-tex-stream-v1', 'files': [
        {'path': path, 'data_base64': base64.b64encode(raw).decode()}
        for path, raw in files.items()]}
    raw = encoded(value)
    ids = ['shadow-%03d' % index for index in range(1, 122)]
    pieces = {name: raw[len(raw) * index // 121:len(raw) * (index + 1) // 121]
              for index, name in enumerate(ids)}
    mapping = {'schema_version': 1, 'record_kind': 'canonical-tex-parts-v1',
               'source_manifest_sha256': digest(b'synthetic signed manifest'),
               'source_stream_sha256': digest(raw), 'source_stream_bytes': len(raw),
               'canonical_output_count': 29, 'parts': {
                   name: {'index': index, 'sha256': digest(pieces[name]), 'bytes': len(pieces[name])}
                   for index, name in enumerate(ids)}}
    inventory = {'source_map_sha256': digest(encoded(mapping)),
                 'source_manifest_sha256': mapping['source_manifest_sha256'], 'records': {
                     name: {'source_part_sha256': item['sha256'], 'source_part_bytes': item['bytes']}
                     for name, item in mapping['parts'].items()}}
    manifest = {'canonical_outputs': outputs or {path: digest(data) for path, data in files.items()}}
    return files, value, raw, pieces, mapping, inventory, manifest


class SourceTests(unittest.TestCase):
    def setUp(self):
        (self.files, self.value, self.raw, self.pieces, self.mapping,
         self.inventory, self.manifest) = fixture()

    def collector(self, mapping=None):
        return SourceCollector(encoded(mapping or self.mapping), self.inventory, self.manifest)

    def test_all_parts_recover_exact_bytes_independent_of_arrival_order(self):
        collector = self.collector()
        for name in reversed(self.pieces):
            collector.add(name, encoded(self.mapping), self.pieces[name])
        self.assertEqual(collector.finish(), self.files)

    def test_every_part_is_required(self):
        collector = self.collector()
        for name in list(self.pieces)[:-1]:
            collector.add(name, encoded(self.mapping), self.pieces[name])
        with self.assertRaisesRegex(BuildError, 'All 121'):
            collector.finish()

    def test_duplicate_part_rejected(self):
        collector = self.collector()
        name = next(iter(self.pieces))
        collector.add(name, encoded(self.mapping), self.pieces[name])
        with self.assertRaisesRegex(BuildError, 'duplicate'):
            collector.add(name, encoded(self.mapping), self.pieces[name])

    def test_part_bit_drift_and_length_drift_rejected(self):
        name = next(iter(self.pieces))
        for raw in (b'X' + self.pieces[name][1:], self.pieces[name] + b'X'):
            with self.subTest(raw=raw[:5]), self.assertRaises(BuildError):
                self.collector().add(name, encoded(self.mapping), raw)

    def test_map_copy_drift_rejected(self):
        name = next(iter(self.pieces))
        with self.assertRaisesRegex(BuildError, 'different source maps'):
            self.collector().add(name, encoded(self.mapping) + b' ', self.pieces[name])

    def test_fully_rehashed_unsigned_stream_still_fails_signed_canonical_hash(self):
        changed = dict(self.files, **{'main.tex': b'forged manuscript\n'})
        _, _, _, pieces, mapping, inventory, manifest = fixture(
            changed, outputs=self.manifest['canonical_outputs'])
        collector = SourceCollector(encoded(mapping), inventory, manifest)
        for name, raw in pieces.items():
            collector.add(name, encoded(mapping), raw)
        with self.assertRaisesRegex(BuildError, 'signed canonical source main.tex'):
            collector.finish()

    def test_rehashed_stream_digest_drift_rejected(self):
        self.mapping['source_stream_sha256'] = '0' * 64
        self.inventory['source_map_sha256'] = digest(encoded(self.mapping))
        collector = self.collector()
        for name, raw in self.pieces.items():
            collector.add(name, encoded(self.mapping), raw)
        with self.assertRaisesRegex(BuildError, 'source stream'):
            collector.finish()

    def test_partition_constraints(self):
        for field, value in [('index', 1), ('index', True), ('bytes', 0),
                             ('bytes', True), ('sha256', 'bad')]:
            with self.subTest(field=field, value=value):
                mapping = copy.deepcopy(self.mapping)
                mapping['parts']['shadow-001'][field] = value
                self.inventory['source_map_sha256'] = digest(encoded(mapping))
                with self.assertRaises(BuildError):
                    self.collector(mapping)

    def test_map_schema_bounds_and_identity(self):
        for field, value in [('source_stream_bytes', MAX_STREAM_BYTES + 1),
                             ('source_manifest_sha256', '0' * 64),
                             ('canonical_output_count', True), ('schema_version', True),
                             ('record_kind', 'wrong'), ('extra', 1)]:
            with self.subTest(field=field):
                mapping = dict(self.mapping, **{field: value})
                self.inventory['source_map_sha256'] = digest(encoded(mapping))
                with self.assertRaises(BuildError):
                    self.collector(mapping)

    def test_stream_exact_file_set_required(self):
        for replacement in (self.value['files'][:-1],
                            self.value['files'] + [self.value['files'][0]],
                            self.value['files'][:-1] + [{'path': 'other.tex', 'data_base64': ''}]):
            with self.subTest(count=len(replacement)), self.assertRaises(BuildError):
                decode_stream(encoded(dict(self.value, files=replacement)), self.manifest['canonical_outputs'])

    def test_duplicate_and_case_colliding_paths_rejected(self):
        for replacement in ('main.tex', 'MAIN.tex', 'Chapters/other.tex'):
            value = copy.deepcopy(self.value)
            value['files'][-1]['path'] = replacement
            with self.subTest(path=replacement), self.assertRaises(BuildError):
                decode_stream(encoded(value), self.manifest['canonical_outputs'])

    def test_unsafe_paths_rejected_even_if_canonical_hash_map_agrees(self):
        for unsafe in ('../escape.tex', '/absolute.tex', 'a/../b.tex', 'a//b.tex',
                       'a\\b.tex', 'a\x00b.tex', 'a:b.tex', '.git/a.tex',
                       'trailing. /b.tex', 'NUL.tex', 'a\nb.tex', 'café.tex'):
            outputs = dict(self.manifest['canonical_outputs'])
            outputs[unsafe] = outputs.pop('main.tex')
            with self.subTest(path=unsafe), self.assertRaises(BuildError):
                canonical_paths(outputs)

    def test_file_directory_collision_rejected(self):
        paths = list(self.files)
        paths[-1] = 'main.tex/part.tex'
        with self.assertRaisesRegex(BuildError, 'Conflicting'):
            canonical_paths(paths)

    def test_strict_base64(self):
        for data in ('!!!!', 'Zg=', 'Zg===', 'Zh==', 'Zg==\n', 'é', None):
            value = copy.deepcopy(self.value)
            value['files'][0]['data_base64'] = data
            with self.subTest(data=data), self.assertRaises(BuildError):
                decode_stream(encoded(value), self.manifest['canonical_outputs'])

    def test_strict_json(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'[]', b'\xff',
                    b'{"a":' + b'[' * 1500 + b']' * 1500 + b'}'):
            with self.subTest(raw=raw[:12]), self.assertRaises(BuildError):
                strict_json(raw, 'test', 10000)
        with self.assertRaises(BuildError):
            strict_json(b'{"a":1}', 'test', 2)


if __name__ == '__main__':
    unittest.main()
