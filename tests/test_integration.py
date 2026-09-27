"""Actual qpdf and SSH signature checks on isolated copies of supplied artifacts."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from recovery.common import BuildError, digest, encoded
from recovery.engine import load_inputs, verify
from recovery.pdf import run


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('qpdf') and shutil.which('ssh-keygen'),
                     'qpdf and ssh-keygen required for artifact integration checks')
class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='shadow-test-artifacts-')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.repo = self.base / 'repo'
        self.repo.mkdir()
        (self.repo / 'shadows').mkdir()
        for name in ('route.json', 'shadow-manifest.json'):
            shutil.copyfile(ROOT / name, self.repo / name)
        for path in (ROOT / 'shadows').iterdir():
            os.link(path, self.repo / 'shadows' / path.name)

    def inventory(self):
        return json.loads((self.repo / 'shadow-manifest.json').read_bytes())

    def write_inventory(self, inventory):
        (self.repo / 'shadow-manifest.json').write_bytes(encoded(inventory))

    def attachment(self, key, shadow='shadow-001'):
        return run(['qpdf', '--show-attachment=' + key,
                    self.repo / 'shadows' / (shadow + '.pdf')])

    def replace_attachment(self, key, data, shadow='shadow-001'):
        source = self.repo / 'shadows' / (shadow + '.pdf')
        payload = self.base / 'attachment.bin'
        payload.write_bytes(data)
        updated = self.base / 'changed.pdf'
        run(['qpdf', source, '--remove-attachment=' + key,
             '--add-attachment', payload, '--key=' + key, '--', updated])
        updated.replace(source)  # Replace the hard link; never edit original bytes.
        inventory = self.inventory()
        inventory['records'][shadow]['shadow_sha256'] = digest(source.read_bytes())
        self.write_inventory(inventory)

    def test_missing_shadow_rejected_before_extraction(self):
        (self.repo / 'shadows/shadow-121.pdf').unlink()
        with self.assertRaisesRegex(BuildError, 'exactly the 121'):
            load_inputs(self.repo)

    def test_altered_shadow_rejected_before_extraction(self):
        path = self.repo / 'shadows/shadow-001.pdf'
        raw = path.read_bytes()
        path.unlink()
        path.write_bytes(raw + b'altered')
        with self.assertRaisesRegex(BuildError, 'Hash drift'):
            load_inputs(self.repo)

    def test_extra_shadow_rejected(self):
        (self.repo / 'shadows/extra.pdf').write_bytes(b'not a shadow')
        with self.assertRaisesRegex(BuildError, 'exactly the 121'):
            load_inputs(self.repo)

    def test_signature_drift_rejected_despite_rehashed_inventory(self):
        signature = self.attachment('watermark-signature.sig')
        self.replace_attachment('watermark-signature.sig', signature.replace(b'SSH', b'XXX', 1))
        with self.assertRaisesRegex(BuildError, 'signature check failed'):
            verify(self.repo)

    def test_signed_manifest_drift_rejected_despite_rehashed_inventory(self):
        manifest = json.loads(self.attachment('watermark-manifest.json'))
        manifest['canonical_outputs']['main.tex'] = '0' * 64
        self.replace_attachment('watermark-manifest.json', encoded(manifest))
        inventory = self.inventory()
        inventory['source_manifest_sha256'] = digest(encoded(manifest))
        self.write_inventory(inventory)
        with self.assertRaisesRegex(BuildError, 'signature check failed'):
            verify(self.repo)

    def test_reference_drift_rejected_despite_rehashed_inventory(self):
        raw = self.attachment('reference-fingerprint.json')
        self.replace_attachment('reference-fingerprint.json', raw + b' ')
        with self.assertRaisesRegex(BuildError, 'checks/reference-fingerprint.json'):
            verify(self.repo)

    def test_route_drift_rejected_despite_rehashed_inventory(self):
        path = self.repo / 'route.json'
        path.write_bytes(path.read_bytes() + b' ')
        inventory = self.inventory()
        inventory['route_sha256'] = digest(path.read_bytes())
        self.write_inventory(inventory)
        with self.assertRaisesRegex(BuildError, 'signed source route'):
            verify(self.repo)

    def test_source_part_drift_rejected_despite_rehashed_inventory(self):
        raw = self.attachment('source-part.bin')
        altered = bytes([raw[0] ^ 1]) + raw[1:]
        self.replace_attachment('source-part.bin', altered)
        inventory = self.inventory()
        inventory['records']['shadow-001']['source_part_sha256'] = digest(altered)
        self.write_inventory(inventory)
        with self.assertRaisesRegex(BuildError, 'inconsistent source part'):
            verify(self.repo)

    def test_source_map_copy_drift_rejected(self):
        raw = self.attachment('source-map.json', 'shadow-002')
        self.replace_attachment('source-map.json', raw + b' ', 'shadow-002')
        with self.assertRaisesRegex(BuildError, 'different source maps'):
            verify(self.repo)

    def test_mixed_source_bundle_rejected(self):
        raw = self.attachment('reference-fingerprint.json', 'shadow-002')
        self.replace_attachment('reference-fingerprint.json', raw + b' ', 'shadow-002')
        with self.assertRaisesRegex(BuildError, 'different signed source bundles'):
            verify(self.repo)

    def test_incorrect_independently_pinned_key_rejected(self):
        with self.assertRaisesRegex(BuildError, 'independently trusted fingerprint'):
            verify(self.repo, 'SHA256:' + 'A' * 43)

    def test_pdf_payload_drift_rejected_despite_rehashed_inventory(self):
        raw = self.attachment('recovery.pdf') + b'\nchanged\n'
        self.replace_attachment('recovery.pdf', raw)
        inventory = self.inventory()
        inventory['records']['shadow-001']['payload_sha256'] = digest(raw)
        self.write_inventory(inventory)
        with self.assertRaisesRegex(BuildError, 'embedded payload'):
            verify(self.repo)

    def test_sources_command_recovers_all_signed_clean_files(self):
        # Use a copied decoder and only the shadow distribution as input.
        shutil.copyfile(ROOT / 'recover.py', self.repo / 'recover.py')
        shutil.copytree(ROOT / 'recovery', self.repo / 'recovery',
                        ignore=shutil.ignore_patterns('__pycache__'))
        output = self.base / 'sources'
        process = subprocess.run([sys.executable, '-B', str(self.repo / 'recover.py'),
                                  'sources', '--output', str(output)],
                                 capture_output=True, timeout=120)
        self.assertEqual(process.returncode, 0, process.stderr.decode())
        signed = json.loads(self.attachment('watermark-manifest.json'))['canonical_outputs']
        recovered = {str(path.relative_to(output)): digest(path.read_bytes())
                     for path in output.rglob('*.tex')}
        self.assertEqual(recovered, signed)
        report = json.loads((output / 'source-verification.json').read_bytes())
        self.assertTrue(report['canonical_source_hashes_match_signed_manifest'])
        self.assertEqual(report['canonical_output_count'], 29)
        self.assertEqual(len(list(output.rglob('*.pdf'))), 0)


if __name__ == '__main__':
    unittest.main()
