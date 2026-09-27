"""Representation regressions use only tiny synthetic shadows and local Git."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from scripts.check_repository import InventoryError, SHADOW_IDS, audit


class RepositoryInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='shadow-inventory-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        (self.root / 'shadows').mkdir()
        route = b'{"schema_version": 1}\n'
        (self.root / 'route.json').write_bytes(route)
        self.manifest = {
            'records': {}, 'route_sha256': hashlib.sha256(route).hexdigest(),
        }
        for name in sorted(SHADOW_IDS):
            raw = b'%PDF-1.7\nsynthetic inventory fixture ' + name.encode() + b'\n'
            (self.root / 'shadows' / (name + '.pdf')).write_bytes(raw)
            self.manifest['records'][name] = {'shadow_sha256': hashlib.sha256(raw).hexdigest()}
        self.write_manifest()

    def write_manifest(self):
        (self.root / 'shadow-manifest.json').write_text(json.dumps(self.manifest))

    def git(self, *args):
        return subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', '-c',
                               'commit.gpgsign=false', '-C', str(self.root), *args],
                              check=True, capture_output=True).stdout

    def init(self):
        if not shutil.which('git'):
            self.skipTest('Git required for historical fixtures')
        self.git('init', '--template=')
        self.git('config', 'user.name', 'Inventory Test')
        self.git('config', 'user.email', 'inventory-test@example.invalid')

    def commit(self):
        self.git('add', '-A')
        self.git('commit', '-m', 'Synthetic inventory fixture')
        return self.git('rev-parse', 'HEAD').decode().strip()

    def test_pre_git_inventory_works(self):
        report = audit(self.root)
        self.assertTrue(report['pass'])
        self.assertEqual(report['working_tree']['shadow_pdfs'], 121)

    def test_history_requires_git_at_this_root(self):
        with self.assertRaisesRegex(InventoryError, 'initialized Git'):
            audit(self.root, history=True)

    def test_standalone_manuscript_formats_rejected_even_if_ignored(self):
        (self.root / '.gitignore').write_text('*\n')
        for suffix in ('.tex', '.PDF', '.doc', '.docx', '.zip', '.tar.gz', '.txt'):
            with self.subTest(suffix=suffix):
                path = self.root / ('manuscript' + suffix)
                path.write_text('synthetic content')
                with self.assertRaisesRegex(InventoryError, 'Standalone'):
                    audit(self.root)
                path.unlink()

    def test_unexpected_code_and_packager_paths_rejected(self):
        for name in ('build.py', 'pack_sources.py', 'recovery/extra.py'):
            with self.subTest(name=name):
                path = self.root / name
                path.parent.mkdir(exist_ok=True)
                path.write_text('# synthetic code\n')
                with self.assertRaisesRegex(InventoryError, 'Unexpected'):
                    audit(self.root)
                path.unlink()

    def test_symlink_asset_and_symlink_directory_rejected(self):
        asset = self.root / 'shadows/shadow-001.pdf'
        raw = asset.read_bytes()
        asset.unlink()
        asset.symlink_to('shadow-002.pdf')
        with self.assertRaisesRegex(InventoryError, 'symlink'):
            audit(self.root)
        asset.unlink()
        asset.write_bytes(raw)
        (self.root / 'recovery').symlink_to('shadows', target_is_directory=True)
        with self.assertRaisesRegex(InventoryError, 'symlink'):
            audit(self.root)

    def test_nonregular_path_rejected(self):
        import os
        os.mkfifo(self.root / 'README.md')
        with self.assertRaisesRegex(InventoryError, 'nonregular'):
            audit(self.root)

    def test_missing_extra_and_mutated_assets_rejected(self):
        asset = self.root / 'shadows/shadow-001.pdf'
        raw = asset.read_bytes()
        asset.unlink()
        with self.assertRaisesRegex(InventoryError, 'missing shadow'):
            audit(self.root)
        asset.write_bytes(raw + b'changed')
        with self.assertRaisesRegex(InventoryError, 'Shadow bytes differ'):
            audit(self.root)
        asset.write_bytes(raw)
        (self.root / 'shadows/shadow-122.pdf').write_bytes(raw)
        with self.assertRaisesRegex(InventoryError, 'Standalone'):
            audit(self.root)

    def test_non_pdf_asset_rejected_even_with_matching_hash(self):
        raw = b'not a PDF'
        (self.root / 'shadows/shadow-001.pdf').write_bytes(raw)
        self.manifest['records']['shadow-001']['shadow_sha256'] = hashlib.sha256(raw).hexdigest()
        self.write_manifest()
        with self.assertRaisesRegex(InventoryError, 'Expected PDF'):
            audit(self.root)

    def test_plain_manuscript_hidden_in_allowed_doc_rejected(self):
        (self.root / 'README.md').write_text('\\' + 'document' + 'class{book}\n')
        with self.assertRaisesRegex(InventoryError, 'TeX manuscript marker'):
            audit(self.root)

    def test_tex_fragment_hidden_in_allowed_code_rejected(self):
        (self.root / 'recover.py').write_text(('\\' + 'section{Synthetic}\n') * 8)
        with self.assertRaisesRegex(InventoryError, 'Repeated TeX manuscript'):
            audit(self.root)

    def test_binary_and_long_encoding_hidden_in_doc_rejected(self):
        for raw in (b'P' + b'K\x03\x04\x00synthetic', b'A' * 3000, b'\xffbad encoding'):
            with self.subTest(raw=raw[:8]):
                (self.root / 'README.md').write_bytes(raw)
                with self.assertRaises(InventoryError):
                    audit(self.root)

    def test_duplicate_manifest_keys_rejected(self):
        path = self.root / 'shadow-manifest.json'
        path.write_text('{"records":{},' + path.read_text()[1:])
        with self.assertRaisesRegex(InventoryError, 'Duplicate JSON key'):
            audit(self.root)

    def test_route_drift_rejected(self):
        (self.root / 'route.json').write_bytes(b'{}\n')
        with self.assertRaisesRegex(InventoryError, 'Route bytes differ'):
            audit(self.root)

    def test_history_checks_each_snapshots_own_manifest(self):
        self.init()
        self.commit()
        path = self.root / 'shadows/shadow-001.pdf'
        raw = path.read_bytes() + b'% allowed repackaging\n'
        path.write_bytes(raw)
        self.manifest['records']['shadow-001']['shadow_sha256'] = hashlib.sha256(raw).hexdigest()
        self.write_manifest()
        self.commit()
        report = audit(self.root, history=True)
        self.assertEqual(report['history']['reachable_commits_checked'], 2)

    def test_deleted_historical_manuscript_is_rejected(self):
        self.init()
        path = self.root / 'manuscript.docx'
        path.write_text('synthetic forbidden artifact')
        self.commit()
        path.unlink()
        self.commit()
        with self.assertRaisesRegex(InventoryError, 'Historical commit.*Standalone'):
            audit(self.root, history=True)

    def test_history_also_checks_other_branches(self):
        self.init()
        clean = self.commit()
        path = self.root / 'main.tex'
        path.write_text('synthetic forbidden artifact')
        forbidden = self.commit()
        self.git('branch', 'source-leak', forbidden)
        self.git('checkout', '--detach', clean)
        with self.assertRaisesRegex(InventoryError, 'Historical commit.*Standalone'):
            audit(self.root, history=True)

    def test_historical_hash_drift_is_rejected_after_repair(self):
        self.init()
        path = self.root / 'shadows/shadow-001.pdf'
        original = path.read_bytes()
        path.write_bytes(original + b'corruption')
        self.commit()
        path.write_bytes(original)
        self.commit()
        with self.assertRaisesRegex(InventoryError, 'Historical commit.*Shadow bytes differ'):
            audit(self.root, history=True)

    def test_forbidden_staged_file_rejected_after_worktree_removal(self):
        self.init()
        self.commit()
        path = self.root / 'main.tex'
        path.write_text('synthetic forbidden artifact')
        self.git('add', 'main.tex')
        path.unlink()
        with self.assertRaisesRegex(InventoryError, 'Standalone'):
            audit(self.root, history=True)

    def test_historical_symlink_rejected(self):
        self.init()
        path = self.root / 'README.md'
        path.symlink_to('route.json')
        self.commit()
        path.unlink()
        path.write_text('Synthetic documentation\n')
        self.commit()
        with self.assertRaisesRegex(InventoryError, 'Historical commit.*symlink'):
            audit(self.root, history=True)

    def test_staged_submodule_rejected(self):
        self.init()
        commit = self.commit()
        self.git('update-index', '--add', '--cacheinfo', '160000,' + commit + ',recovery/extra')
        with self.assertRaisesRegex(InventoryError, 'submodule'):
            audit(self.root, history=True)

    def test_noncommit_ref_rejected(self):
        self.init()
        self.commit()
        blob = self.git('rev-parse', 'HEAD:route.json').decode().strip()
        self.git('update-ref', 'refs/tags/hidden-blob', blob)
        with self.assertRaisesRegex(InventoryError, 'Noncommit ref'):
            audit(self.root, history=True)

    def test_shallow_and_promisor_repositories_rejected(self):
        self.init()
        commit = self.commit()
        (self.root / '.git/shallow').write_text(commit + '\n')
        with self.assertRaisesRegex(InventoryError, 'Shallow history'):
            audit(self.root, history=True)
        (self.root / '.git/shallow').unlink()
        self.git('config', 'remote.origin.promisor', 'true')
        with self.assertRaisesRegex(InventoryError, 'Partial/promisor'):
            audit(self.root, history=True)


if __name__ == '__main__':
    unittest.main()
