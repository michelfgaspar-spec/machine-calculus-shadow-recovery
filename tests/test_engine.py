"""Publication and failure behavior independent of expensive page rendering."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from recovery.common import BuildError
from recovery.engine import (_publish, _publish_directory, external_output,
                             reconstruct_directory, output_paths)


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='shadow-test-publish-')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.repo = self.base / 'repo'
        self.repo.mkdir()

    def test_directory_publish_is_complete_and_exclusive(self):
        source, output = self.base / 'ready', self.base / 'output'
        source.mkdir()
        (source / 'checked').write_bytes(b'all checked')
        _publish_directory(source, output)
        self.assertEqual((output / 'checked').read_bytes(), b'all checked')
        source.mkdir()
        (source / 'checked').write_bytes(b'replacement')
        with self.assertRaises((BuildError, FileExistsError)):
            _publish_directory(source, output)
        self.assertEqual((output / 'checked').read_bytes(), b'all checked')
        self.assertTrue(source.exists())

    def test_empty_directory_collision_is_not_overwritten(self):
        source, output = self.base / 'ready', self.base / 'output'
        source.mkdir()
        output.mkdir()
        with self.assertRaises((BuildError, FileExistsError)):
            _publish_directory(source, output)
        self.assertTrue(source.is_dir())
        self.assertTrue(output.is_dir())

    def test_file_publish_collision_rolls_back_only_our_files(self):
        first, second = self.base / 'first', self.base / 'second'
        first.write_bytes(b'checked first')
        second.write_bytes(b'checked second')
        output1, output2 = self.base / 'out1', self.base / 'out2'
        output2.write_bytes(b'preserve')
        with self.assertRaises(FileExistsError):
            _publish([(first, output1), (second, output2)])
        self.assertFalse(output1.exists())
        self.assertEqual(output2.read_bytes(), b'preserve')

    def test_link_failure_never_exposes_accepted_pdf(self):
        checked = self.base / 'checked'
        checked.write_bytes(b'verified bytes')
        output = self.base / 'book.pdf'
        with patch('recovery.engine.os.link', side_effect=OSError('injected failure')):
            with self.assertRaises(OSError):
                _publish([(checked, output)])
        self.assertFalse(output.exists())

    def test_output_must_be_external_and_new(self):
        with self.assertRaises(BuildError):
            external_output(self.repo, self.repo / 'recovered')
        git = self.base / '.git'
        git.write_bytes(b'gitdir: fixture')
        with self.assertRaises(BuildError):
            external_output(self.repo, self.base / 'recovered')
        git.unlink()
        (self.base / 'existing').mkdir()
        with self.assertRaises(BuildError):
            external_output(self.repo, self.base / 'existing')

    def test_symlink_output_ancestor_and_dangling_git_rejected(self):
        alias = self.base / 'alias'
        alias.symlink_to(self.repo, target_is_directory=True)
        with self.assertRaises(BuildError):
            external_output(self.repo, alias / 'recovered')
        (self.base / '.git').symlink_to(self.base / 'missing')
        with self.assertRaises(BuildError):
            external_output(self.repo, self.base / 'recovered')

    def test_report_collision_preserved_before_pdf_recovery(self):
        report = self.base / 'book-comparison.json'
        report.write_bytes(b'preserve')
        with self.assertRaises(BuildError):
            output_paths(self.repo, self.base / 'book.pdf')
        self.assertEqual(report.read_bytes(), b'preserve')

    def synthetic_extraction(self):
        return ({}, {}, {}, {'schema_version': 1}, {'main.tex': b'synthetic bytes'})

    def test_source_output_is_one_complete_tree(self):
        output = self.base / 'sources'
        with patch('recovery.engine.extract_verified', return_value=self.synthetic_extraction()), \
             patch('recovery.engine._require_tools'):
            reconstruct_directory(self.repo, output)
        self.assertEqual((output / 'main.tex').read_bytes(), b'synthetic bytes')
        self.assertTrue((output / 'source-verification.json').is_file())
        self.assertEqual(set(self.base.iterdir()), {self.repo, output})

    def test_all_comparison_failure_publishes_neither_source_nor_book(self):
        output = self.base / 'all'
        with patch('recovery.engine.extract_verified', return_value=self.synthetic_extraction()), \
             patch('recovery.engine._require_tools'), \
             patch('recovery.engine._checked_book', side_effect=BuildError('reference mismatch')):
            with self.assertRaisesRegex(BuildError, 'reference mismatch'):
                reconstruct_directory(self.repo, output, book=True)
        self.assertEqual(set(self.base.iterdir()), {self.repo})

    def test_directory_publish_failure_leaves_no_accepted_output(self):
        output = self.base / 'all'
        with patch('recovery.engine.extract_verified', return_value=self.synthetic_extraction()), \
             patch('recovery.engine._require_tools'), \
             patch('recovery.engine._publish_directory', side_effect=OSError('injected rename failure')):
            with self.assertRaisesRegex(OSError, 'injected rename failure'):
                reconstruct_directory(self.repo, output)
        self.assertEqual(set(self.base.iterdir()), {self.repo})

    def test_verification_failure_leaves_no_accepted_output(self):
        output = self.base / 'sources'
        with patch('recovery.engine.extract_verified', side_effect=BuildError('invalid signature')), \
             patch('recovery.engine._require_tools'):
            with self.assertRaisesRegex(BuildError, 'invalid signature'):
                reconstruct_directory(self.repo, output)
        self.assertEqual(set(self.base.iterdir()), {self.repo})


if __name__ == '__main__':
    unittest.main()
