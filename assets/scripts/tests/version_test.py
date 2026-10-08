"""Version namespace, projection drift, and artifact identity regression tests."""

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / 'version.py'
spec = importlib.util.spec_from_file_location('authcrunch_version', SCRIPT)
version = importlib.util.module_from_spec(spec)
spec.loader.exec_module(version)


class VersionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='authcrunch-version-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'VERSION').write_text('1.1.41\n')
        api = self.root / 'assets/openapi/content/openapi.yaml'
        api.parent.mkdir(parents=True, exist_ok=True)
        api.write_text('openapi: 3.1.1\ninfo:\n  title: Fixture\n  version: 1.1.41\n  description: Fixture API\n')
        for target in version.TARGETS:
            path = self.root / target
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('app.SetVersion(appVersion, "1.1.41")\n'
                            'app.SetGitBranch(gitBranch, "")\n'
                            'app.SetGitCommit(gitCommit, "")\n')

    def test_valid_version_and_exact_tag(self):
        self.assertEqual(version.check_version(self.root, 'v1.1.41'), '1.1.41')
        with self.assertRaises(ValueError):
            version.check_version(self.root, 'v1.1.42')

    def test_namespace_rejects_noncanonical_versions(self):
        for text in ('2.0.0', '0.1.0', '1.01.2', '1.1.02', 'v1.1.41',
                     '1.1.41-rc1', '1.1.41+build', '1.1.41\n\n', ' 1.1.41',
                     '1.1', '1.1.41\nother', '1.1.18446744073709551615'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                (self.root / 'VERSION').write_text(text)
                version.read_version(self.root)

    def test_all_projection_versions_and_metadata_are_checked(self):
        for target in version.TARGETS:
            path = self.root / target
            baseline = path.read_text()
            for old, new in (('1.1.41', '1.1.40'), ('gitBranch, ""', 'gitBranch, "main"'),
                             ('gitCommit, ""', 'gitCommit, "old-sha"')):
                with self.subTest(target=target, field=old):
                    path.write_text(baseline.replace(old, new))
                    with self.assertRaises(ValueError):
                        version.check_version(self.root)
                    path.write_text(baseline)
            path.write_text(baseline + 'app.SetVersion(appVersion, "1.1.41")\n')
            with self.assertRaises(ValueError):
                version.check_version(self.root)
            path.write_text(baseline)

    def test_openapi_projection_check_and_sync(self):
        api = self.root / version.OPENAPI_SOURCE
        original = api.read_bytes()
        api.write_bytes(original.replace(b'1.1.41', b'1.1.40'))
        with self.assertRaisesRegex(ValueError, 'OpenAPI info.version'):
            version.check_version(self.root)
        with patch.object(version.subprocess, 'run') as run:
            self.assertEqual(version.sync_version(self.root), '1.1.41')
            self.assertEqual(run.call_count, len(version.TARGETS))
        self.assertEqual(api.read_bytes(), original)

    def test_ambiguous_openapi_fails_before_go_sync(self):
        api = self.root / version.OPENAPI_SOURCE
        original = api.read_bytes()
        for malformed in (original + b'---\n{}\n', original.replace(b'  version:', b'  "version":'),
                          original.replace(b'  version: 1.1.41', b'  version: 1.1.41\n  version: 1.1.41')):
            api.write_bytes(malformed)
            with patch.object(version.subprocess, 'run') as run, self.assertRaises(ValueError):
                version.sync_version(self.root)
            run.assert_not_called()
            self.assertEqual(api.read_bytes(), malformed)
        api.write_bytes(original)

    def test_patch_and_minor_arithmetic(self):
        self.assertEqual(version.next_version('1.1.41', 'patch'), '1.1.42')
        self.assertEqual(version.next_version('1.1.41', 'minor'), '1.2.0')
        with self.assertRaises(ValueError):
            version.next_version('1.1.41', 'major')
        with self.assertRaises(ValueError):
            version.next_version('2.1.41', 'patch')
        with self.assertRaises(ValueError):
            version.next_version('1.1.18446744073709551614', 'patch')

    def test_artifact_identity_binds_version_time_and_commit(self):
        sha = 'abcdef0123456789' * 2 + 'abcdef01'
        self.assertEqual(version.artifact_identity('1.1.41', sha, 'branch', 'main',
                         '20260911T130000Z'), 'v1.1.41_20260911T130000Z_abcdef012345')
        self.assertEqual(version.artifact_identity('1.1.41', sha, 'tag', 'v1.1.41'), 'v1.1.41')
        for values in (('1.1.41', sha, 'tag', 'v1.1.40'),
                       ('1.1.41', 'abc', 'branch', 'main'),
                       ('1.1.41', sha, 'other', 'main'),
                       ('2.1.41', sha, 'branch', 'main')):
            with self.subTest(values=values), self.assertRaises(ValueError):
                version.artifact_identity(*values)
        with self.assertRaises(ValueError):
            version.artifact_identity('1.1.41', sha, 'branch', 'main', 'bad\noutput=1')


if __name__ == '__main__':
    unittest.main()
