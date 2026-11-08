#!/usr/bin/env python3
"""Tests for stage_engine.py with a small fake engine package (python3 -m unittest)."""
import hashlib
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import stage_engine as se  # noqa: E402

FILES = {
    'vanta-chromium.exe': b'MZ fake engine',
    'chrome.dll': b'MZ fake dll' * 1000,
    'locales/en-US.pak': b'pak',
    'resources.pak': b'res',
}


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def package(d: Path, files=FILES, extra=(), exe_sum=None) -> Path:
    """What package_engine.py writes: the zip and its two-line SHA256SUMS."""
    src = d / 'dl'
    src.mkdir()
    z = src / se.ZIP
    with zipfile.ZipFile(z, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f'{se.TOP}/', b'')
        for name, data in files.items():
            zf.writestr(f'{se.TOP}/{name}', data)
        for name, data in extra:
            zf.writestr(name, data)
    exe = exe_sum or sha(files.get(se.EXE, b''))
    (src / se.SUMS).write_text(f'{sha(z.read_bytes())}  {se.ZIP}\n{exe}  {se.TOP}/{se.EXE}\n')
    return src


class StageEngineTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        self.version = self.d / 'VERSION'
        self.version.write_text('156.0.8078.79\n')
        self.dest = self.d / 'src-tauri' / 'engine-bundle'
        self.cfg = self.d / 'src-tauri' / 'tauri.engine.json'
        self.dest.parent.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def run_stage(self, src):
        return se.stage(src, self.dest, self.version, self.cfg)

    def test_stages_files_sums_version_and_overlay(self):
        src = package(self.d)
        self.assertEqual(self.run_stage(src), len(FILES))
        for name, data in FILES.items():
            self.assertEqual((self.dest / name).read_bytes(), data)
        self.assertEqual((self.dest / 'VERSION').read_text(), '156.0.8078.79\n')
        lines = (self.dest / se.SUMS).read_text().splitlines()
        # The original two lines first, verbatim; then one line per other file.
        self.assertEqual(lines[:2], (src / se.SUMS).read_text().splitlines())
        listed = {l.split('  ', 1)[1]: l.split('  ', 1)[0] for l in lines}
        for name, data in FILES.items():
            self.assertEqual(listed[f'{se.TOP}/{name}'], sha(data))
        self.assertEqual(len(lines), 1 + len(FILES))
        # Exactly the grammar vanta-core's parse_sums accepts.
        for l in lines:
            self.assertRegex(l, r'^[0-9a-f]{64}  [^\\]+$')
            self.assertNotIn('..', l)
        self.assertEqual(json.loads(self.cfg.read_text()),
                         {'bundle': {'resources': {'engine-bundle/': 'engine/'}}})

    def test_zip_not_matching_sums_is_refused(self):
        src = package(self.d)
        with zipfile.ZipFile(src / se.ZIP, 'a') as zf:
            zf.writestr(f'{se.TOP}/extra.dll', b'x')
        with self.assertRaisesRegex(se.StageError, 'does not match'):
            self.run_stage(src)
        self.assertFalse(self.dest.exists())
        self.assertFalse(self.cfg.exists())

    def test_exe_not_matching_sums_is_refused_and_cleaned_up(self):
        src = package(self.d, exe_sum='0' * 64)
        with self.assertRaisesRegex(se.StageError, 'vanta-chromium.exe does not match'):
            self.run_stage(src)
        self.assertFalse(self.dest.exists())

    def test_entries_outside_the_top_folder_are_refused(self):
        for bad in ('../evil.dll', 'other/evil.dll', '/abs.dll', f'{se.TOP}/../evil.dll'):
            with self.subTest(bad=bad):
                d = Path(tempfile.mkdtemp(dir=self.d))
                src = package(d, extra=[(bad, b'x')])
                with self.assertRaises(se.StageError):
                    se.stage(src, self.dest, self.version)
                self.assertFalse(self.dest.exists())
                self.assertFalse((self.d / 'evil.dll').exists())

    def test_missing_lines_files_or_bad_version(self):
        src = package(self.d)
        sums = (src / se.SUMS).read_text().splitlines()
        (src / se.SUMS).write_text(sums[0] + '\n')
        with self.assertRaisesRegex(se.StageError, 'no line for'):
            self.run_stage(src)
        (src / se.SUMS).write_text('nonsense\n')
        with self.assertRaisesRegex(se.StageError, 'line 1'):
            self.run_stage(src)
        (src / se.SUMS).write_text('\n'.join(sums) + '\n')
        self.version.write_text('latest\n')
        with self.assertRaisesRegex(se.StageError, 'not a version'):
            self.run_stage(src)
        self.version.write_text('156.0.8078.79\n')
        (src / se.ZIP).unlink()
        with self.assertRaisesRegex(se.StageError, 'not found'):
            self.run_stage(src)

    def test_zip_without_the_exe_is_refused(self):
        files = {k: v for k, v in FILES.items() if k != se.EXE}
        src = package(self.d, files=files, exe_sum='1' * 64)
        with self.assertRaisesRegex(se.StageError, 'has no'):
            self.run_stage(src)

    def test_cli_exit_codes(self):
        src = package(self.d)
        args = ['--from', str(src), '--to', str(self.dest), '--version-file', str(self.version)]
        self.assertEqual(se.main(args), 0)
        exe_line = (src / se.SUMS).read_text().splitlines()[1]
        (src / se.SUMS).write_text(f'{"0" * 64}  {se.ZIP}\n{exe_line}\n')
        self.assertEqual(se.main(args), 1)


if __name__ == '__main__':
    unittest.main()
