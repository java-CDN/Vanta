"""Tests for fetch_geoip.py (no network: a synthetic download page and MMDB file)."""
import datetime as dt
import gzip
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import fetch_geoip as f

TODAY = dt.date(2026, 11, 9)


def fake_mmdb(db_type='DBIP-City-Lite', size=2 << 20) -> bytes:
    key = b'database_type'
    val = db_type.encode()
    meta = f.MARKER + bytes([0xE1, 0x40 | len(key)]) + key + bytes([0x40 | len(val)]) + val
    return b'\0' * (size - len(meta)) + meta


def page(data: bytes, month='November 2026', url='https://download.db-ip.com/free/dbip-city-lite-2026-11.mmdb.gz',
         sha1=None) -> str:
    sha1 = sha1 or hashlib.sha1(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()
    csv = ('<div class="card"><dl><dt>Format</dt><dd>CSV</dd><dt>Release</dt><dd>November 2026</dd>'
           '<dt>SHA1SUM</dt><dd>' + '0' * 40 + '</dd></dl>'
           "<a href='https://download.db-ip.com/free/dbip-city-lite-2026-11.csv.gz'>x</a></div>")
    mm = (f'<div class="card"><dl><dt>Format</dt><dd>MMDB</dd><dt>Release</dt><dd>{month}</dd>'
          f'<dt>MD5SUM</dt><dd class="x">{md5}</dd><dt>SHA1SUM</dt><dd class="x">{sha1}</dd></dl>'
          f"<a href='{url}'>Download</a></div>")
    return '<html>' + csv + mm + '</html>'


class FetchGeoipTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.data = fake_mmdb()
        self.gz = self.tmp / 'dbip-city-lite-2026-11.mmdb.gz'
        self.gz.write_bytes(gzip.compress(self.data))

    def run_fetch(self, html, **kw):
        return f.fetch(self.tmp / 'bundle', self.tmp / 'tauri.geoip.json', page_html=html,
                       gz_file=self.gz, today=TODAY, min_mb=1, **kw)

    def test_ok_writes_manifest_and_overlay(self):
        m = self.run_fetch(page(self.data))
        self.assertEqual(m['release'], '2026-11')
        self.assertEqual(m['sha256'], hashlib.sha256(self.data).hexdigest())
        self.assertEqual(m['license'], 'CC BY 4.0')
        on_disk = json.loads((self.tmp / 'bundle' / 'geoip.json').read_text())
        self.assertEqual(on_disk, m)
        overlay = json.loads((self.tmp / 'tauri.geoip.json').read_text())
        self.assertEqual(overlay, {'bundle': {'resources': {'bundle/': 'geoip/'}}})

    def test_sha1_mismatch_leaves_nothing(self):
        with self.assertRaises(f.FetchError):
            self.run_fetch(page(self.data, sha1='1' * 40))
        self.assertFalse((self.tmp / 'bundle').exists())

    def test_stale_release_refused(self):
        with self.assertRaises(f.FetchError):
            self.run_fetch(page(self.data, month='August 2026',
                                url='https://download.db-ip.com/free/dbip-city-lite-2026-08.mmdb.gz'))

    def test_foreign_link_refused(self):
        with self.assertRaises(f.FetchError):
            self.run_fetch(page(self.data, url='https://example.com/free/dbip-city-lite-2026-11.mmdb.gz'))

    def test_wrong_database_type(self):
        data = fake_mmdb('GeoLite2-City')
        self.gz.write_bytes(gzip.compress(data))
        with self.assertRaises(f.FetchError):
            self.run_fetch(page(data))

    def test_previous_month_accepted_early_in_month(self):
        info = {'release': '2026-10', 'url': 'https://download.db-ip.com/free/dbip-city-lite-2026-10.mmdb.gz'}
        f.check_release(info, dt.date(2026, 11, 1))


if __name__ == '__main__':
    unittest.main()
