#!/usr/bin/env python3
"""Download and check the DB-IP "IP to City Lite" MMDB for the desktop installer (F07).

DB-IP Lite: https://db-ip.com/db/download/ip-to-city-lite, Creative Commons Attribution
4.0 (https://creativecommons.org/licenses/by/4.0/): free to use and ship with attribution
to DB-IP.com ("IP geolocation by DB-IP"). Released monthly. The database is NOT kept in
git (about 120 MB); CI fetches the current release at build time.

Steps (any problem stops with exit code 1 and nothing usable left behind):
  1. read the download page: the MMDB card's release month, SHA1SUM, MD5SUM and link;
  2. the release must be this month or the previous one (UTC) and the link must be
     https://download.db-ip.com/free/dbip-city-lite-<YYYY-MM>.mmdb.gz for that month;
  3. download the .gz (or reuse --cache/<name> from an earlier run), gunzip it;
  4. size sanity (--min-mb..--max-mb), SHA-1 and MD5 of the .mmdb as the page publishes
     them, MaxMind DB metadata marker and database_type "DBIP-City-Lite";
  5. --to/dbip-city-lite.mmdb + --to/geoip.json (release, SHA-256 the app checks at start,
     SHA-1, source, license, attribution);
  6. --tauri-config: a config overlay for `tauri build --config` that ships --to as the
     app's geoip/ resource folder.

  fetch_geoip.py --to apps/desktop/src-tauri/geoip-bundle \\
      --tauri-config apps/desktop/src-tauri/tauri.geoip.json [--cache DIR]

Only db-ip.com is contacted, only at build time. The app itself never downloads it.
"""
import argparse
import datetime as dt
import gzip
import hashlib
import json
import os
import re
import shutil
import sys
import urllib.request
from pathlib import Path

PAGE = 'https://db-ip.com/db/download/ip-to-city-lite'
LINK = re.compile(r'^https://download\.db-ip\.com/free/dbip-city-lite-(\d{4}-\d{2})\.mmdb\.gz$')
DB_NAME = 'dbip-city-lite.mmdb'
MANIFEST = 'geoip.json'
DB_TYPE = 'DBIP-City-Lite'
MARKER = b'\xab\xcd\xefMaxMind.com'
MONTHS = ['january', 'february', 'march', 'april', 'may', 'june', 'july', 'august',
          'september', 'october', 'november', 'december']
LICENSE = 'CC BY 4.0'
ATTRIBUTION = 'IP geolocation by DB-IP (https://db-ip.com)'
UA = 'Vanta-CI/1.0 (+https://github.com/java-CDN/Vanta)'


class FetchError(Exception):
    pass


def parse_page(html: str) -> dict:
    """The MMDB card of the download page: release (YYYY-MM), sha1, md5, url."""
    for card in re.split(r'<div class="card">', html)[1:]:
        if not re.search(r'<dt>\s*Format\s*</dt>\s*<dd>\s*MMDB\s*</dd>', card, re.I):
            continue
        rel = re.search(r'<dt>\s*Release\s*</dt>\s*<dd>\s*([A-Za-z]+)\s+(\d{4})\s*</dd>', card)
        sha1 = re.search(r'SHA1SUM\s*</dt>\s*<dd[^>]*>\s*([0-9a-fA-F]{40})\s*</dd>', card)
        md5 = re.search(r'MD5SUM\s*</dt>\s*<dd[^>]*>\s*([0-9a-fA-F]{32})\s*</dd>', card)
        url = re.search(r"href=['\"](https://download\.db-ip\.com/free/[^'\"]+\.mmdb\.gz)['\"]", card)
        if not (rel and sha1 and url):
            raise FetchError('MMDB card found but release, SHA1SUM or link is missing')
        month = rel.group(1).lower()
        if month not in MONTHS:
            raise FetchError(f'release month not understood: {rel.group(1)!r}')
        release = f'{rel.group(2)}-{MONTHS.index(month) + 1:02d}'
        return {'release': release, 'sha1': sha1.group(1).lower(),
                'md5': md5.group(1).lower() if md5 else None, 'url': url.group(1)}
    raise FetchError('no MMDB download on the page')


def check_release(info: dict, today: dt.date) -> None:
    m = LINK.match(info['url'])
    if not m:
        raise FetchError(f'unexpected download link {info["url"]}')
    if m.group(1) != info['release']:
        raise FetchError(f'link is for {m.group(1)} but the page says {info["release"]}')
    this = f'{today.year:04d}-{today.month:02d}'
    prev_day = today.replace(day=1) - dt.timedelta(days=1)
    prev = f'{prev_day.year:04d}-{prev_day.month:02d}'
    if info['release'] not in (this, prev):
        raise FetchError(f'release {info["release"]} is not current ({this}) or the month before ({prev})')


def digest(path: Path, algo: str) -> str:
    h = hashlib.new(algo)
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def database_type(path: Path) -> str:
    """database_type from the MMDB metadata (a UTF-8 string value after its key)."""
    size = path.stat().st_size
    with path.open('rb') as f:
        f.seek(max(0, size - 128 * 1024))
        tail = f.read()
    at = tail.rfind(MARKER)
    if at < 0:
        raise FetchError('no MaxMind DB metadata marker: not an MMDB file')
    meta = tail[at + len(MARKER):]
    key = b'database_type'
    k = meta.find(bytes([0x40 | len(key)]) + key)
    if k < 0:
        raise FetchError('MMDB metadata has no database_type')
    p = k + 1 + len(key)
    ctrl = meta[p]
    if ctrl >> 5 != 2:
        raise FetchError('database_type is not a string')
    n = ctrl & 0x1F
    p += 1
    if n == 29:
        n, p = 29 + meta[p], p + 1
    elif n >= 30:
        raise FetchError('database_type is implausibly long')
    return meta[p:p + n].decode('utf-8')


def http_get(url: str, dest: Path = None, timeout: int = 120):
    req = urllib.request.Request(url, headers={'User-Agent': UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        if dest is None:
            return r.read().decode('utf-8', 'replace')
        tmp = dest.with_suffix(dest.suffix + '.part')
        with tmp.open('wb') as f:
            shutil.copyfileobj(r, f, 1 << 20)
        tmp.replace(dest)
        return None


def fetch(dest: Path, tauri_config: Path = None, cache: Path = None, page_html: str = None,
          gz_file: Path = None, today: dt.date = None, min_mb: int = 40, max_mb: int = 600,
          get=http_get) -> dict:
    today = today or dt.datetime.now(dt.timezone.utc).date()
    html = page_html if page_html is not None else get(PAGE)
    info = parse_page(html)
    check_release(info, today)
    name = info['url'].rsplit('/', 1)[1]
    if gz_file is None:
        cache = cache or dest.parent / '.geoip-cache'
        cache.mkdir(parents=True, exist_ok=True)
        gz_file = cache / name
        if not gz_file.is_file():
            print(f'downloading {info["url"]}')
            get(info['url'], gz_file)
        else:
            print(f'using cached {gz_file}')

    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    db = dest / DB_NAME
    try:
        try:
            with gzip.open(gz_file, 'rb') as src, db.open('wb') as out:
                shutil.copyfileobj(src, out, 1 << 20)
        except (OSError, EOFError) as e:
            raise FetchError(f'{name} is not a valid gzip file: {e}')
        size = db.stat().st_size
        if not (min_mb << 20) <= size <= (max_mb << 20):
            raise FetchError(f'{DB_NAME} is {size} bytes, outside {min_mb}-{max_mb} MB')
        sha1 = digest(db, 'sha1')
        if sha1 != info['sha1']:
            raise FetchError(f'{DB_NAME} SHA-1 {sha1} does not match the published {info["sha1"]}')
        if info['md5'] and digest(db, 'md5') != info['md5']:
            raise FetchError(f'{DB_NAME} MD5 does not match the published {info["md5"]}')
        dbt = database_type(db)
        if dbt != DB_TYPE:
            raise FetchError(f'database_type is {dbt!r}, expected {DB_TYPE!r}')
        manifest = {
            'file': DB_NAME, 'release': info['release'], 'sha256': digest(db, 'sha256'), 'sha1': sha1,
            'source': info['url'], 'license': LICENSE, 'attribution': ATTRIBUTION,
        }
        (dest / MANIFEST).write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8', newline='\n')
    except BaseException:
        shutil.rmtree(dest, ignore_errors=True)
        raise

    if tauri_config is not None:
        rel = Path(os.path.relpath(dest.resolve(), tauri_config.resolve().parent)).as_posix()
        overlay = {'bundle': {'resources': {f'{rel}/': 'geoip/'}}}
        tauri_config.write_text(json.dumps(overlay, indent=2) + '\n', encoding='utf-8')
    print(f'GeoIP {info["release"]}: {size} bytes, sha256 {manifest["sha256"]} in {dest}')
    return manifest


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--to', dest='dest', type=Path, required=True)
    ap.add_argument('--tauri-config', type=Path)
    ap.add_argument('--cache', type=Path, help='folder that keeps the downloaded .mmdb.gz between runs')
    ap.add_argument('--retries', type=int, default=3)
    a = ap.parse_args(argv)
    last = None
    for attempt in range(1, a.retries + 1):
        try:
            fetch(a.dest, a.tauri_config, a.cache)
            return 0
        except FetchError as e:
            # A checked mismatch is not retried (a re-download of a cached file could help,
            # so drop the cache entry once).
            print(f'error: {e}', file=sys.stderr)
            if a.cache and attempt == 1:
                for f in a.cache.glob('dbip-city-lite-*.mmdb.gz'):
                    f.unlink()
                continue
            return 1
        except OSError as e:  # network
            last = e
            print(f'attempt {attempt}: {e}', file=sys.stderr)
    print(f'error: download failed: {last}', file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())
