#!/usr/bin/env python3
"""Find the newest ungoogled-chromium-windows release and rewrite engine/VERSION and
engine/upstream.lock for it. Used by .github/workflows/engine-watch.yml.

  update_lock.py --check        print the newest ucw tag and whether it differs (exit 0)
  update_lock.py --apply TAG    rewrite VERSION + upstream.lock for TAG

Every pin is read from the upstream repositories themselves (git ls-remote and the
published .hashes file of the Chromium tarball); nothing is guessed. S1 then verifies
the pins again against a real checkout, so a wrong value fails the pipeline.
"""
import argparse
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

ENGINE = Path(__file__).resolve().parent.parent
UCW = 'https://github.com/ungoogled-software/ungoogled-chromium-windows.git'
UNG = 'https://github.com/ungoogled-software/ungoogled-chromium.git'
CHROMIUM = 'https://chromium.googlesource.com/chromium/src.git'
TAG_RE = re.compile(r'^(\d+)\.(\d+)\.(\d+)\.(\d+)-(\d+)\.(\d+)$')


def git(*args, cwd=None):
    return subprocess.run(['git', *args], cwd=cwd, check=True, text=True,
                          capture_output=True).stdout


def ls_remote_tags(url, pattern='refs/tags/*'):
    """{tag: commit}; annotated tags resolve to their peeled commit, and
    'objects' maps annotated tags to the tag object."""
    commits, objects = {}, {}
    for line in git('ls-remote', '--tags', url, pattern).splitlines():
        sha, ref = line.split('\t')
        name = ref[len('refs/tags/'):]
        if name.endswith('^{}'):
            commits[name[:-3]] = sha
        else:
            objects[name] = sha
            commits.setdefault(name, sha)
    return commits, objects


def current():
    out = {}
    for line in (ENGINE / 'upstream.lock').read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            k, v = line.split('=', 1)
            out[k.strip()] = v.strip()
    return out


def newest_ucw():
    commits, _ = ls_remote_tags(UCW)
    tags = [t for t in commits if TAG_RE.match(t)]
    if not tags:
        sys.exit('no ungoogled-chromium-windows release tags found')
    return max(tags, key=lambda t: tuple(int(x) for x in TAG_RE.match(t).groups()))


def apply(tag):
    m = TAG_RE.match(tag)
    if not m:
        sys.exit(f'not a ucw release tag: {tag}')
    version = '.'.join(m.groups()[:4])
    ucw_commits, _ = ls_remote_tags(UCW, f'refs/tags/{tag}*')
    ucw_commit = ucw_commits[tag]
    with tempfile.TemporaryDirectory() as d:
        git('init', '-q', d)
        git('fetch', '-q', '--depth=1', UCW, ucw_commit, cwd=d)
        sub = git('ls-tree', 'FETCH_HEAD', 'ungoogled-chromium', cwd=d).split()[2]
    ung_commits, ung_objects = ls_remote_tags(UNG, f'refs/tags/{version}-*')
    ung_tags = [t for t, c in ung_commits.items() if c == sub]
    if len(ung_tags) != 1:
        sys.exit(f'ungoogled-chromium tag for submodule {sub} not unique: {ung_tags}')
    ung_tag = ung_tags[0]
    cr_commits, _ = ls_remote_tags(CHROMIUM, f'refs/tags/{version}')
    cr_commit = cr_commits[version]
    tarball = ('https://commondatastorage.googleapis.com/chromium-browser-official/'
               f'chromium-{version}-lite.tar.xz')
    hashes = urllib.request.urlopen(tarball + '.hashes', timeout=60).read().decode()
    sha = next((l.split()[1] for l in hashes.splitlines() if l.startswith('sha256')), None)
    if not sha or not re.fullmatch(r'[0-9a-f]{64}', sha):
        sys.exit('no sha256 in the tarball .hashes file')
    text = (ENGINE / 'upstream.lock').read_text(encoding='utf-8')
    new = {
        'chromium_version': version, 'chromium_tag': version, 'chromium_commit': cr_commit,
        'chromium_tarball': tarball, 'chromium_tarball_sha256': sha,
        'ucw_tag': tag, 'ucw_commit': ucw_commit,
        'ungoogled_tag': ung_tag, 'ungoogled_tag_object': ung_objects.get(ung_tag, sub),
        'ungoogled_commit': sub,
    }
    for k, v in new.items():
        text, n = re.subn(rf'^{k}=.*$', f'{k}={v}', text, flags=re.M)
        if n != 1:
            sys.exit(f'upstream.lock: key {k} found {n} times')
    (ENGINE / 'upstream.lock').write_text(text, encoding='utf-8')
    (ENGINE / 'VERSION').write_text(version + '\n', encoding='utf-8')
    print(f'pinned {tag}: chromium {version}@{cr_commit[:12]}, ucw@{ucw_commit[:12]}, '
          f'ungoogled {ung_tag}@{sub[:12]}, tarball sha256 {sha[:12]}')


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument('--check', action='store_true')
    g.add_argument('--apply', metavar='TAG')
    a = ap.parse_args()
    if a.check:
        tag, cur = newest_ucw(), current()['ucw_tag']
        print(f'newest={tag} current={cur} new={"yes" if tag != cur else "no"}')
        if os.environ.get('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
                f.write(f'tag={tag}\nnew={"true" if tag != cur else "false"}\n')
    else:
        apply(a.apply)


if __name__ == '__main__':
    main()
