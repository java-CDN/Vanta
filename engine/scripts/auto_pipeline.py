#!/usr/bin/env python3
"""Engine auto-update state machine, run every few hours by engine-watch.yml.

Each run looks at where the newest upstream release is in the pipeline and starts
the next step, then exits. No step waits for another inside a job, so the 37-hour
compile costs nothing here.

  new ucw tag, no branch       -> pin it (update_lock.py), push engine/auto-<tag>, start S1
  S1 green                     -> start S3 (chained compile)
  S3 green                     -> start S5 (smoke + safety test) on that engine
  S5 green                     -> start CI with engine_run_id (installer with the engine)
  CI green                     -> READY: a person merges the branch and publishes a release
  any step red                 -> job fails with the reason (GitHub mails the owner)

Never pushes to main, never creates releases, issues or pull requests.
Needs GH_TOKEN (contents: write, actions: write) and GITHUB_REPOSITORY.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPO = os.environ.get('GITHUB_REPOSITORY', 'java-CDN/Vanta')
STEPS = ['engine-s1.yml', 'engine-s3.yml', 'engine-s5.yml', 'ci.yml']


def sh(*args, cwd=ROOT, check=True):
    r = subprocess.run(list(args), cwd=cwd, text=True, capture_output=True)
    if check and r.returncode:
        sys.exit(f'{" ".join(args)} failed:\n{r.stdout}\n{r.stderr}')
    return r.stdout.strip()


def gh_api(path):
    return json.loads(sh('gh', 'api', path))


def latest_run(wf, branch):
    runs = gh_api(f'repos/{REPO}/actions/workflows/{wf}/runs?branch={branch}'
                  f'&event=workflow_dispatch&per_page=1')['workflow_runs']
    return runs[0] if runs else None


def dispatch(wf, branch, **inputs):
    args = ['gh', 'workflow', 'run', wf, '--repo', REPO, '--ref', branch]
    for k, v in inputs.items():
        args += ['-f', f'{k}={v}']
    sh(*args)
    print(f'started {wf} on {branch} {inputs or ""}')


def branch_exists(branch):
    return bool(sh('git', 'ls-remote', '--heads', 'origin', branch))


def summary(text):
    print(text)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as f:
            f.write(text + '\n')


def main():
    out = sh(sys.executable, 'engine/scripts/update_lock.py', '--check')
    print(out)
    fields = dict(kv.split('=') for kv in out.split())
    tag = os.environ.get('FORCE_TAG') or fields['newest']
    if tag == fields['current'] and not os.environ.get('FORCE_TAG'):
        summary(f'Engine is current ({tag}). Nothing to do.')
        return
    branch = f'engine/auto-{tag}'
    if not branch_exists(branch):
        sh('git', 'switch', '-c', branch)
        print(sh(sys.executable, 'engine/scripts/update_lock.py', '--apply', tag))
        sh('git', '-c', 'user.name=Vanta', '-c',
           'user.email=109491259+java-CDN@users.noreply.github.com',
           'commit', '-qam', f'engine: pin upstream {tag} (auto)')
        sh('git', 'push', '-q', 'origin', branch)
        dispatch('engine-s1.yml', branch)
        summary(f'New upstream {tag}: pinned on {branch}, S1 started.')
        return
    runs = {wf: latest_run(wf, branch) for wf in STEPS}
    for i, wf in enumerate(STEPS):
        r = runs[wf]
        if r is None:
            prev = runs[STEPS[i - 1]] if i else None
            if wf == 'engine-s3.yml':
                dispatch(wf, branch)
            elif wf in ('engine-s5.yml', 'ci.yml'):
                dispatch(wf, branch, engine_run_id=runs['engine-s3.yml']['id'])
            else:
                dispatch(wf, branch)
            summary(f'{tag}: {STEPS[i - 1] if prev else "pin"} green, started {wf}.')
            return
        if r['status'] != 'completed':
            summary(f'{tag}: {wf} still running ({r["html_url"]}).')
            return
        if r['conclusion'] != 'success':
            summary(f'{tag}: {wf} FAILED ({r["html_url"]}). A person must fix it '
                    f'(usually a Vanta patch that no longer applies) and re-run {wf} '
                    f'on {branch}; the pipeline then continues by itself.')
            sys.exit(1)
    summary(f'{tag}: READY. S1, S3, S5 and CI are green on {branch}. Installer: '
            f'{runs["ci.yml"]["html_url"]}. Merge {branch} into main and publish a release.')


if __name__ == '__main__':
    main()
