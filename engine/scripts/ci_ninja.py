#!/usr/bin/env python3
"""Run ninja for one CI stage of S3 with a wall-clock deadline (Windows).

Mirrors ungoogled-chromium-windows build.py --ci: ninja runs under vcvars64 with
DEPOT_TOOLS_WIN_TOOLCHAIN=0 and is stopped with CTRL_BREAK when the stage's
time is up, so the out dir can be archived and the next job continues. Unlike
build.py it stops at an absolute deadline (job start + budget), keeps going
past failed edges (-k 0) so one compile error does not waste the stage, and
prints a progress line every N edges instead of every edge.

  ci_ninja.py --src D:\\vanta\\build\\src --deadline <epoch> [--jobs 4] [--canary]

--canary first builds only the object files of the .cc files the Vanta series
touches (with their generated-header deps), so a compile error in a Vanta patch
fails stage 1 within the first hour instead of somewhere in a 15 h chain.

Writes to $GITHUB_OUTPUT: finished=true|false, failures=<n>, and keeps
out/Default/vanta_progress.json (edges total/done across stages).
Exit code: 0 unless the script itself breaks; callers read the outputs.
"""
import argparse
import collections
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

ENGINE = Path(__file__).resolve().parent.parent
STATUS = re.compile(r'^\[(\d+)/(\d+)\] ')
sys.path.insert(0, str(Path(__file__).resolve().parent))


def log(msg):
    print(f'[vanta-ninja] {msg}', flush=True)


def vc_env():
    vswhere = os.path.expandvars(
        r'%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe')
    inst = subprocess.run([vswhere, '-products', '*', '-prerelease', '-latest', '-property',
                           'installationPath'], check=True, capture_output=True,
                          text=True).stdout.strip()
    vcvars = Path(inst, 'VC/Auxiliary/Build/vcvars64.bat')
    out = subprocess.run(f'call "{vcvars}" >nul && set', shell=True, check=True,
                         capture_output=True, text=True, errors='replace').stdout
    env = {}
    for line in out.splitlines():
        if '=' in line and not line.startswith('='):
            k, v = line.split('=', 1)
            env[k] = v
    env['DEPOT_TOOLS_WIN_TOOLCHAIN'] = '0'
    env['NINJA_STATUS'] = '[%f/%t] '
    log(f'vcvars: {vcvars}')
    return env


class Progress:
    """out/Default/vanta_progress.json: survives between stages in the archive."""

    def __init__(self, out_dir: Path):
        self.path = out_dir / 'vanta_progress.json'
        self.data = json.loads(self.path.read_text()) if self.path.exists() else {
            'edges_total': None, 'stages': []}

    def save(self):
        self.path.write_text(json.dumps(self.data, indent=1))


def count_edges(ninja, out, targets, env, src):
    """All edges the targets need (built or not): `ninja -t commands` lines."""
    r = subprocess.run([ninja, '-C', out, '-t', 'commands', *targets], cwd=src, env=env,
                       capture_output=True, text=True, errors='replace')
    if r.returncode != 0:
        log('ninja -t commands failed:\n' + r.stderr[-4000:])
        return None, ''
    return len(r.stdout.splitlines()), r.stdout


def canary_objects(commands: str):
    """Object outputs of the .cc files the Vanta series touches, from the command list."""
    import prepare  # noqa: E402  (engine/scripts)
    ccs = [rel for rel in prepare.vanta_targets() if rel.endswith('.cc')]
    objs = []
    for line in commands.splitlines():
        for rel in ccs:
            if f'../../{rel} ' in line or line.endswith(f'../../{rel}'):
                m = re.search(r'/Fo(\S+\.obj)', line)
                if m and m.group(1) not in objs:
                    objs.append(m.group(1))
    return ccs, objs


def run_ninja(ninja, out, targets, jobs, env, src, deadline, every, label):
    cmd = [ninja, '-C', out, '-j', str(jobs), '-k', '0', *targets]
    log(f'{label}: ' + ' '.join(cmd))
    proc = subprocess.Popen(cmd, cwd=src, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, errors='replace',
                            creationflags=getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0))
    st = {'f': 0, 't': None, 'first_t': None, 'failed': 0, 'last_print': 0.0}
    tail = collections.deque(maxlen=20)

    def reader():
        for line in proc.stdout:
            line = line.rstrip('\n')
            m = STATUS.match(line)
            if m:
                st['f'], st['t'] = int(m.group(1)), int(m.group(2))
                if st['first_t'] is None:
                    st['first_t'] = st['t']
                tail.append(line)
                now = time.time()
                if st['f'] % every == 0 or now - st['last_print'] > 300:
                    st['last_print'] = now
                    print(f'{line}   ({time.strftime("%H:%M:%S")})', flush=True)
                continue
            if line.startswith('FAILED: '):
                st['failed'] += 1
                print('::group::last edges before failure', flush=True)
                print('\n'.join(tail), flush=True)
                print('::endgroup::', flush=True)
            print(line, flush=True)

    th = threading.Thread(target=reader, daemon=True)
    th.start()
    timed_out = False
    try:
        proc.wait(timeout=max(1, deadline - time.time()))
    except subprocess.TimeoutExpired:
        timed_out = True
        log('stage deadline reached: sending CTRL_BREAK to ninja')
        for _ in range(3):
            try:
                os.kill(proc.pid, signal.CTRL_BREAK_EVENT)
            except (OSError, AttributeError) as exc:
                log(f'CTRL_BREAK failed: {exc}')
            time.sleep(1)
        try:
            proc.wait(180)
        except subprocess.TimeoutExpired:
            log('ninja did not stop; killing the process tree')
            subprocess.run(['taskkill', '/T', '/F', '/PID', str(proc.pid)])
            proc.wait(60)
    th.join(30)
    rc = proc.returncode
    log(f'{label}: rc={rc} timed_out={timed_out} edges {st["f"]}/{st["t"]} '
        f'failed={st["failed"]}')
    return rc, timed_out, st


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--src', type=Path, required=True)
    ap.add_argument('--out', default='out\\Default')
    ap.add_argument('--targets', default='chrome')
    ap.add_argument('--jobs', type=int, default=4)
    ap.add_argument('--deadline', type=float, required=True, help='epoch seconds')
    ap.add_argument('--stage', default='?')
    ap.add_argument('--canary', action='store_true')
    ap.add_argument('--every', type=int, default=250, help='print every N edges')
    a = ap.parse_args()

    src = a.src.resolve()
    ninja = str(src / 'third_party' / 'ninja' / 'ninja.exe')
    targets = a.targets.split(',')
    env = vc_env()
    prog = Progress(src / a.out)

    total, commands = count_edges(ninja, a.out, targets, env, src)
    if total and not prog.data['edges_total']:
        prog.data['edges_total'] = total
    log(f'edges needed by {targets} in total: {total}')

    failures = 0
    if a.canary:
        ccs, objs = canary_objects(commands)
        log(f'canary: Vanta-touched sources {ccs} -> objects {objs}')
        if objs:
            rc, timed_out, st = run_ninja(ninja, a.out, objs, a.jobs, env, src, a.deadline, 50,
                                          'canary')
            if rc != 0 and not timed_out:
                log('CANARY FAILED: a Vanta-touched source does not compile')
                write_outputs(finished=False, failures=max(1, st['failed']))
                sys.exit(3)
        else:
            log('canary: no objects matched (continuing)')

    t0 = time.time()
    rc, timed_out, st = run_ninja(ninja, a.out, targets, a.jobs, env, src, a.deadline, a.every,
                                  'build')
    finished = rc == 0 and not timed_out
    failures = st['failed'] if not finished else 0
    if rc != 0 and not timed_out and failures == 0:
        failures = 1  # ninja error without FAILED: line (manifest, missing input, ...)
    remaining = (st['t'] or 0) - st['f'] if st['t'] is not None else None
    if finished:
        remaining = 0
    tot = prog.data['edges_total']
    done = tot - remaining if (tot and remaining is not None) else None
    prog.data['stages'].append({
        'stage': a.stage, 'started': int(t0), 'seconds': int(time.time() - t0),
        'edges_at_start': st['first_t'], 'edges_run': st['f'], 'remaining': remaining,
        'finished': finished, 'failures': failures})
    prog.save()
    pct = f'{100.0 * done / tot:.1f}%' if done is not None else 'n/a'
    summary = (f'S3 stage {a.stage}: ran {st["f"]} edges in {int(time.time() - t0) // 60} min; '
               f'overall {done}/{tot} edges ({pct}); remaining {remaining}; '
               f'finished={finished}; failed edges={failures}')
    log(summary)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as f:
            f.write(f'### {summary}\n')
    write_outputs(finished=finished, failures=failures, done=done, total=tot)


def write_outputs(finished, failures, done=None, total=None):
    out = os.environ.get('GITHUB_OUTPUT')
    lines = [f'finished={"true" if finished else "false"}', f'failures={failures}',
             f'edges_done={done if done is not None else ""}',
             f'edges_total={total if total is not None else ""}']
    if out:
        with open(out, 'a', encoding='utf-8') as f:
            f.write('\n'.join(lines) + '\n')
    log('outputs: ' + ' '.join(lines))


if __name__ == '__main__':
    main()
