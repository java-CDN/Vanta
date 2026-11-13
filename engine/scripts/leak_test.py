#!/usr/bin/env python3
"""Safety test of a built Vanta engine on Windows (CI: engine-leak.yml).

Runs the engine the way the launcher does (signed persona, GuardPolicy flags,
SOCKS5 proxy on 127.0.0.1) with a stand-in SOCKS5 proxy that logs every
request, then checks:

  Leaks (the browser must reach the network only through the proxy)
    L1  no TCP connection from the engine's processes to a non-loopback address
    L2  no UDP socket of the engine's processes on a non-loopback address
    L3  names go to the proxy as names (SOCKS5 ATYP 3), never resolved locally
    L4  no SOCKS5 UDP ASSOCIATE (WebRTC/QUIC over the proxy)
    L5  WebRTC gathers no candidate carrying a real IP (host, srflx, prflx)
    L6  a page fetch to the internet works through the proxy
  Persona (the engine shows the signed persona, not the host)
    P1.. navigator, UA-CH, screen, time zone, languages, WebGL strings

Nothing here is a leak test of a user's real proxy; it proves the engine
side: flags + patches keep every byte on the proxy path.

  leak_test.py --exe <dir>\\vanta-chromium.exe [--work DIR] [--seconds 25]
"""
import argparse
import base64
import json
import os
import select
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from smoke_s5lite import ENGINE, b64, kill_tree, signed_config, smoke_persona  # noqa: E402

PROXY_LOG = []          # (cmd, atyp, host, port)
PROXY_LOCK = threading.Lock()
RESULT = {}
RESULT_EVENT = threading.Event()

PROBE = r'''<!doctype html><meta charset="utf-8"><title>vanta probe</title><body>probe
<script>
(async () => {
  const r = {};
  const t = (k, f) => { try { r[k] = f(); } catch (e) { r[k] = 'ERR ' + e; } };
  t('ua', () => navigator.userAgent);
  t('platform', () => navigator.platform);
  t('hardwareConcurrency', () => navigator.hardwareConcurrency);
  t('deviceMemory', () => navigator.deviceMemory);
  t('maxTouchPoints', () => navigator.maxTouchPoints);
  t('languages', () => navigator.languages.join(','));
  t('language', () => navigator.language);
  t('timezone', () => Intl.DateTimeFormat().resolvedOptions().timeZone);
  t('screen', () => [screen.width, screen.height, screen.availWidth, screen.availHeight,
                     screen.colorDepth].join('x'));
  t('dpr', () => devicePixelRatio);
  t('webdriver', () => navigator.webdriver);
  try {
    const h = await navigator.userAgentData.getHighEntropyValues(
        ['platform', 'platformVersion', 'architecture', 'bitness', 'fullVersionList']);
    r.uach = {brands: navigator.userAgentData.brands.map(b => b.brand + '/' + b.version),
              platform: h.platform, platformVersion: h.platformVersion,
              architecture: h.architecture, bitness: h.bitness,
              mobile: navigator.userAgentData.mobile};
  } catch (e) { r.uach = 'ERR ' + e; }
  try {
    const c = document.createElement('canvas');
    const gl = c.getContext('webgl') || c.getContext('experimental-webgl');
    r.webgl2 = !!document.createElement('canvas').getContext('webgl2');
    const d = gl.getExtension('WEBGL_debug_renderer_info');
    r.webgl = {vendor: gl.getParameter(d.UNMASKED_VENDOR_WEBGL),
               renderer: gl.getParameter(d.UNMASKED_RENDERER_WEBGL)};
  } catch (e) { r.webgl = 'ERR ' + e; }
  try {
    const res = await fetch('https://api.ipify.org?format=json', {cache: 'no-store'});
    r.exit_ip = (await res.json()).ip;
  } catch (e) { r.exit_ip = 'ERR ' + e; }
  r.candidates = [];
  try {
    const pc = new RTCPeerConnection({iceServers: [{urls: 'stun:stun.l.google.com:19302'}]});
    pc.createDataChannel('x');
    pc.onicecandidate = e => { if (e.candidate && e.candidate.candidate)
                                 r.candidates.push(e.candidate.candidate); };
    await pc.setLocalDescription(await pc.createOffer());
    await new Promise(ok => setTimeout(ok, 6000));
    r.sdp_c_lines = (pc.localDescription.sdp.match(/^c=.*$/mg) || []).join(' | ');
    pc.close();
  } catch (e) { r.candidates.push('ERR ' + e); }
  await fetch('/result', {method: 'POST', body: JSON.stringify(r)});
  document.body.textContent = 'done';
})();
</script>'''


# ---- stand-in SOCKS5 proxy (no auth, CONNECT only; logs everything) ----------

def _recv(s, n):
    b = b''
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise ConnectionError('closed')
        b += c
    return b


class Socks(socketserver.BaseRequestHandler):
    def handle(self):
        s = self.request
        try:
            ver, n = _recv(s, 2)
            _recv(s, n)
            s.sendall(b'\x05\x00')
            ver, cmd, _, atyp = _recv(s, 4)
            if atyp == 1:
                host = socket.inet_ntoa(_recv(s, 4))
            elif atyp == 3:
                host = _recv(s, _recv(s, 1)[0]).decode('ascii', 'replace')
            elif atyp == 4:
                host = socket.inet_ntop(socket.AF_INET6, _recv(s, 16))
            else:
                return
            port = struct.unpack('!H', _recv(s, 2))[0]
            with PROXY_LOCK:
                PROXY_LOG.append((cmd, atyp, host, port))
            if cmd != 1:  # only CONNECT; UDP ASSOCIATE / BIND refused
                s.sendall(b'\x05\x07\x00\x01' + b'\0' * 6)
                return
            try:
                up = socket.create_connection((host, port), timeout=15)
            except OSError:
                s.sendall(b'\x05\x05\x00\x01' + b'\0' * 6)
                return
            s.sendall(b'\x05\x00\x00\x01' + b'\0' * 6)
            pair = [s, up]
            while True:
                r, _, _ = select.select(pair, [], [], 60)
                if not r:
                    break
                for x in r:
                    d = x.recv(65536)
                    if not d:
                        return
                    (up if x is s else s).sendall(d)
        except (OSError, ConnectionError, ValueError):
            pass


class TS(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


# ---- local page server (loopback: the browser reaches it directly) -----------

class Page(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = PROBE.encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get('Content-Length', '0'))
        RESULT.update(json.loads(self.rfile.read(n)))
        RESULT_EVENT.set()
        self.send_response(204)
        self.end_headers()


# ---- network watcher on the engine's process tree ---------------------------

def is_loopback(ip):
    return ip.startswith('127.') or ip in ('::1', '0.0.0.0', '::') or ip.startswith('::ffff:127.')


def watch(root_pid, stop, seen_tcp, seen_udp):
    import psutil
    while not stop.is_set():
        try:
            root = psutil.Process(root_pid)
            pids = {root_pid} | {c.pid for c in root.children(recursive=True)}
        except psutil.Error:
            pids = {root_pid}
        try:
            conns = psutil.net_connections(kind='inet')
        except psutil.Error:
            conns = []
        for c in conns:
            if c.pid not in pids:
                continue
            if c.type == socket.SOCK_STREAM and c.raddr and not is_loopback(c.raddr.ip):
                seen_tcp.add(f'{c.raddr.ip}:{c.raddr.port}')
            if c.type == socket.SOCK_DGRAM and c.laddr and not is_loopback(c.laddr.ip):
                seen_udp.add(f'{c.laddr.ip}:{c.laddr.port}')
        time.sleep(0.1)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--exe', type=Path, required=True)
    ap.add_argument('--work', type=Path)
    ap.add_argument('--seconds', type=int, default=40)
    ap.add_argument('--extra', action='append', default=[],
                    help='diagnostic: extra engine switch')
    ap.add_argument('--control', action='store_true',
                    help='diagnostic: no persona, report WebGL only')
    a = ap.parse_args()
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    work = a.work or Path(tempfile.mkdtemp(prefix='vanta-leak-'))
    work.mkdir(parents=True, exist_ok=True)
    version = (ENGINE / 'VERSION').read_text().strip()
    major, minor, build, patch = (int(x) for x in version.split('.'))
    engine = {'major': major, 'minor': minor, 'build': build, 'patch': patch}
    persona = smoke_persona(engine)

    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(serialization.Encoding.Raw,
                                        serialization.PublicFormat.Raw)
    cfg = signed_config(key, engine, work / 'persona.json')

    proxy = TS(('127.0.0.1', 0), Socks)
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    page = ThreadingHTTPServer(('127.0.0.1', 0), Page)
    threading.Thread(target=page.serve_forever, daemon=True).start()
    pport, wport = proxy.server_address[1], page.server_address[1]

    # Same flags as vanta-proxy GuardPolicy::engine_args + EngineLaunch::args.
    args = [str(a.exe.resolve()),
            f'--user-data-dir={work / "profile"}',
            f'--vanta-config={cfg}', f'--vanta-pubkey={b64(pub)}',
            f'--proxy-server=socks5://127.0.0.1:{pport}',
            '--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1',
            '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
            '--disable-quic', '--no-first-run', '--no-default-browser-check',
            # Test only: CI runners have no GPU, so WebGL needs the software
            # rasterizer. Real profiles run on the host GPU (G001).
            # (D3D11 fails there; ANGLE on SwiftShader Vulkan works.)
            '--use-angle=swiftshader', '--use-gl=angle',
            f'http://127.0.0.1:{wport}/probe.html']
    if a.control:
        args = [x for x in args if not x.startswith(('--vanta-config', '--vanta-pubkey'))]
    args[1:1] = a.extra
    print('>', ' '.join(args))
    log = open(work / 'engine.log', 'w', encoding='utf-8', errors='replace')
    proc = subprocess.Popen(args + ['--enable-logging=stderr', '--v=0'],
                            stdout=log, stderr=subprocess.STDOUT)
    stop = threading.Event()
    seen_tcp, seen_udp = set(), set()
    w = threading.Thread(target=watch, args=(proc.pid, stop, seen_tcp, seen_udp), daemon=True)
    w.start()
    got = RESULT_EVENT.wait(a.seconds)
    time.sleep(3)  # late background connections
    exit_code = proc.poll()
    stop.set()
    w.join(5)
    kill_tree(proc)
    proxy.shutdown()
    page.shutdown()

    res = []
    if a.control:
        print('CONTROL (no persona): probe', got, 'webgl', RESULT.get('webgl'),
              'webgl2', RESULT.get('webgl2'))
        for l in (work / 'engine.log').read_text(encoding='utf-8', errors='replace').splitlines():
            if 'gpu' in l.lower():
                print(l[:300])
        return 0

    def rec(name, ok, detail):
        res.append((name, bool(ok), str(detail)[:300]))

    rec('engine ran and probe reported', got and exit_code is None,
        f'probe={got} exit={exit_code}')
    rec('L1 no direct TCP', not seen_tcp, sorted(seen_tcp) or 'none')
    rec('L2 no non-loopback UDP socket', not seen_udp, sorted(seen_udp) or 'none')
    by_ip = [h for c, t, h, p in PROXY_LOG if t != 3]
    rec('L3 names resolved at the proxy', got and not by_ip and
        any(h == 'api.ipify.org' for c, t, h, p in PROXY_LOG),
        f'by-address requests: {by_ip or "none"}; proxied: '
        f'{sorted({h for c, t, h, p in PROXY_LOG})}')
    udp_assoc = [x for x in PROXY_LOG if x[0] != 1]
    rec('L4 no UDP ASSOCIATE/BIND', not udp_assoc, udp_assoc or 'none')
    cands = RESULT.get('candidates', [])
    bad = [c for c in cands if any(f' typ {k}' in c for k in ('host', 'srflx', 'prflx'))
           and '.local ' not in c]
    rec('L5 WebRTC exposes no IP', got and not bad,
        f'{len(cands)} candidates; bad={bad or "none"}; c={RESULT.get("sdp_c_lines")}')
    ip = RESULT.get('exit_ip', '')
    rec('L6 fetch through proxy', got and not str(ip).startswith('ERR') and ip, ip)

    uach = RESULT.get('uach') if isinstance(RESULT.get('uach'), dict) else {}
    expect = [
        ('P1 userAgent', RESULT.get('ua'), persona['user_agent']),
        ('P2 platform', RESULT.get('platform'), 'Win32'),
        ('P3 hardwareConcurrency', RESULT.get('hardwareConcurrency'),
         persona['hardware_concurrency']),
        ('P4 deviceMemory', RESULT.get('deviceMemory'), persona['device_memory']),
        ('P5 languages', RESULT.get('languages'), ','.join(persona['languages'])),
        ('P6 timezone', RESULT.get('timezone'), persona['geo']['timezone']),
        ('P7 screen', RESULT.get('screen'), '1920x1080x1920x1032x24'),
        ('P8 UA-CH platformVersion', uach.get('platformVersion'),
         persona['ua_ch']['platform_version']),
        ('P9 WebGL vendor', (RESULT.get('webgl') or {}).get('vendor')
         if isinstance(RESULT.get('webgl'), dict) else RESULT.get('webgl'),
         persona['gpu']['vendor']),
        ('P10 WebGL renderer', (RESULT.get('webgl') or {}).get('renderer')
         if isinstance(RESULT.get('webgl'), dict) else RESULT.get('webgl'),
         persona['gpu']['renderer']),
        ('P11 maxTouchPoints', RESULT.get('maxTouchPoints'), 0),
        ('P12 webdriver false', RESULT.get('webdriver'), False),
    ]
    for name, got_v, want in expect:
        rec(name, got and got_v == want, f'got {got_v!r} want {want!r}')

    (work / 'probe.json').write_text(json.dumps(RESULT, indent=1), encoding='utf-8')
    (work / 'proxy.log').write_text('\n'.join(map(str, PROXY_LOG)), encoding='utf-8')
    lines = ['| check | result | detail |', '|---|---|---|']
    lines += [f'| {n} | {"PASS" if ok else "FAIL"} | {d.replace("|", "/")} |'
              for n, ok, d in res]
    table = '\n'.join(lines)
    print(table)
    log.close()
    gl_lines = [l.rstrip() for l in (work / 'engine.log').read_text(
        encoding='utf-8', errors='replace').splitlines()
        if any(k in l.lower() for k in ('gpu', 'webgl', 'angle', 'swiftshader', 'vanta', 'gl_'))]
    print('--- engine log (gpu/webgl/vanta lines) ---')
    print('\n'.join(gl_lines[:60]))
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as f:
            f.write(f'### Vanta safety test ({version})\n\n{table}\n')
    return 0 if all(ok for _, ok, _ in res) else 1


if __name__ == '__main__':
    sys.exit(main())
