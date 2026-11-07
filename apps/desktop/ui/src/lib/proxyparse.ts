// Preview of the Proxy Hub import grammar (crates/vanta-proxy/src/endpoint.rs parse_line).
// The import itself is parsed again by the backend, which is authoritative; this only
// shows the user what will happen before anything is stored. Passwords are never echoed.

import type { ProxyScheme } from '../api/types';

export interface ParsedLine {
  line: number;
  scheme?: ProxyScheme;
  host?: string;
  port?: number;
  user?: string;
  hasPassword?: boolean;
  err?: string;
}

const SCHEMES: Record<string, ProxyScheme> = { http: 'http', https: 'https', socks5: 'socks5', socks5h: 'socks5', socks: 'socks5' };

function hostPort(h: string, p: string): { host: string; port: number } {
  const host = h.replace(/^\[|\]$/g, '');
  if (!host) throw new Error('missing host');
  const v4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
  if (v4 && host.split('.').some(o => Number(o) > 255)) throw new Error('invalid IPv4 address');
  if (!v4 && !h.startsWith('[') && !/^([a-z0-9-]+\.)*[a-z0-9-]+$/i.test(host)) throw new Error('invalid host');
  if (!/^\d+$/.test(p)) throw new Error('port must be a number');
  const port = Number(p);
  if (port < 1 || port > 65535) throw new Error('port must be 1-65535');
  return { host, port };
}

export function parseLine(raw: string, n: number, def: ProxyScheme): ParsedLine | null {
  const line = raw.trim();
  if (!line || line.startsWith('#')) return null;
  try {
    if (/\s/.test(line)) throw new Error('whitespace inside the proxy line');
    let scheme = def;
    let rest = line;
    let hasScheme = false;
    const sep = line.indexOf('://');
    if (sep >= 0) {
      const s = SCHEMES[line.slice(0, sep).toLowerCase()];
      if (!s) throw new Error(`unknown scheme '${line.slice(0, sep)}'`);
      scheme = s; rest = line.slice(sep + 3).replace(/\/+$/, ''); hasScheme = true;
    }
    const at = rest.lastIndexOf('@');
    if (at >= 0) {
      const userinfo = rest.slice(0, at);
      const hp = rest.slice(at + 1);
      const c = userinfo.indexOf(':');
      const pc = hp.lastIndexOf(':');
      if (c > 0 && pc > 0) {
        const { host, port } = hostPort(hp.slice(0, pc), hp.slice(pc + 1));
        return { line: n, scheme, host, port, user: userinfo.slice(0, c), hasPassword: c < userinfo.length - 1 };
      }
      if (hasScheme) throw new Error('login must be user:pass');
    }
    const parts = rest.split(':');
    if (parts.length === 2) return { line: n, scheme, ...hostPort(parts[0], parts[1]) };
    if (parts.length >= 4 && !hasScheme) {
      const [h, p, u, ...pw] = parts;
      if (!u) throw new Error('empty username');
      return { line: n, scheme, ...hostPort(h, p), user: u, hasPassword: pw.join(':').length > 0 };
    }
    throw new Error('expected host:port, host:port:user:pass, user:pass@host:port or scheme://user:pass@host:port');
  } catch (e) {
    return { line: n, err: (e as Error).message };
  }
}

export function parseList(text: string, def: ProxyScheme): ParsedLine[] {
  return text.split(/\r?\n/).map((l, i) => parseLine(l, i + 1, def)).filter((x): x is ParsedLine => !!x);
}
