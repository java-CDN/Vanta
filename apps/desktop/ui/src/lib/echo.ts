/** IP echo endpoint used by health runs (mirrors `vanta_proxy::echo`; the Rust side has the
 *  final say). The exit IP is asked through the profile's proxy; the PC's own public IP is
 *  asked over a direct connection and only compared, never stored or logged. */
export const DEFAULT_IP_ECHO_URL = 'https://api.ipify.org/';
/** Proxy Hub check defaults (vanta_proxy::inspect). Both are only asked through the proxy. */
export const DEFAULT_IP_INFO_URL = 'https://ipinfo.io/json';
export const DEFAULT_SPEED_TEST_URL = 'https://speed.cloudflare.com/__down?bytes=2000000';
/** vanta_proxy::inspect::SPEED_MAX_BYTES: a speed test never downloads more. */
export const SPEED_MAX_BYTES = 2_000_000;

/** Problem with a user-entered https endpoint URL (IP echo, IP info, speed test), or null
 *  when it looks valid. */
export function echoUrlProblem(raw: string): string | null {
  const s = raw.trim();
  if (!s) return null; // empty = the default
  if (s.length > 512) return 'The URL is too long.';
  if (/\s/.test(s)) return 'The URL must not contain spaces.';
  if (!/^https:\/\//i.test(s)) return 'The URL must start with https://.';
  if (s.includes('#')) return 'The URL must not contain a fragment (#).';
  const rest = s.slice(8);
  const authority = rest.split(/[/?]/, 1)[0];
  if (authority.includes('@')) return 'The URL must not contain a user name or password.';
  if (authority.startsWith('[')) return 'IPv6 addresses are not supported.';
  const m = /^([^:]+)(?::(\d{1,5}))?$/.exec(authority);
  if (!m) return 'The host or port is not valid.';
  const host = m[1].toLowerCase().replace(/\.$/, '');
  if (m[2] !== undefined && (Number(m[2]) < 1 || Number(m[2]) > 65535)) return 'The port is not valid.';
  if (host === 'localhost' || host.endsWith('.localhost')) return 'Use a public host.';
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
    const [a, b] = host.split('.').map(Number);
    if (a === 0 || a === 10 || a === 127 || a >= 224 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || (a === 198 && (b === 18 || b === 19))) return 'Use a public address.';
    return null;
  }
  if (!host.includes('.') || !/^[a-z0-9_-]+(\.[a-z0-9_-]+)+$/.test(host)) return 'The host name is not valid.';
  return null;
}
