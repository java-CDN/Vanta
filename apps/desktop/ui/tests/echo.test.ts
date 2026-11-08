import { describe, expect, it } from 'vitest';
import { DEFAULT_IP_ECHO_URL, echoUrlProblem } from '../src/lib/echo';
import { mockBackend } from '../src/api/mock';

describe('IP echo URL (mirrors vanta_proxy::EchoUrl::parse)', () => {
  it('accepts https URLs to public hosts', () => {
    for (const ok of ['', DEFAULT_IP_ECHO_URL, 'https://icanhazip.com', 'HTTPS://ifconfig.me:8443/ip', 'https://api.ipify.org?format=text', 'https://1.1.1.1/cdn-cgi/trace']) {
      expect(echoUrlProblem(ok), ok).toBeNull();
    }
  });
  it('refuses what the backend refuses', () => {
    for (const bad of ['http://api.ipify.org/', 'api.ipify.org', 'https://user:pw@api.ipify.org/', 'https://api.ipify.org/#x', 'https://api ipify.org/', 'https://[2001:db8::1]/', 'https://localhost/', 'https://echo.localhost/', 'https://127.0.0.1/', 'https://192.168.1.1/', 'https://10.0.0.1/', 'https://api.ipify.org:0/', 'https://api.ipify.org:99999/', 'https://intranet/']) {
      expect(echoUrlProblem(bad), bad).not.toBeNull();
    }
  });
  it('mock backend stores a valid URL and rejects an invalid one', async () => {
    const b = mockBackend({ speed: 0, unlocked: true });
    const s = await b.getSettings();
    expect(s.ip_echo_url).toBeNull();
    await expect(b.setSettings({ ...s, ip_echo_url: 'http://x.example/' })).rejects.toMatchObject({ kind: 'invalid' });
    expect((await b.setSettings({ ...s, ip_echo_url: 'https://icanhazip.com/' })).ip_echo_url).toBe('https://icanhazip.com/');
  });
});
