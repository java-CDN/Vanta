import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { AREAS, CHECKS } from '../src/lib/catalog';
import { RULE_TAB } from '../src/screens/Fingerprints';

describe('health check catalog', () => {
  it('has the 56 checks of crates/vanta-health in screen order', () => {
    const rs = readFileSync(fileURLToPath(new URL('../../../../crates/vanta-health/src/checks.rs', import.meta.url)), 'utf8');
    const body = rs.slice(rs.indexOf('pub const CHECKS'));
    const defs = [...body.matchAll(/c!\(\s*"(H\d+)",\s*"([^"]+)",\s*(\w+),\s*(\w+),\s*"((?:[^"\\]|\\.)*)",/g)];
    expect(defs).toHaveLength(56);
    const snake = (s: string) => s.replace(/(?<!^)([A-Z])/g, '_$1').toLowerCase();
    expect(CHECKS.map(c => [c.id, c.key, c.area, c.severity, c.title])).toEqual(defs.map(d => [d[1], d[2], snake(d[3]), d[4].toLowerCase(), d[5].replace(/\\"/g, '"')]));
  });
  it('covers 8 areas, each non-empty, every check explained', () => {
    expect(AREAS).toHaveLength(8);
    for (const [a] of AREAS) expect(CHECKS.some(c => c.area === a)).toBe(true);
    expect(CHECKS.every(c => c.why.length > 10)).toBe(true);
  });
  it('maps every consistency rule C001–C030 to a Fingerprint Studio tab', () => {
    expect(Object.keys(RULE_TAB)).toEqual(Array.from({ length: 30 }, (_, i) => `C${String(i + 1).padStart(3, '0')}`));
  });
});
