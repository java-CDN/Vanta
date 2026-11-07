import { describe, expect, it } from 'vitest';
import { buildQuery, matches, parse, tokenize, validate } from '../src/lib/search';
import type { ProfileMeta } from '../src/api/types';

const meta = (o: Partial<ProfileMeta>): ProfileMeta => ({
  id: 'x', name: 'p', folder: '', tags: [], os: 'windows11', proxy_id: null, exit_ip: '', country: '', health: 0,
  status: 'stopped', color: '', notes: '', created_ms: 0, last_opened_ms: null, ...o,
});

describe('search language (mirrors vanta-store query.rs)', () => {
  it('parses every filter', () => {
    expect(parse('tag:shop os:win11 health:<80 status:running folder:"QA Lab" proxy:de frank')).toEqual([[
      { k: 'tag', v: 'shop' }, { k: 'os', v: 'windows11' }, { k: 'health', cmp: '<', n: 80 }, { k: 'status', v: 'running' },
      { k: 'folder', v: 'QA Lab' }, { k: 'proxy', v: 'de' }, { k: 'text', v: 'frank' },
    ]]);
  });
  it('splits OR groups', () => {
    expect(parse('tag:shop OR tag:ads')).toHaveLength(2);
    expect(parse('OR OR tag:a')).toHaveLength(1);
  });
  it('accepts os aliases and all health comparators', () => {
    expect(parse('os:W10')[0][0]).toEqual({ k: 'os', v: 'windows10' });
    for (const [s, c] of [['<=5', '<='], ['>=5', '>='], ['>5', '>'], ['=5', '='], ['5', '=']] as const) expect(parse('health:' + s)[0][0]).toEqual({ k: 'health', cmp: c, n: 5 });
  });
  it('reports the same errors as the store', () => {
    for (const q of ['os:beos', 'os:mac', 'os:linux', 'health:<abc', 'health:>101', 'status:flying', 'folder:"open']) expect(validate(q)).not.toBe('');
    expect(validate('os:mac')).toContain("unknown os 'mac'");
    expect(validate('tag:shop')).toBe('');
  });
  it('treats unknown keys and empty values as text', () => {
    expect(parse('foo:bar')[0][0]).toEqual({ k: 'text', v: 'foo:bar' });
    expect(parse('tag:')[0][0]).toEqual({ k: 'text', v: 'tag:' });
  });
  it('tokenizes quotes', () => {
    expect(tokenize('folder:"QA Lab" x')).toEqual(['folder:QA Lab', 'x']);
  });
  it('matches like the SQL', () => {
    const p = meta({ name: 'shop-de-01', tags: ['shop', 'de'], health: 79, status: 'running', folder: 'E-commerce', country: 'DE', exit_ip: '203.0.113.24' });
    expect(matches(parse('tag:shop health:<80'), p)).toBe(true);
    expect(matches(parse('tag:sho'), p)).toBe(false); // tags are whole words
    expect(matches(parse('folder:e-commerce'), p)).toBe(true); // NOCASE
    expect(matches(parse('proxy:de'), p)).toBe(true);
    expect(matches(parse('proxy:203.0.113'), p)).toBe(true);
    expect(matches(parse('shop-de'), p)).toBe(true); // FTS phrase prefix
    expect(matches(parse('sho'), p)).toBe(true);
    expect(matches(parse('status:stopped OR tag:de'), p)).toBe(true);
    expect(matches(parse('status:stopped OR tag:us'), p)).toBe(false);
    expect(matches(parse(''), p)).toBe(true);
  });
  it('builds queries from the filter controls', () => {
    const none = { status: '', tag: '', country: '', folder: '' };
    expect(buildQuery('  shop ', none)).toBe('shop');
    expect(buildQuery('', { ...none, status: 'Running', tag: 'ads' })).toBe('status:running tag:ads');
    expect(buildQuery('', { ...none, folder: 'QA Lab', country: 'IN' })).toBe('proxy:IN folder:"QA Lab"');
    expect(buildQuery('tag:a OR tag:b', { ...none, status: 'Blocked' })).toBe('tag:a status:blocked OR tag:b status:blocked');
    expect(validate(buildQuery('x', { status: 'Running', tag: 'a b', country: 'DE', folder: 'Q "L"' }))).toBe('');
  });
});
