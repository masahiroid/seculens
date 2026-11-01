import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { compare, matchRecord } from '../dist/matcher.js';
const cases = JSON.parse(readFileSync(new URL('./fixtures/composer-versions.json', import.meta.url)));
for (const c of cases) test(`composer: ${c.a} vs ${c.b}`, () => {
  assert.equal(compare(c.a, c.b, 'Packagist'), c.expected);
  if (c.expected !== null) assert.equal(compare(c.b, c.a, 'Packagist'), -c.expected || 0);
});
test('Packagist ranges use Composer stability order', () => {
  const record = { id: 'X', affected: [{ package: { name: 'acme/lib', ecosystem: 'Packagist' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '2.0.0-RC1' }] }] }] };
  const at = version => matchRecord({ name: 'acme/lib', ecosystem: 'Packagist', version }, record);
  assert.equal(at('2.0.0-beta3'), 'affected');
  assert.equal(at('2.0.0-RC1'), 'not-affected');
  assert.equal(at('1.9.9.1'), 'affected');
  assert.equal(at('2.x-dev'), 'unknown');
});
