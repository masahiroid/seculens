import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { componentPriority, cvss4Score, scanSbom, validateContext, validateDocument } from '../dist/index.js';
const load = name => JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url)));
const vectors = load('cvss4-vectors.json');
const fixture = load('priority.json');
test('CVSS 4: published and generated vectors', () => {
  for (const { vector, score } of [...vectors.published, ...vectors.generated]) assert.equal(cvss4Score(vector), score, vector);
});
test('CVSS 4: rejects invalid vectors', () => {
  for (const vector of vectors.invalid) assert.equal(cvss4Score(vector), undefined, vector);
  assert.equal(cvss4Score(null), undefined);
});
test('CVSS 4: every base metric combination matches the shared digest', () => {
  const keys = Object.keys(vectors.baseMetrics);
  const hash = createHash('sha256');
  let count = 0;
  const walk = (i, parts) => {
    if (i === keys.length) {
      const vector = `CVSS:4.0/${parts.join('/')}`;
      hash.update(`${vector} ${cvss4Score(vector).toFixed(1)}\n`);
      count += 1;
      return;
    }
    for (const value of vectors.baseMetrics[keys[i]]) walk(i + 1, [...parts, `${keys[i]}:${value}`]);
  };
  walk(0, []);
  assert.equal(count, vectors.baseVectors.count);
  assert.equal(hash.digest('hex'), vectors.baseVectors.sha256);
});
for (const c of fixture.cases) test(`priority: ${c.name}`, () => {
  assert.deepEqual(componentPriority(c.severity, c.component, c.context), c.expected);
});
test('priority: rejects invalid context', () => {
  for (const context of fixture.invalidContexts) assert.throws(() => validateContext(context), /Policy/, JSON.stringify(context));
});
test('scan: CVSS 4 severity and priority, valid against the report schema', () => {
  const { sbom, records, policy, expected } = fixture.scan;
  const report = scanSbom(JSON.stringify(sbom), records, { policy });
  const finding = report.findings.find(f => f.category === 'vulnerability');
  assert.equal(finding.severity.level, expected.severity.level);
  assert.equal(finding.severity.score, expected.severity.score);
  assert.deepEqual(finding.priority, expected.priority);
  assert.equal(validateDocument(JSON.parse(JSON.stringify(report)), 'report').valid, true);
  assert.equal(scanSbom(JSON.stringify(sbom), records, {}).findings.find(f => f.category === 'vulnerability').priority, undefined);
  assert.throws(() => scanSbom(JSON.stringify(sbom), records, { policy: { context: { foo: 1 } } }), /Policy/);
});
test('validation: keeps accepting schema 1.1 reports and rejects priority in them', () => {
  const { sbom, records, policy } = fixture.scan;
  const report = JSON.parse(JSON.stringify(scanSbom(JSON.stringify(sbom), records, { policy })));
  report.schemaVersion = '1.1';
  assert.equal(validateDocument(report, 'report').schema, 'report-1.1.schema.json');
  assert.equal(validateDocument(report, 'report').valid, false);
  for (const f of report.findings) delete f.priority;
  assert.equal(validateDocument(report, 'report').valid, true);
});
