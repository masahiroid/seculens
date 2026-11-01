import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { validateDocument, scanSbom } from '../dist/index.js';
const cases = JSON.parse(readFileSync(new URL('./fixtures/validation.json', import.meta.url)));
for (const c of cases) test(`schema: ${c.name}`, () => {
  const result = validateDocument(c.input, c.kind);
  assert.equal(result.valid, c.valid, JSON.stringify(result));
  assert.equal(result.errors.length === 0, c.valid);
});
test('serialized reports obey the 1.1 schema; malformed nested fields fail', () => {
  const report = JSON.parse(JSON.stringify(scanSbom(readFileSync(new URL('../examples/cyclonedx.json',import.meta.url),'utf8'), JSON.parse(readFileSync(new URL('../examples/database.json',import.meta.url),'utf8')).records)));
  assert.equal(validateDocument(report,'report').valid,true);
  for (const mutate of [r => r.schemaVersion='2', r => r.checks[0].status='safe', r => r.sbom.components[0].depth=-1, r => r.findings[0].severity={level:'high',score:11,sources:[]}, r => delete r.database.sha256]) {
    const bad=structuredClone(report); mutate(bad);
    assert.equal(validateDocument(bad,'report').valid,false);
  }
});
test('CLI validation returns JSON and exit codes without a database', () => {
  const run=(...args)=>spawnSync(process.execPath,['dist/cli.js','validate',...args],{encoding:'utf8'});
  const ok=run('examples/cyclonedx.json'); assert.equal(ok.status,0); assert.equal(JSON.parse(ok.stdout).valid,true);
  const bad=run('examples/policy.json'); assert.equal(bad.status,2); assert.equal(JSON.parse(bad.stdout).valid,false);
  assert.equal(run('examples/cyclonedx.json','--kind','other').status,2);
});
