import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";
import {
  applyWaivers,
  validateWaivers,
  validateDocument,
  handleMcpRequest,
} from "../dist/index.js";
const exec = promisify(execFile);
const fixture = JSON.parse(
  readFileSync(new URL("./fixtures/waivers.json", import.meta.url)),
);
for (const c of fixture.cases)
  test(`waivers: ${c.name}`, () => {
    assert.deepEqual(applyWaivers(c.findings, c.waivers, c.date), c.expected);
  });
test("waivers: accepts valid files in code and schema", () => {
  for (const file of fixture.valid) {
    assert.deepEqual(validateWaivers(file), file);
    assert.equal(validateDocument(file, "waivers").valid, true);
  }
});
test("waivers: rejects invalid files in code and schema", () => {
  for (const file of fixture.invalid) {
    assert.throws(() => validateWaivers(file), /Waiver/, JSON.stringify(file));
    assert.equal(
      validateDocument(file, "waivers").valid,
      false,
      JSON.stringify(file),
    );
  }
});
test("waivers: rejects an invalid evaluation date", () => {
  assert.throws(() => applyWaivers([], [], "2026-13-01"), /Waiver/);
});
const waiverFile = (ruleId, expires) =>
  JSON.stringify({
    schemaVersion: "1.0",
    waivers: [
      {
        ruleId,
        justification: "Demo package is not shipped",
        approvedBy: "Security team",
        expires,
      },
    ],
  });
test("CLI: an active waiver keeps the finding and clears the exit code", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "seculens-waiver-"));
  const waivers = path.join(dir, "waivers.json");
  await writeFile(waivers, waiverFile("SECULENS-DEMO-001", "2999-12-31"));
  const args = [
    "dist/cli.js",
    "scan",
    "examples/spdx.json",
    "--db",
    "examples/database.json",
    "--waivers",
    waivers,
    "--fail-on-findings",
    "--output",
    path.join(dir, "out"),
  ];
  await exec(process.execPath, args);
  const report = JSON.parse(
    await readFile(path.join(dir, "out", "report.json"), "utf8"),
  );
  const finding = report.findings.find((f) => f.category === "vulnerability");
  assert.equal(finding.status, "affected");
  assert.equal(finding.waiver.source, "waivers[0]");
  assert.equal(report.schemaVersion, "1.3");
  assert.equal(validateDocument(report, "report").valid, true);
  const older = { ...report, schemaVersion: "1.2" };
  assert.equal(validateDocument(older, "report").valid, false);
  older.findings = older.findings.map(({ waiver, ...f }) => f);
  assert.equal(validateDocument(older, "report").valid, true);
  await writeFile(waivers, waiverFile("SECULENS-DEMO-001", "2000-01-01"));
  await assert.rejects(exec(process.execPath, args), (e) => e.code === 1);
  const expired = JSON.parse(
    await readFile(path.join(dir, "out", "report.json"), "utf8"),
  );
  assert.ok(expired.findings.some((f) => f.ruleId === "WAIVER-EXPIRED"));
});
test("CLI: rejects an invalid waiver file with exit code 2", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "seculens-waiver-"));
  const waivers = path.join(dir, "waivers.json");
  await writeFile(waivers, waiverFile("X", "2027-02-30"));
  await assert.rejects(
    exec(process.execPath, [
      "dist/cli.js",
      "scan",
      "examples/spdx.json",
      "--db",
      "examples/database.json",
      "--waivers",
      waivers,
      "--output",
      path.join(dir, "out"),
    ]),
    (e) => e.code === 2 && e.stderr.includes("expires"),
  );
});
test("MCP: seculens_scan applies waivers and reports the waived count", async () => {
  const response = await handleMcpRequest({
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: {
      name: "seculens_scan",
      arguments: {
        sbomPath: "examples/spdx.json",
        dbPath: "examples/database.json",
        waivers: JSON.parse(waiverFile("SECULENS-DEMO-001", "2999-12-31")),
      },
    },
  });
  const body = JSON.parse(response.result.content[0].text);
  assert.equal(body.summary.waived, 1);
  assert.equal(body.summary.affectedVulnerabilities, 0);
  const bad = await handleMcpRequest({
    jsonrpc: "2.0",
    id: 2,
    method: "tools/call",
    params: {
      name: "seculens_scan",
      arguments: { sbomPath: "examples/spdx.json", waivers: { waivers: [] } },
    },
  });
  assert.equal(bad.result.isError, true);
});
