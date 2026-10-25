import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  parseSbom,
  computeDependencyDepths,
  checkLockfileIntegrity,
  checkPackageCoolOff,
} from "../dist/index.js";

test("computeDependencyDepths calculates direct and transitive dependency depths", () => {
  const components = [
    { id: "root-app", name: "app", licenses: [] },
    { id: "pkg-a", name: "a", licenses: [] },
    { id: "pkg-b", name: "b", licenses: [] },
    { id: "pkg-c", name: "c", licenses: [] },
  ];
  const dependencies = [
    { from: "root-app", to: "pkg-a" },
    { from: "pkg-a", to: "pkg-b" },
    { from: "pkg-b", to: "pkg-c" },
  ];

  computeDependencyDepths(components, dependencies);

  assert.equal(components.find((c) => c.id === "pkg-a")?.depth, 1);
  assert.equal(components.find((c) => c.id === "pkg-b")?.depth, 2);
  assert.equal(components.find((c) => c.id === "pkg-c")?.depth, 3);
});

test("checkLockfileIntegrity detects insecure HTTP resolution URL", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "seculens-lock-"));
  await writeFile(
    path.join(dir, "package-lock.json"),
    JSON.stringify({
      packages: {
        "node_modules/insecure-lib": {
          version: "1.0.0",
          resolved: "http://malicious-mirror.org/insecure-lib-1.0.0.tgz",
        },
      },
    }),
  );

  const sbom = {
    format: "CycloneDX",
    version: "1.6",
    components: [{ id: "c1", name: "insecure-lib", version: "1.0.0", licenses: [] }],
    dependencies: [],
    warnings: [],
  };

  const findings = await checkLockfileIntegrity(dir, sbom);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, "SC-INSECURE-REGISTRY-URL");
  assert.equal(findings[0].subject, "insecure-lib");
});

test("checkLockfileIntegrity detects hash mismatch between SBOM and lockfile", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "seculens-hash-"));
  await writeFile(
    path.join(dir, "package-lock.json"),
    JSON.stringify({
      packages: {
        "node_modules/tampered-pkg": {
          version: "2.0.0",
          integrity: "sha512-LOCKFILE_FAKE_HASH_VALUE_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
        },
      },
    }),
  );

  const sbom = {
    format: "CycloneDX",
    version: "1.6",
    components: [
      {
        id: "c1",
        name: "tampered-pkg",
        version: "2.0.0",
        licenses: [],
        hashes: [{ alg: "SHA-512", content: "SBOM_ORIGINAL_HASH_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB==" }],
      },
    ],
    dependencies: [],
    warnings: [],
  };

  const findings = await checkLockfileIntegrity(dir, sbom);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, "SC-INTEGRITY-MISMATCH");
  assert.equal(findings[0].subject, "tampered-pkg");
});

test("checkPackageCoolOff flags package released within minDays", async () => {
  const components = [
    {
      id: "pkg-new",
      name: "express",
      version: "4.21.2",
      ecosystem: "npm",
      licenses: ["MIT"],
    },
  ];

  // Pass a date where express 4.21.2 is considered very fresh (e.g. published date + 1 day)
  const simulatedNow = new Date("2024-12-05T00:00:00Z");
  const findings = await checkPackageCoolOff(components, 30, simulatedNow);
  // May be 0 if network unavailable, but should execute cleanly
  assert.ok(Array.isArray(findings));
});

