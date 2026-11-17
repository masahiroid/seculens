import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  parseSbom,
  computeDependencyDepths,
  checkLockfileIntegrity,
  checkPackageCoolOff,
  coolOffFindings,
  expandPackagistVersions,
  fetchReleaseDates,
  parseCoolOffDays,
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

const shared = JSON.parse(
  await readFile(new URL("./fixtures/supply-chain.json", import.meta.url), "utf8"),
);

for (const c of shared.integrity) {
  test(`shared integrity fixture: ${c.name}`, async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "seculens-integrity-"));
    for (const [name, content] of Object.entries(c.files)) {
      await writeFile(
        path.join(dir, name),
        typeof content === "string" ? content : JSON.stringify(content),
      );
    }
    assert.deepEqual(
      await checkLockfileIntegrity(dir, { components: c.components }),
      c.expected,
    );
  });
}

test("checkLockfileIntegrity skips a missing directory", async () => {
  assert.deepEqual(
    await checkLockfileIntegrity(path.join(tmpdir(), "seculens-missing-dir"), {
      components: [],
    }),
    [],
  );
});

test("shared cool-off fixture: findings agree across languages", () => {
  const f = shared.coolOff;
  assert.deepEqual(
    coolOffFindings(f.components, f.published, f.minDays, new Date(f.now)),
    f.expected,
  );
});

test("shared cool-off fixture: day limits", () => {
  for (const value of shared.coolOff.validDays)
    assert.equal(parseCoolOffDays(value), Number(value));
  for (const value of shared.coolOff.invalidDays)
    assert.throws(() => parseCoolOffDays(value), /Cool-off must be a whole number/);
});

test("checkPackageCoolOff uses the injected lookup", async () => {
  const f = shared.coolOff;
  const seen = [];
  const findings = await checkPackageCoolOff(f.components, 7, new Date(f.now), async (c) => {
    seen.push(c.length);
    return f.published;
  });
  assert.deepEqual(findings, f.expected);
  assert.deepEqual(seen, [f.components.length]);
});

test("fetchReleaseDates queries npm, PyPI and Packagist once per document", async (t) => {
  const urls = [];
  t.mock.method(globalThis, "fetch", async (url) => {
    urls.push(String(url));
    const body = String(url).startsWith("https://registry.npmjs.org/")
      ? { time: { "1.0.0": "2026-11-14T00:00:00Z", "1.1.0": "2026-11-15T00:00:00Z" } }
      : String(url).startsWith("https://pypi.org/")
        ? { urls: [{ upload_time_iso_8601: "2026-11-16T02:00:00Z" }, { upload_time_iso_8601: "2026-11-16T01:00:00Z" }] }
        : { packages: { "acme/lib": [{ version: "v1.2.0", time: "2026-11-13T00:00:00+00:00" }, { version: "v1.1.0" }] } };
    return new Response(JSON.stringify(body), { status: String(url).includes("missing") ? 404 : 200 });
  });
  const dates = await fetchReleaseDates([
    { id: "1", name: "@scope/pkg", version: "1.0.0", ecosystem: "npm", licenses: [] },
    { id: "2", name: "@scope/pkg", version: "1.1.0", ecosystem: "npm", licenses: [] },
    { id: "3", name: "Requests", version: "2.40.0", ecosystem: "PyPI", licenses: [] },
    { id: "4", name: "acme/lib", version: "1.2.0", ecosystem: "Packagist", licenses: [] },
    { id: "5", name: "acme/lib", version: "1.1.0", ecosystem: "Packagist", licenses: [] },
    { id: "6", name: "missing", version: "1.0.0", ecosystem: "npm", licenses: [] },
    { id: "7", name: "lib", version: "1.0.0", ecosystem: "Maven", licenses: [] },
  ]);
  assert.deepEqual(dates, {
    npm: { "@scope/pkg@1.0.0": "2026-11-14T00:00:00Z", "@scope/pkg@1.1.0": "2026-11-15T00:00:00Z" },
    PyPI: { "Requests@2.40.0": "2026-11-16T01:00:00Z" },
    Packagist: { "acme/lib@1.2.0": "2026-11-13T00:00:00+00:00", "acme/lib@1.1.0": "2026-11-13T00:00:00+00:00" },
  });
  assert.deepEqual(urls, [
    "https://registry.npmjs.org/@scope%2Fpkg",
    "https://pypi.org/pypi/Requests/2.40.0/json",
    "https://repo.packagist.org/p2/acme/lib.json",
    "https://registry.npmjs.org/missing",
  ]);
});

test("fetchReleaseDates treats network failures as unknown dates", async (t) => {
  t.mock.method(globalThis, "fetch", async () => {
    throw new Error("offline");
  });
  assert.deepEqual(
    await fetchReleaseDates([{ id: "1", name: "a", version: "1.0.0", ecosystem: "npm", licenses: [] }]),
    { npm: {}, PyPI: {}, Packagist: {} },
  );
});

test("expandPackagistVersions honours __unset", () => {
  assert.deepEqual(
    expandPackagistVersions([{ version: "2.0.0", time: "t2", license: ["MIT"] }, { version: "1.0.0", license: "__unset" }]),
    [{ version: "2.0.0", time: "t2", license: ["MIT"] }, { version: "1.0.0", time: "t2" }],
  );
});
