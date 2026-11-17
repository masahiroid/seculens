import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { handleMcpRequest, MCP_TOOLS } from "../dist/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");

test("MCP initialize returns protocol version and server capabilities", async () => {
  const res = await handleMcpRequest({
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2024-11-05",
      clientInfo: { name: "test-client" },
    },
  });

  assert.equal(res.id, 1);
  assert.equal(res.result.protocolVersion, "2024-11-05");
  assert.equal(res.result.serverInfo.name, "seculens");
  assert.ok(res.result.capabilities.tools);
});

test("MCP tools/list returns available SecuLens tools", async () => {
  const res = await handleMcpRequest({
    jsonrpc: "2.0",
    id: 2,
    method: "tools/list",
  });

  assert.equal(res.id, 2);
  const toolNames = res.result.tools.map((t) => t.name);
  assert.ok(toolNames.includes("seculens_scan"));
  assert.ok(toolNames.includes("seculens_analyze"));
  assert.ok(toolNames.includes("seculens_check_license"));
  assert.ok(toolNames.includes("seculens_generate_report"));
});

test("MCP tools/call seculens_check_license evaluates license", async () => {
  const res = await handleMcpRequest({
    jsonrpc: "2.0",
    id: 3,
    method: "tools/call",
    params: {
      name: "seculens_check_license",
      arguments: {
        expression: "MIT OR Apache-2.0",
        allow: ["MIT"],
      },
    },
  });

  assert.equal(res.id, 3);
  assert.equal(res.result.isError, false);
  const data = JSON.parse(res.result.content[0].text);
  assert.equal(data.status, "allowed");
});

test("MCP tools/call seculens_scan performs offline assessment", async () => {
  const res = await handleMcpRequest({
    jsonrpc: "2.0",
    id: 4,
    method: "tools/call",
    params: {
      name: "seculens_scan",
      arguments: {
        sbomPath: path.join(ROOT, "examples/cyclonedx.json"),
        dbPath: path.join(ROOT, "examples/database.json"),
        policy: { allow: ["MIT", "Apache-2.0"] },
      },
    },
  });

  assert.equal(res.id, 4);
  assert.equal(res.result.isError, false);
  const data = JSON.parse(res.result.content[0].text);
  assert.ok(data.summary.components > 0);
  assert.ok(Array.isArray(data.findings));
});


test("MCP seculens_scan checks lockfileDir and rejects invalid coolOffDays", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "seculens-mcp-"));
  await writeFile(
    path.join(dir, "composer.lock"),
    JSON.stringify({ packages: [{ name: "acme/http", dist: { url: "http://mirror.example/a.zip" } }] }),
  );
  const call = (extra) =>
    handleMcpRequest({
      jsonrpc: "2.0",
      id: 9,
      method: "tools/call",
      params: {
        name: "seculens_scan",
        arguments: {
          sbomPath: path.join(ROOT, "examples/cyclonedx.json"),
          dbPath: path.join(ROOT, "examples/database.json"),
          lockfileDir: dir,
          ...extra,
        },
      },
    });
  const ok = await call({});
  assert.equal(ok.result.isError, false);
  assert.ok(
    JSON.parse(ok.result.content[0].text).findings.some(
      (f) => f.ruleId === "SC-INSECURE-REGISTRY-URL",
    ),
  );
  for (const coolOffDays of [0, 1.5, "x"]) {
    const bad = await call({ coolOffDays });
    assert.equal(bad.result.isError, true);
    assert.match(bad.result.content[0].text, /Cool-off must be a whole number/);
  }
});
