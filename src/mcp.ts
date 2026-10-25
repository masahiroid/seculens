import { readFile, writeFile, mkdir, mkdtemp } from "node:fs/promises";
import path from "node:path";
import readline from "node:readline";
import {
  scanSbom,
  parseSbom,
  fetchDatabase,
  validateDatabase,
  evaluateLicense,
  analyze,
  writeWordReport,
  sha256,
  checkLockfileIntegrity,
  checkPackageCoolOff,
} from "./index.js";
import type { Policy, OsvRecord } from "./types.js";

export const MCP_TOOLS = [
  {
    name: "seculens_scan",
    description:
      "Scan SPDX or CycloneDX SBOM for known vulnerabilities (OSV) and license policy violations",
    inputSchema: {
      type: "object",
      properties: {
        sbomPath: {
          type: "string",
          description: "Path to SPDX or CycloneDX JSON file",
        },
        dbPath: {
          type: "string",
          description: "Path to local OSV JSON snapshot (optional, offline)",
        },
        fetchOsv: {
          type: "boolean",
          description:
            "Fetch candidate advisories from api.osv.dev if dbPath not provided (default: true)",
        },
        policy: {
          type: "object",
          description: "License policy with allow and/or deny lists",
          properties: {
            allow: { type: "array", items: { type: "string" } },
            deny: { type: "array", items: { type: "string" } },
          },
        },
      },
      required: ["sbomPath"],
    },
  },
  {
    name: "seculens_analyze",
    description:
      "Perform static AST analysis and supply chain inspection on source directory and lifecycle scripts",
    inputSchema: {
      type: "object",
      properties: {
        directory: {
          type: "string",
          description: "Directory containing source code and package files",
        },
      },
      required: ["directory"],
    },
  },
  {
    name: "seculens_check_license",
    description: "Evaluate an SPDX license expression against allow/deny lists",
    inputSchema: {
      type: "object",
      properties: {
        expression: {
          type: "string",
          description: "SPDX license expression (e.g. 'MIT OR Apache-2.0')",
        },
        allow: { type: "array", items: { type: "string" } },
        deny: { type: "array", items: { type: "string" } },
      },
      required: ["expression"],
    },
  },
  {
    name: "seculens_generate_report",
    description:
      "Generate customer Word (.docx) and JSON reports from SBOM and analysis results",
    inputSchema: {
      type: "object",
      properties: {
        sbomPath: { type: "string", description: "Path to SBOM JSON" },
        outputDir: {
          type: "string",
          description:
            "Directory where report.docx and report.json will be saved",
        },
        customer: { type: "string", description: "Customer name" },
        target: { type: "string", description: "Target system name" },
        dbPath: {
          type: "string",
          description: "Path to local OSV JSON snapshot (optional)",
        },
        sourceDir: {
          type: "string",
          description: "Optional source directory for AST analysis",
        },
        lang: {
          type: "string",
          enum: ["en", "ja"],
          description: "Report language: en or ja",
        },
      },
      required: ["sbomPath", "outputDir"],
    },
  },
];

export async function handleMcpRequest(request: any): Promise<any> {
  const { id, method, params } = request;

  if (method === "initialize") {
    return {
      jsonrpc: "2.0",
      id,
      result: {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: "seculens", version: "1.1.0" },
      },
    };
  }

  if (method === "notifications/initialized") {
    return null;
  }

  if (method === "ping") {
    return { jsonrpc: "2.0", id, result: {} };
  }

  if (method === "tools/list") {
    return {
      jsonrpc: "2.0",
      id,
      result: { tools: MCP_TOOLS },
    };
  }

  if (method === "tools/call") {
    const { name, arguments: args = {} } = params || {};
    try {
      let contentText = "";
      if (name === "seculens_scan") {
        const input = await readFile(path.resolve(args.sbomPath), "utf8");
        const sbom = parseSbom(JSON.parse(input));
        let records: OsvRecord[] = [];
        let dbSource = "None";
        let dbHash = "";
        if (args.dbPath) {
          const dbText = await readFile(path.resolve(args.dbPath), "utf8");
          records = validateDatabase(JSON.parse(dbText));
          dbSource = path.basename(args.dbPath);
          dbHash = sha256(dbText);
        } else if (args.fetchOsv !== false) {
          records = await fetchDatabase(sbom.components);
          dbSource = "OSV API snapshot";
          dbHash = sha256(JSON.stringify(records));
        }
        const policy: Policy = args.policy || {};
        const report = scanSbom(input, records, {
          databaseSource: dbSource,
          databaseHash: dbHash,
          policy,
        });
        const lockfileDir = args.lockfileDir || path.dirname(path.resolve(args.sbomPath));
        report.findings.push(...(await checkLockfileIntegrity(lockfileDir, sbom)));
        if (args.coolOffDays) {
          report.findings.push(...(await checkPackageCoolOff(sbom.components, Number(args.coolOffDays))));
        }
        contentText = JSON.stringify(
          {
            summary: {
              components: report.sbom.components.length,
              findings: report.findings.length,
              affectedVulnerabilities: report.findings.filter(
                (f) =>
                  f.category === "vulnerability" && f.status === "affected",
              ).length,
              deniedLicenses: report.findings.filter(
                (f) => f.category === "license" && f.status === "denied",
              ).length,
            },
            findings: report.findings,
          },
          null,
          2,
        );
      } else if (name === "seculens_analyze") {
        const findings = await analyze(path.resolve(args.directory));
        contentText = JSON.stringify(
          {
            totalFindings: findings.length,
            securityReviewCandidates: findings.filter(
              (f) => f.category === "security",
            ).length,
            qualityFindings: findings.filter((f) => f.category === "quality")
              .length,
            findings,
          },
          null,
          2,
        );
      } else if (name === "seculens_check_license") {
        const status = evaluateLicense(args.expression, {
          allow: args.allow || [],
          deny: args.deny || [],
        });
        contentText = JSON.stringify({ expression: args.expression, status });
      } else if (name === "seculens_generate_report") {
        const input = await readFile(path.resolve(args.sbomPath), "utf8");
        const sbom = parseSbom(JSON.parse(input));
        let records: OsvRecord[] = [];
        let dbText = "{}";
        if (args.dbPath) {
          dbText = await readFile(path.resolve(args.dbPath), "utf8");
          records = validateDatabase(JSON.parse(dbText));
        } else {
          records = await fetchDatabase(sbom.components);
          dbText = JSON.stringify({ records }, null, 2);
        }
        const report = scanSbom(input, records, {
          customer: args.customer || "Customer",
          target: args.target || path.basename(args.sbomPath),
          databaseSource: args.dbPath
            ? path.basename(args.dbPath)
            : "OSV API snapshot",
          databaseHash: sha256(dbText),
        });
        if (args.sourceDir) {
          report.findings.push(...(await analyze(path.resolve(args.sourceDir))));
        }
        await mkdir(path.resolve(args.outputDir), {
          recursive: true,
          mode: 0o700,
        });
        const jsonPath = path.join(
          path.resolve(args.outputDir),
          "report.json",
        );
        const docxPath = path.join(
          path.resolve(args.outputDir),
          "report.docx",
        );
        await writeFile(jsonPath, JSON.stringify(report, null, 2) + "\n", {
          mode: 0o600,
        });
        await writeWordReport(
          report,
          docxPath,
          args.lang === "ja" ? "ja" : "en",
          { style: "customer" },
        );
        contentText = JSON.stringify(
          {
            status: "success",
            reportJson: jsonPath,
            reportDocx: docxPath,
            findingsCount: report.findings.length,
          },
          null,
          2,
        );
      } else {
        return {
          jsonrpc: "2.0",
          id,
          error: { code: -32601, message: `Unknown tool: ${name}` },
        };
      }

      return {
        jsonrpc: "2.0",
        id,
        result: {
          content: [{ type: "text", text: contentText }],
          isError: false,
        },
      };
    } catch (err: any) {
      return {
        jsonrpc: "2.0",
        id,
        result: {
          content: [{ type: "text", text: `Error: ${err.message}` }],
          isError: true,
        },
      };
    }
  }

  return {
    jsonrpc: "2.0",
    id,
    error: { code: -32601, message: `Method not found: ${method}` },
  };
}

export async function runMcpServer(): Promise<void> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: false,
  });

  for await (const line of rl) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const parsed = JSON.parse(trimmed);
      const response = await handleMcpRequest(parsed);
      if (response !== null) {
        process.stdout.write(JSON.stringify(response) + "\n");
      }
    } catch (e: any) {
      process.stdout.write(
        JSON.stringify({
          jsonrpc: "2.0",
          id: null,
          error: { code: -32700, message: "Parse error" },
        }) + "\n",
      );
    }
  }
}
