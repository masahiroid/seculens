import ts from "typescript";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import type { Finding } from "./types.js";
export async function analyze(directory: string): Promise<Finding[]> {
  const root = path.resolve(directory);
  const findings: Finding[] = [];
  async function visit(dir: string) {
    for (const entry of (await readdir(dir, { withFileTypes: true })).sort(
      (a, b) => a.name.localeCompare(b.name),
    )) {
      if (
        ["node_modules", "vendor", ".git", "dist", "build"].includes(entry.name)
      )
        continue;
      const file = path.join(dir, entry.name);
      if (entry.isDirectory()) await visit(file);
      else if (entry.isFile() && /\.(?:[cm]?[jt]s|[jt]sx)$/.test(entry.name))
        await inspect(file);
    }
  }
  async function inspect(file: string) {
    const source = ts.createSourceFile(
      file,
      await readFile(file, "utf8"),
      ts.ScriptTarget.Latest,
      true,
    );
    const relative = path.relative(root, file).split(path.sep).join("/");
    const add = (
      n: ts.Node,
      category: "security" | "quality",
      ruleId: string,
      summary: string,
      evidence: string,
    ) =>
      findings.push({
        category,
        ruleId,
        subject: relative,
        status: "review",
        summary,
        evidence,
        recommendation:
          category === "security"
            ? "Review the call and trace untrusted input before deciding whether it is exploitable."
            : "Consider simplifying the function and adding focused tests.",
        file: relative,
        line: source.getLineAndCharacterOfPosition(n.getStart(source)).line + 1,
      });
    function walk(n: ts.Node) {
      if (
        ts.isCallExpression(n) &&
        ts.isIdentifier(n.expression) &&
        n.expression.text === "eval"
      )
        add(
          n,
          "security",
          "JS-EVAL",
          "Direct eval call requires review",
          n.getText(source).slice(0, 300),
        );
      if (
        ts.isNewExpression(n) &&
        ts.isIdentifier(n.expression) &&
        n.expression.text === "Function"
      )
        add(
          n,
          "security",
          "JS-FUNCTION-CONSTRUCTOR",
          "Dynamic Function constructor requires review",
          n.getText(source).slice(0, 300),
        );
      if (
        ts.isBinaryExpression(n) &&
        n.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        ts.isPropertyAccessExpression(n.left) &&
        ["innerHTML", "outerHTML"].includes(n.left.name.text)
      )
        add(
          n,
          "security",
          "JS-HTML-ASSIGNMENT",
          "HTML assignment requires review",
          n.getText(source).slice(0, 300),
        );
      if (
        ts.isCallExpression(n) &&
        ((ts.isIdentifier(n.expression) &&
          [
            "exec",
            "execSync",
            "spawn",
            "spawnSync",
            "execFile",
            "execFileSync",
          ].includes(n.expression.text)) ||
          (ts.isPropertyAccessExpression(n.expression) &&
            [
              "exec",
              "execSync",
              "spawn",
              "spawnSync",
              "execFile",
              "execFileSync",
            ].includes(n.expression.name.text)))
      )
        add(
          n,
          "security",
          "JS-CHILD-PROCESS",
          "Child process execution requires review",
          n.getText(source).slice(0, 300),
        );
      if (
        ts.isPropertyAccessExpression(n) &&
        ts.isIdentifier(n.expression) &&
        n.expression.text === "process" &&
        n.name.text === "env"
      )
        add(
          n,
          "security",
          "JS-PROCESS-ENV",
          "Environment variable access requires review",
          n.getText(source).slice(0, 300),
        );
      if (
        (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) &&
        /(?:\/\.ssh|\/\.aws|\/\.npmrc|id_rsa|id_ed25519)/.test(n.text)
      )
        add(
          n,
          "security",
          "JS-SENSITIVE-PATH",
          "Sensitive credential path reference requires review",
          n.getText(source).slice(0, 300),
        );
      if (ts.isFunctionLike(n) && "body" in n && n.body) {
        let complexity = 1,
          maxDepth = 0;
        function count(x: ts.Node, depth: number) {
          if (x !== n && ts.isFunctionLike(x)) return;
          const branch =
            ts.isIfStatement(x) ||
            ts.isForStatement(x) ||
            ts.isForInStatement(x) ||
            ts.isForOfStatement(x) ||
            ts.isWhileStatement(x) ||
            ts.isDoStatement(x) ||
            ts.isConditionalExpression(x) ||
            ts.isCatchClause(x) ||
            ts.isCaseClause(x);
          if (branch) complexity++;
          if (
            ts.isBinaryExpression(x) &&
            [
              ts.SyntaxKind.AmpersandAmpersandToken,
              ts.SyntaxKind.BarBarToken,
              ts.SyntaxKind.QuestionQuestionToken,
            ].includes(x.operatorToken.kind)
          )
            complexity++;
          const next = depth + (branch ? 1 : 0);
          maxDepth = Math.max(maxDepth, next);
          ts.forEachChild(x, (c) => count(c, next));
        }
        count(n.body, 0);
        if (complexity > 10 || maxDepth > 4)
          add(
            n,
            "quality",
            "JS-COMPLEXITY",
            "Function complexity exceeds the baseline",
            `cyclomatic=${complexity}; nesting=${maxDepth}; thresholds=10,4`,
          );
      }
      ts.forEachChild(n, walk);
    }
    walk(source);
    const diagnostics = (source as any).parseDiagnostics as ts.Diagnostic[];
    for (const d of diagnostics || [])
      findings.push({
        category: "coverage",
        ruleId: "JS-PARSE-ERROR",
        subject: relative,
        status: "unassessed",
        summary: "Source could not be completely parsed",
        evidence: ts.flattenDiagnosticMessageText(d.messageText, " "),
        recommendation: "Resolve the syntax error and repeat the analysis.",
        file: relative,
      });
  }
  await visit(root);
  findings.push(...(await checkLifecycleScripts(root)));
  return findings;
}

export async function checkLifecycleScripts(
  directory: string,
): Promise<Finding[]> {
  const root = path.resolve(directory);
  const findings: Finding[] = [];

  const pkgFile = path.join(root, "package.json");
  try {
    const raw = await readFile(pkgFile, "utf8");
    const json = JSON.parse(raw);
    if (json.scripts && typeof json.scripts === "object") {
      const hooks = [
        "preinstall",
        "install",
        "postinstall",
        "preuninstall",
        "postuninstall",
      ];
      for (const hook of hooks) {
        if (
          typeof json.scripts[hook] === "string" &&
          json.scripts[hook].trim().length > 0
        ) {
          findings.push({
            category: "security",
            ruleId: "SC-LIFECYCLE-SCRIPT",
            subject: "package.json",
            status: "review",
            summary: `Lifecycle script '${hook}' detected in root project`,
            evidence: `"${hook}": "${json.scripts[hook]}"`,
            recommendation:
              "Review the lifecycle script or install with --ignore-scripts to avoid arbitrary command execution during installation.",
            file: "package.json",
          });
        }
      }
    }
  } catch {
    // ignore missing or invalid package.json
  }

  const lockFile = path.join(root, "package-lock.json");
  try {
    const raw = await readFile(lockFile, "utf8");
    const lock = JSON.parse(raw);
    if (lock.packages && typeof lock.packages === "object") {
      for (const [pkgPath, pkgVal] of Object.entries<any>(lock.packages)) {
        if (!pkgPath) continue;
        if (pkgVal && pkgVal.hasInstallScript) {
          const name = pkgPath.replace(/^.*node_modules\//, "");
          findings.push({
            category: "security",
            ruleId: "SC-LIFECYCLE-SCRIPT",
            subject: name,
            status: "review",
            summary: `Dependency has install script: ${name}`,
            evidence: `hasInstallScript: true (version: ${pkgVal.version || "unknown"})`,
            recommendation:
              "Review the package installation scripts or use --ignore-scripts.",
            file: "package-lock.json",
          });
        }
      }
    }
  } catch {
    // ignore missing or invalid package-lock.json
  }

  return findings;
}
