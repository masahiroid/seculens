import { readFile } from "node:fs/promises";
import path from "node:path";
import type { Finding, Sbom, Component } from "./types.js";

/**
 * Verify lockfile integrity against the SBOM components and detect tampering or insecure resolution URLs.
 */
export async function checkLockfileIntegrity(
  directory: string,
  sbom: Sbom,
): Promise<Finding[]> {
  const root = path.resolve(directory);
  const findings: Finding[] = [];

  // 1. Verify npm package-lock.json
  const npmLockPath = path.join(root, "package-lock.json");
  try {
    const raw = await readFile(npmLockPath, "utf8");
    const lock = JSON.parse(raw);
    const packages = lock.packages || {};

    // Build map of SBOM hashes
    const sbomHashes = new Map<string, { alg: string; content: string }[]>();
    for (const c of sbom.components) {
      if (c.name && c.hashes && c.hashes.length > 0) {
        sbomHashes.set(`${c.name}@${c.version || ""}`, c.hashes);
      }
    }

    for (const [pkgKey, pkgVal] of Object.entries<any>(packages)) {
      if (!pkgKey || typeof pkgVal !== "object") continue;
      const pkgName = pkgKey.replace(/^.*node_modules\//, "");
      const version = pkgVal.version || "";
      const resolved = pkgVal.resolved || "";
      const integrity = pkgVal.integrity || "";

      // Insecure resolution URL check
      if (typeof resolved === "string" && resolved.startsWith("http://")) {
        findings.push({
          category: "security",
          ruleId: "SC-INSECURE-REGISTRY-URL",
          subject: pkgName,
          status: "review",
          summary: `Insecure HTTP package resolution URL: ${pkgName}`,
          evidence: `resolved: "${resolved}"`,
          recommendation:
            "Replace HTTP package sources with secure HTTPS registries to prevent man-in-the-middle attacks.",
          file: "package-lock.json",
        });
      }

      // Hash mismatch check against SBOM if present
      const key = `${pkgName}@${version}`;
      const sbomHashList = sbomHashes.get(key);
      if (sbomHashList && integrity) {
        // e.g. integrity: "sha512-ABC..."
        const [alg, val] = integrity.split("-");
        if (alg && val) {
          const match = sbomHashList.some((h) => {
            const hAlg = h.alg.toLowerCase().replace(/[^a-z0-9]/g, "");
            return (
              hAlg === alg.toLowerCase() &&
              (h.content === val ||
                Buffer.from(h.content, "hex").toString("base64") === val)
            );
          });
          if (!match && sbomHashList.length > 0) {
            findings.push({
              category: "security",
              ruleId: "SC-INTEGRITY-MISMATCH",
              subject: pkgName,
              status: "review",
              summary: `Lockfile integrity hash mismatch for ${pkgName}@${version}`,
              evidence: `lockfile: "${integrity}"; SBOM hashes: ${JSON.stringify(sbomHashList)}`,
              recommendation:
                "Investigate possible package tampering or lockfile poisoning before installing or deploying.",
              file: "package-lock.json",
            });
          }
        }
      }
    }
  } catch {
    // package-lock.json not found or unparseable
  }

  // 2. Verify Composer composer.lock
  const composerLockPath = path.join(root, "composer.lock");
  try {
    const raw = await readFile(composerLockPath, "utf8");
    const lock = JSON.parse(raw);
    const pkgs = [
      ...(lock.packages || []),
      ...(lock["packages-dev"] || []),
    ];

    for (const p of pkgs) {
      if (!p || typeof p !== "object") continue;
      const name = p.name || "";
      const distUrl = p.dist?.url || "";

      if (typeof distUrl === "string" && distUrl.startsWith("http://")) {
        findings.push({
          category: "security",
          ruleId: "SC-INSECURE-REGISTRY-URL",
          subject: name,
          status: "review",
          summary: `Insecure HTTP download URL in composer.lock: ${name}`,
          evidence: `dist.url: "${distUrl}"`,
          recommendation:
            "Use secure HTTPS package sources to avoid tampering during download.",
          file: "composer.lock",
        });
      }
    }
  } catch {
    // composer.lock not found or unparseable
  }

  return findings;
}

/**
 * Check if components have been released within the specified cool-off period.
 */
export async function checkPackageCoolOff(
  components: Component[],
  minDays: number = 7,
  now: Date = new Date(),
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const npmComponents = components.filter(
    (c) => c.ecosystem === "npm" && c.name && c.version,
  );

  for (const c of npmComponents) {
    try {
      const url = `https://registry.npmjs.org/${encodeURIComponent(c.name)}`;
      const res = await fetch(url, { headers: { Accept: "application/json" } });
      if (!res.ok) continue;
      const data = (await res.json()) as any;
      const timeStr = data.time?.[c.version!];
      if (timeStr) {
        const publishedDate = new Date(timeStr);
        const diffMs = now.getTime() - publishedDate.getTime();
        const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
        if (diffDays >= 0 && diffDays < minDays) {
          findings.push({
            category: "security",
            ruleId: "SC-PACKAGE-AGE-UNVERIFIED",
            subject: `${c.name}@${c.version}`,
            status: "review",
            summary: `Package version was released recently (${diffDays} day(s) ago)`,
            evidence: `Published on ${timeStr} (${diffDays} days ago; cool-off threshold=${minDays} days)`,
            recommendation:
              "Allow a cool-off period before upgrading in production to guard against compromised zero-day releases.",
          });
        }
      }
    } catch {
      // ignore network errors
    }
  }

  return findings;
}

