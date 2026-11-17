import { readFile } from "node:fs/promises";
import path from "node:path";
import type { Finding, Sbom, Component } from "./types.js";

type Hash = { alg: string; content: string };
const isObject = (value: unknown): value is Record<string, any> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

async function readLock(file: string): Promise<Record<string, any> | null> {
  try {
    const value = JSON.parse(await readFile(file, "utf8"));
    return isObject(value) ? value : null;
  } catch {
    return null;
  }
}

/** Hex digests are compared as base64, the encoding npm uses; anything else is compared as written. */
function base64Digest(content: string): string {
  return /^(?:[0-9a-f]{2})+$/i.test(content)
    ? Buffer.from(content, "hex").toString("base64")
    : content;
}

const normalizeAlg = (alg: string) => alg.toLowerCase().replace(/[-_]/g, "");

/**
 * Verify lockfile integrity against the SBOM components and detect tampering or insecure resolution URLs.
 * Reads package-lock.json and composer.lock in `directory`; a missing or unparseable lockfile is skipped.
 */
export async function checkLockfileIntegrity(
  directory: string,
  sbom: Pick<Sbom, "components">,
): Promise<Finding[]> {
  const root = path.resolve(directory);
  const findings: Finding[] = [];

  const npmLock = await readLock(path.join(root, "package-lock.json"));
  if (npmLock) {
    const sbomHashes = new Map<string, Hash[]>();
    for (const c of sbom.components) {
      if (c.name && c.hashes && c.hashes.length > 0) {
        sbomHashes.set(`${c.name}@${c.version ?? ""}`, c.hashes);
      }
    }
    const packages = isObject(npmLock.packages) ? npmLock.packages : {};
    for (const [pkgKey, pkgVal] of Object.entries<any>(packages)) {
      if (!pkgKey || !isObject(pkgVal)) continue;
      const pkgName = pkgKey.split("node_modules/").pop() ?? pkgKey;
      const version = typeof pkgVal.version === "string" ? pkgVal.version : "";
      const resolved = pkgVal.resolved;
      const integrity = pkgVal.integrity;

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

      const hashes = sbomHashes.get(`${pkgName}@${version}`);
      if (!hashes || typeof integrity !== "string" || !integrity.includes("-"))
        continue;
      const separator = integrity.indexOf("-");
      const alg = integrity.slice(0, separator);
      const value = integrity.slice(separator + 1);
      const matched = hashes.some(
        (h) =>
          normalizeAlg(h.alg) === alg.toLowerCase() &&
          (h.content === value || base64Digest(h.content) === value),
      );
      if (!matched) {
        findings.push({
          category: "security",
          ruleId: "SC-INTEGRITY-MISMATCH",
          subject: pkgName,
          status: "review",
          summary: `Lockfile integrity hash mismatch for ${pkgName}@${version}`,
          evidence: `lockfile: "${integrity}"; SBOM hashes: ${JSON.stringify(hashes.map((h) => ({ alg: h.alg, content: h.content })))}`,
          recommendation:
            "Investigate possible package tampering or lockfile poisoning before installing or deploying.",
          file: "package-lock.json",
        });
      }
    }
  }

  const composerLock = await readLock(path.join(root, "composer.lock"));
  if (composerLock) {
    const list = (value: unknown) => (Array.isArray(value) ? value : []);
    for (const p of [
      ...list(composerLock.packages),
      ...list(composerLock["packages-dev"]),
    ]) {
      if (!isObject(p)) continue;
      const name = typeof p.name === "string" ? p.name : "";
      const distUrl = isObject(p.dist) ? p.dist.url : undefined;
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
  }

  return findings;
}

export const COOL_OFF_MAX_DAYS = 3650;

/** Accepts a whole number of days from 1 to 3650, given as a number or a string of digits. */
export function parseCoolOffDays(value: unknown): number {
  const text =
    typeof value === "number" && Number.isInteger(value)
      ? String(value)
      : typeof value === "string"
        ? value
        : "";
  const days = /^[0-9]+$/.test(text) ? Number(text) : NaN;
  if (!(days >= 1 && days <= COOL_OFF_MAX_DAYS)) {
    throw new Error(
      `Cool-off must be a whole number of days from 1 to ${COOL_OFF_MAX_DAYS}`,
    );
  }
  return days;
}

/** Release timestamps by ecosystem, keyed by `name@version`. */
export type ReleaseDates = Record<string, Record<string, string>>;
const COOL_OFF_ECOSYSTEMS = ["npm", "PyPI", "Packagist"];
const TIMESTAMP =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/i;

function timestampMs(text: string): number | null {
  if (!TIMESTAMP.test(text)) return null;
  // Date.parse handles milliseconds only; drop extra fractional digits first.
  const ms = Date.parse(text.replace(/(\.\d{3})\d+/, "$1"));
  return Number.isNaN(ms) ? null : ms;
}

const coolOffTargets = (components: Component[]) => {
  const seen = new Set<string>();
  return components.filter((c) => {
    if (
      !c.name ||
      !c.version ||
      !COOL_OFF_ECOSYSTEMS.includes(c.ecosystem ?? "")
    )
      return false;
    const key = `${c.ecosystem}|${c.name}@${c.version}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
};

/** Pure cool-off evaluation: one finding per npm, PyPI or Packagist release younger than `minDays`. */
export function coolOffFindings(
  components: Component[],
  published: ReleaseDates,
  minDays: number,
  now: Date,
): Finding[] {
  const findings: Finding[] = [];
  for (const c of coolOffTargets(components)) {
    const timeStr = published[c.ecosystem!]?.[`${c.name}@${c.version}`];
    const ms = typeof timeStr === "string" ? timestampMs(timeStr) : null;
    if (ms === null) continue;
    const days = Math.floor((now.getTime() - ms) / 86_400_000);
    if (days < 0 || days >= minDays) continue;
    findings.push({
      category: "security",
      ruleId: "SC-PACKAGE-AGE-UNVERIFIED",
      subject: `${c.name}@${c.version}`,
      status: "review",
      summary: `Package version was released recently (${days} day(s) ago)`,
      evidence: `Published on ${timeStr} (${days} days ago; cool-off threshold=${minDays} days)`,
      recommendation:
        "Allow a cool-off period before upgrading in production to guard against compromised zero-day releases.",
    });
  }
  return findings;
}

async function getJson(url: string): Promise<any> {
  try {
    const res = await fetch(url, {
      headers: { Accept: "application/json", "User-Agent": "SecuLens" },
      signal: AbortSignal.timeout(10_000),
    });
    return res.ok ? await res.json() : null;
  } catch {
    return null;
  }
}

/** Expands Packagist's minified p2 version list, where each entry only lists fields that changed. */
export function expandPackagistVersions(
  versions: unknown,
): Record<string, unknown>[] {
  const expanded: Record<string, unknown>[] = [];
  let previous: Record<string, unknown> = {};
  for (const entry of Array.isArray(versions) ? versions : []) {
    if (!isObject(entry)) continue;
    const current: Record<string, unknown> = { ...previous };
    for (const [key, value] of Object.entries(entry)) {
      if (value === "__unset") delete current[key];
      else current[key] = value;
    }
    expanded.push(current);
    previous = current;
  }
  return expanded;
}

/**
 * Looks up release timestamps from the public registries (registry.npmjs.org, pypi.org, repo.packagist.org).
 * Sends package names and versions only. Lookups that fail are left out, so those components are not flagged.
 */
export async function fetchReleaseDates(
  components: Component[],
): Promise<ReleaseDates> {
  const dates: ReleaseDates = { npm: {}, PyPI: {}, Packagist: {} };
  const documents = new Map<string, Promise<any>>();
  const once = (url: string) => {
    if (!documents.has(url)) documents.set(url, getJson(url));
    return documents.get(url)!;
  };
  for (const c of coolOffTargets(components)) {
    const name = c.name;
    const version = c.version!;
    let time: unknown;
    if (c.ecosystem === "npm") {
      const doc = await once(
        `https://registry.npmjs.org/${name.replace("/", "%2F")}`,
      );
      time = isObject(doc?.time) ? doc.time[version] : undefined;
    } else if (c.ecosystem === "PyPI") {
      const doc = await once(
        `https://pypi.org/pypi/${encodeURIComponent(name)}/${encodeURIComponent(version)}/json`,
      );
      const uploads = (Array.isArray(doc?.urls) ? doc.urls : [])
        .map((u: any) => u?.upload_time_iso_8601)
        .filter((t: unknown): t is string => typeof t === "string")
        .sort();
      time = uploads[0];
    } else if (/^[a-z0-9_.-]+\/[a-z0-9_.-]+$/i.test(name)) {
      const doc = await once(
        `https://repo.packagist.org/p2/${name.toLowerCase()}.json`,
      );
      const versions = expandPackagistVersions(
        doc?.packages?.[name.toLowerCase()],
      );
      const strip = (v: string) => v.replace(/^v/i, "");
      time = versions.find(
        (v) =>
          typeof v.version === "string" && strip(v.version) === strip(version),
      )?.time;
    }
    if (typeof time === "string")
      dates[c.ecosystem!][`${name}@${version}`] = time;
  }
  return dates;
}

/** Check if components have been released within the specified cool-off period. */
export async function checkPackageCoolOff(
  components: Component[],
  minDays: number = 7,
  now: Date = new Date(),
  lookup: (
    components: Component[],
  ) => Promise<ReleaseDates> = fetchReleaseDates,
): Promise<Finding[]> {
  return coolOffFindings(components, await lookup(components), minDays, now);
}
