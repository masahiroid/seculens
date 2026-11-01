import semver from "semver";
import * as pep440 from "@renovatebot/pep440";
import type { Component, OsvRecord } from "./types.js";
export type Match = "affected" | "not-affected" | "unknown";
const canonical = (name: string, ecosystem: string) =>
  ecosystem === "PyPI" ? name.toLowerCase().replace(/[-_.]+/g, "-") : name;
export function samePackage(
  c: Component,
  p: { name: string; ecosystem: string },
): boolean {
  return (
    c.ecosystem === p.ecosystem &&
    canonical(c.name, p.ecosystem) === canonical(p.name, p.ecosystem)
  );
}
// Composer stability order: dev < alpha < beta < RC < stable < patch.
const STABILITY: Record<string, number> = {
  alpha: 1,
  a: 1,
  beta: 2,
  b: 2,
  rc: 3,
  stable: 4,
  patch: 5,
  pl: 5,
  p: 5,
};
const COMPOSER =
  /^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?(?:[._-]?(stable|beta|b|rc|alpha|a|patch|pl|p)(?:[.-]?(\d+))?)?([.-]?dev)?$/i;
/** Composer VersionParser normalization; branch versions return null. */
function composerKey(v: string): string[] | null {
  const m = COMPOSER.exec(v.trim().replace(/^v/i, "").replace(/\+.*$/, ""));
  if (!m) return null;
  const rank = m[5] ? STABILITY[m[5].toLowerCase()] : m[7] ? 0 : 4;
  const dev = m[5] && m[7] ? "0" : "1";
  return [m[1], m[2], m[3], m[4], String(rank), m[6], dev].map((x) =>
    (x ?? "0").replace(/^0+(?=\d)/, ""),
  );
}
function compareComposer(a: string, b: string): number | null {
  const x = composerKey(a),
    y = composerKey(b);
  if (!x || !y) return null;
  for (let i = 0; i < x.length; i++) {
    const n =
      x[i].length - y[i].length || (x[i] < y[i] ? -1 : x[i] > y[i] ? 1 : 0);
    if (n) return Math.sign(n);
  }
  return 0;
}
export function compare(
  a: string,
  b: string,
  ecosystem: string,
): number | null {
  if (ecosystem === "Packagist") return compareComposer(a, b);
  if (ecosystem === "PyPI") {
    if (!pep440.valid(a) || !pep440.valid(b)) return null;
    return pep440.compare(a, b);
  }
  const av = semver.valid(a),
    bv = semver.valid(b);
  return av && bv ? semver.compare(av, bv) : null;
}
export function supportedVersion(c: Component): boolean {
  return (
    !!c.version &&
    !!c.ecosystem &&
    compare(c.version, c.version, c.ecosystem) !== null
  );
}
export function matchRecord(c: Component, r: OsvRecord): Match {
  if (r.withdrawn) return "not-affected";
  if (!c.version || !c.ecosystem) return "unknown";
  let unknown = false;
  for (const a of r.affected) {
    if (!samePackage(c, a.package)) continue;
    if (
      a.versions?.some(
        (v) => v === c.version || compare(v, c.version!, c.ecosystem!) === 0,
      )
    )
      return "affected";
    for (const range of a.ranges || []) {
      if (!["SEMVER", "ECOSYSTEM"].includes(range.type)) {
        if (
          !(a.ranges || []).some((x) =>
            ["SEMVER", "ECOSYSTEM"].includes(x.type),
          )
        )
          unknown = true;
        continue;
      }
      let active = false,
        uncertain = false;
      for (const e of range.events) {
        if (e.introduced !== undefined) {
          const n =
            e.introduced === "0"
              ? 1
              : compare(c.version, e.introduced, c.ecosystem);
          if (n === null) {
            uncertain = true;
          } else active = n >= 0;
        } else {
          const end = e.fixed ?? e.limit ?? e.last_affected;
          if (end === undefined) {
            uncertain = true;
            continue;
          }
          const n = compare(c.version, end, c.ecosystem);
          if (n === null) {
            uncertain = true;
            continue;
          }
          if (active && (e.last_affected !== undefined ? n <= 0 : n < 0))
            return uncertain ? "unknown" : "affected";
          active = false;
        }
      }
      if (active && !uncertain) return "affected";
      if (uncertain) unknown = true;
    }
    if (!a.versions?.length && !a.ranges?.length) unknown = true;
  }
  return unknown ? "unknown" : "not-affected";
}
