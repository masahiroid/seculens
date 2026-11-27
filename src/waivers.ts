/** Waivers: recorded, expiring customer decisions. Waived findings stay in the report. */
import type { Finding, Waiver, WaiverFile } from "./types.js";
const KEYS = ["ruleId", "subject", "justification", "approvedBy", "expires"];
const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const isText = (value: unknown): value is string =>
  typeof value === "string" && value.trim() !== "";
export function isCalendarDate(value: unknown): value is string {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value))
    return false;
  const [year, month, day] = value.split("-").map(Number);
  const date = new Date(Date.UTC(year, month - 1, day));
  return (
    date.getUTCFullYear() === year &&
    date.getUTCMonth() === month - 1 &&
    date.getUTCDate() === day
  );
}
export function validateWaivers(input: unknown): WaiverFile {
  if (!isObject(input)) throw new Error("Waiver file must be an object");
  for (const key of Object.keys(input))
    if (!["schemaVersion", "waivers"].includes(key))
      throw new Error(`Waiver file has unknown key ${key}`);
  if (input.schemaVersion !== "1.0")
    throw new Error("Waiver file schemaVersion must be 1.0");
  if (!Array.isArray(input.waivers))
    throw new Error("Waiver file waivers must be an array");
  input.waivers.forEach((entry: unknown, index: number) => {
    const path = `waivers[${index}]`;
    if (!isObject(entry)) throw new Error(`Waiver ${path} must be an object`);
    for (const key of Object.keys(entry))
      if (!KEYS.includes(key))
        throw new Error(`Waiver ${path} has unknown key ${key}`);
    for (const key of ["ruleId", "justification", "approvedBy"])
      if (!isText(entry[key]))
        throw new Error(`Waiver ${path}.${key} is required`);
    if (entry.subject !== undefined && !isText(entry.subject))
      throw new Error(`Waiver ${path}.subject must be a non-empty string`);
    if (!isCalendarDate(entry.expires))
      throw new Error(`Waiver ${path}.expires must be a YYYY-MM-DD date`);
  });
  return input as unknown as WaiverFile;
}
const describe = (w: Waiver) =>
  `${w.ruleId}${w.subject !== undefined ? ` on ${w.subject}` : ""}`;
const matches = (w: Waiver, f: Finding) =>
  (w.ruleId === f.ruleId || (f.aliases || []).includes(w.ruleId)) &&
  (w.subject === undefined || w.subject === f.subject);
/**
 * Annotates findings covered by an active waiver (expires on or after `date`, YYYY-MM-DD)
 * and appends a review finding for each waiver that expired or matched nothing.
 */
export function applyWaivers(
  findings: Finding[],
  waivers: Waiver[],
  date: string,
): Finding[] {
  if (!isCalendarDate(date)) throw new Error("Waiver date must be YYYY-MM-DD");
  const used = new Set<number>();
  const expired = new Set<number>();
  const result = findings.map((finding) => {
    const indexes = waivers
      .map((w, i) => (matches(w, finding) ? i : -1))
      .filter((i) => i >= 0);
    indexes.forEach((i) => used.add(i));
    const active = indexes.find((i) => waivers[i].expires >= date);
    indexes
      .filter((i) => waivers[i].expires < date)
      .forEach((i) => expired.add(i));
    if (active === undefined) return finding;
    const w = waivers[active];
    return {
      ...finding,
      waiver: {
        source: `waivers[${active}]`,
        justification: w.justification,
        approvedBy: w.approvedBy,
        expires: w.expires,
      },
    };
  });
  waivers.forEach((w, i) => {
    if (expired.has(i))
      result.push({
        category: "quality",
        ruleId: "WAIVER-EXPIRED",
        subject: `waivers[${i}]`,
        status: "review",
        summary: "Waiver expired",
        evidence: `${describe(w)} expired ${w.expires}; approved by ${w.approvedBy}`,
        recommendation:
          "Remediate the finding or renew the waiver after a new review.",
      });
    else if (!used.has(i))
      result.push({
        category: "quality",
        ruleId: "WAIVER-UNMATCHED",
        subject: `waivers[${i}]`,
        status: "review",
        summary: "Waiver matched no finding",
        evidence: `${describe(w)}; expires ${w.expires}`,
        recommendation: "Remove the waiver, or correct its ruleId or subject.",
      });
  });
  return result;
}
/** Findings that count toward exit codes: everything without an active waiver. */
export const unwaived = (findings: Finding[]) =>
  findings.filter((f) => f.waiver === undefined);
