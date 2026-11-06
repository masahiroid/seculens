/** Customer-context prioritization. Severity is never changed; every adjustment records its assertion. */
import type {
  Component,
  Finding,
  PolicyContext,
  Priority,
  PriorityFactor,
  PriorityLevel,
  SeverityLevel,
} from "./types.js";
const EFFECTS: Record<string, Record<string, number>> = {
  exposure: { internet: 1, internal: 0, isolated: -1 },
  reachability: { reachable: 1, unknown: 0, "not-reachable": -1 },
  criticality: { high: 1, medium: 0, low: -1 },
};
const FACTORS = Object.keys(EFFECTS);
// Unrated advisories rank with High until reviewed, so missing metadata never lowers urgency.
const BASELINE: Record<SeverityLevel, number> = {
  critical: 1,
  high: 2,
  medium: 3,
  low: 4,
  none: 4,
  unknown: 2,
};
const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const isText = (value: unknown): value is string =>
  typeof value === "string" && value.trim() !== "";
function validateEntry(entry: unknown, path: string, identity: string[]): void {
  if (!isObject(entry)) throw new Error(`Policy ${path} must be an object`);
  for (const key of Object.keys(entry))
    if (![...FACTORS, "justification", ...identity].includes(key))
      throw new Error(`Policy ${path} has unknown key ${key}`);
  const stated = FACTORS.filter((factor) => entry[factor] !== undefined);
  if (!stated.length)
    throw new Error(`Policy ${path} must state at least one factor`);
  for (const factor of stated)
    if (!Object.keys(EFFECTS[factor]).includes(entry[factor] as string))
      throw new Error(`Policy ${path}.${factor} has an unsupported value`);
  if (!isText(entry.justification))
    throw new Error(`Policy ${path}.justification is required`);
}
export function validateContext(context: unknown): PolicyContext {
  if (!isObject(context)) throw new Error("Policy context must be an object");
  for (const key of Object.keys(context))
    if (!["defaults", "components"].includes(key))
      throw new Error(`Policy context has unknown key ${key}`);
  if (context.defaults !== undefined)
    validateEntry(context.defaults, "context.defaults", []);
  if (context.components !== undefined) {
    if (!Array.isArray(context.components))
      throw new Error("Policy context.components must be an array");
    context.components.forEach((entry, index) => {
      const path = `context.components[${index}]`;
      validateEntry(entry, path, ["name", "ecosystem"]);
      if (!isText(entry.name))
        throw new Error(`Policy ${path}.name is required`);
      if (
        entry.ecosystem !== undefined &&
        !["npm", "PyPI", "Packagist"].includes(entry.ecosystem)
      )
        throw new Error(`Policy ${path}.ecosystem is not supported`);
    });
  }
  return context as PolicyContext;
}
export function componentPriority(
  level: SeverityLevel,
  component: Pick<Component, "name" | "ecosystem"> | undefined,
  context: PolicyContext,
): Priority {
  const factors: PriorityFactor[] = [];
  for (const factor of FACTORS) {
    const index = (context.components || []).findIndex(
      (entry) =>
        entry[factor as keyof typeof entry] !== undefined &&
        entry.name === component?.name &&
        (entry.ecosystem === undefined ||
          entry.ecosystem === component?.ecosystem),
    );
    const entry = index >= 0 ? context.components![index] : context.defaults;
    const value = entry?.[factor as keyof typeof entry];
    if (entry && value !== undefined)
      factors.push({
        factor: factor as PriorityFactor["factor"],
        value,
        effect: EFFECTS[factor][value],
        source:
          index >= 0 ? `context.components[${index}]` : "context.defaults",
        justification: entry.justification,
      });
  }
  const baseline = BASELINE[level];
  const raised = factors.reduce((sum, factor) => sum + factor.effect, 0);
  // A score of None has no impact to weigh, so context cannot raise it.
  const rank =
    level === "none" ? baseline : Math.min(Math.max(baseline - raised, 1), 4);
  return {
    level: `P${rank}` as PriorityLevel,
    baseline: `P${baseline}` as PriorityLevel,
    factors,
  };
}
export function applyPriorities(
  findings: Finding[],
  components: Component[],
  context: PolicyContext,
): void {
  for (const finding of findings)
    if (finding.category === "vulnerability")
      finding.priority = componentPriority(
        finding.severity?.level || "unknown",
        components.find((c) => c.id === finding.subject),
        context,
      );
}
