/** CVSS v4.0 scoring per FIRST's specification, using its published MacroVector tables. */
import { readFileSync } from "node:fs";
const METRICS: Record<string, string[]> = {
  AV: ["N", "A", "L", "P"],
  AC: ["L", "H"],
  AT: ["N", "P"],
  PR: ["N", "L", "H"],
  UI: ["N", "P", "A"],
  VC: ["H", "L", "N"],
  VI: ["H", "L", "N"],
  VA: ["H", "L", "N"],
  SC: ["H", "L", "N"],
  SI: ["H", "L", "N"],
  SA: ["H", "L", "N"],
  E: ["X", "A", "P", "U"],
  CR: ["X", "H", "M", "L"],
  IR: ["X", "H", "M", "L"],
  AR: ["X", "H", "M", "L"],
  MAV: ["X", "N", "A", "L", "P"],
  MAC: ["X", "L", "H"],
  MAT: ["X", "N", "P"],
  MPR: ["X", "N", "L", "H"],
  MUI: ["X", "N", "P", "A"],
  MVC: ["X", "H", "L", "N"],
  MVI: ["X", "H", "L", "N"],
  MVA: ["X", "H", "L", "N"],
  MSC: ["X", "H", "L", "N"],
  MSI: ["X", "S", "H", "L", "N"],
  MSA: ["X", "S", "H", "L", "N"],
  S: ["X", "N", "P"],
  AU: ["X", "N", "Y"],
  R: ["X", "A", "U", "I"],
  V: ["X", "D", "C"],
  RE: ["X", "L", "M", "H"],
  U: ["X", "Clear", "Green", "Amber", "Red"],
};
const ORDER = Object.keys(METRICS);
const BASE = ORDER.slice(0, 11);
const LEVELS: Record<string, Record<string, number>> = {
  AV: { N: 0, A: 0.1, L: 0.2, P: 0.3 },
  PR: { N: 0, L: 0.1, H: 0.2 },
  UI: { N: 0, P: 0.1, A: 0.2 },
  AC: { L: 0, H: 0.1 },
  AT: { N: 0, P: 0.1 },
  VC: { H: 0, L: 0.1, N: 0.2 },
  VI: { H: 0, L: 0.1, N: 0.2 },
  VA: { H: 0, L: 0.1, N: 0.2 },
  SC: { H: 0.1, L: 0.2, N: 0.3 },
  SI: { S: 0, H: 0.1, L: 0.2, N: 0.3 },
  SA: { S: 0, H: 0.1, L: 0.2, N: 0.3 },
  CR: { H: 0, M: 0.1, L: 0.2 },
  IR: { H: 0, M: 0.1, L: 0.2 },
  AR: { H: 0, M: 0.1, L: 0.2 },
};
interface Tables {
  lookup: Record<string, number>;
  maxComposed: {
    eq1: Record<string, string[]>;
    eq2: Record<string, string[]>;
    eq3: Record<string, Record<string, string[]>>;
    eq4: Record<string, string[]>;
    eq5: Record<string, string[]>;
  };
  maxSeverity: {
    eq1: Record<string, number>;
    eq2: Record<string, number>;
    eq3eq6: Record<string, Record<string, number>>;
    eq4: Record<string, number>;
  };
}
let tables: Tables | undefined;
function load(): Tables {
  tables ??= JSON.parse(
    readFileSync(
      new URL("../schemas/cvss-v4-data.json", import.meta.url),
      "utf8",
    ),
  ) as Tables;
  return tables;
}
function parse(vector: unknown): Record<string, string> | undefined {
  if (typeof vector !== "string" || !vector.startsWith("CVSS:4.0/"))
    return undefined;
  const metrics: Record<string, string> = {};
  let position = -1;
  for (const token of vector.split("/").slice(1)) {
    const pair = token.split(":");
    const index = ORDER.indexOf(pair[0]);
    if (
      pair.length !== 2 ||
      index <= position ||
      !METRICS[pair[0]].includes(pair[1])
    )
      return undefined;
    position = index;
    metrics[pair[0]] = pair[1];
  }
  return BASE.every((key) => Object.hasOwn(metrics, key)) ? metrics : undefined;
}
/** Effective value: threat and requirement metrics default to worst case; modified metrics override base. */
function effective(metrics: Record<string, string>, key: string): string {
  const selected = metrics[key] ?? "X";
  if (key === "E" && selected === "X") return "A";
  if (["CR", "IR", "AR"].includes(key) && selected === "X") return "H";
  const modified = metrics[`M${key}`];
  return modified !== undefined && modified !== "X" ? modified : selected;
}
function macroVector(get: (key: string) => string): number[] {
  const [av, pr, ui] = [get("AV"), get("PR"), get("UI")];
  const eq1 =
    av === "N" && pr === "N" && ui === "N"
      ? 0
      : (av === "N" || pr === "N" || ui === "N") && av !== "P"
        ? 1
        : 2;
  const eq2 = get("AC") === "L" && get("AT") === "N" ? 0 : 1;
  const [vc, vi, va] = [get("VC"), get("VI"), get("VA")];
  const eq3 =
    vc === "H" && vi === "H"
      ? 0
      : vc === "H" || vi === "H" || va === "H"
        ? 1
        : 2;
  const eq4 =
    get("MSI") === "S" || get("MSA") === "S"
      ? 0
      : get("SC") === "H" || get("SI") === "H" || get("SA") === "H"
        ? 1
        : 2;
  const eq5 = { A: 0, P: 1, U: 2 }[get("E")] as number;
  const eq6 =
    (get("CR") === "H" && vc === "H") ||
    (get("IR") === "H" && vi === "H") ||
    (get("AR") === "H" && va === "H")
      ? 0
      : 1;
  return [eq1, eq2, eq3, eq4, eq5, eq6];
}
/** Returns the score, or undefined when the vector is not a valid CVSS v4.0 vector. */
export function cvss4Score(vector: unknown): number | undefined {
  const metrics = parse(vector);
  if (!metrics) return undefined;
  const get = (key: string) => effective(metrics, key);
  if (["VC", "VI", "VA", "SC", "SI", "SA"].every((key) => get(key) === "N"))
    return 0;
  const { lookup, maxComposed, maxSeverity } = load();
  const [eq1, eq2, eq3, eq4, eq5, eq6] = macroVector(get);
  const at = (...parts: number[]) => lookup[parts.join("")];
  const value = at(eq1, eq2, eq3, eq4, eq5, eq6);
  const lowerEq3Eq6 = (): number | undefined => {
    if (eq3 === 0 && eq6 === 0) {
      const left = at(eq1, eq2, eq3, eq4, eq5, eq6 + 1);
      const right = at(eq1, eq2, eq3 + 1, eq4, eq5, eq6);
      return left !== undefined && right !== undefined && left > right
        ? left
        : right;
    }
    if (eq3 === 1 && eq6 === 0) return at(eq1, eq2, eq3, eq4, eq5, eq6 + 1);
    if (eq3 === 2) return undefined;
    return at(eq1, eq2, eq3 + 1, eq4, eq5, eq6);
  };
  const lower = [
    at(eq1 + 1, eq2, eq3, eq4, eq5, eq6),
    at(eq1, eq2 + 1, eq3, eq4, eq5, eq6),
    lowerEq3Eq6(),
    at(eq1, eq2, eq3, eq4 + 1, eq5, eq6),
    at(eq1, eq2, eq3, eq4, eq5 + 1, eq6),
  ];
  const keys = Object.keys(LEVELS);
  const distance: Record<string, number> = {};
  // The first highest-severity vector that is not below the scored vector sets the distances.
  search: for (const a of maxComposed.eq1[eq1])
    for (const b of maxComposed.eq2[eq2])
      for (const c of maxComposed.eq3[eq3][eq6])
        for (const d of maxComposed.eq4[eq4])
          for (const e of maxComposed.eq5[eq5]) {
            const highest = Object.fromEntries(
              (a + b + c + d + e)
                .split("/")
                .filter(Boolean)
                .map((token) => token.split(":")),
            );
            for (const key of keys)
              distance[key] = LEVELS[key][get(key)] - LEVELS[key][highest[key]];
            if (keys.every((key) => distance[key] >= 0)) break search;
          }
  const step = 0.1;
  const current = [
    distance.AV + distance.PR + distance.UI,
    distance.AC + distance.AT,
    distance.VC +
      distance.VI +
      distance.VA +
      distance.CR +
      distance.IR +
      distance.AR,
    distance.SC + distance.SI + distance.SA,
    0,
  ];
  const depth = [
    maxSeverity.eq1[eq1] * step,
    maxSeverity.eq2[eq2] * step,
    maxSeverity.eq3eq6[eq3][eq6] * step,
    maxSeverity.eq4[eq4] * step,
    1,
  ];
  let total = 0;
  let existing = 0;
  lower.forEach((score, index) => {
    if (score === undefined) return;
    existing += 1;
    total += (value - score) * (current[index] / depth[index]);
  });
  const result = Math.min(
    Math.max(value - (existing ? total / existing : 0), 0),
    10,
  );
  return Math.floor(result * 10 + 0.5) / 10;
}
