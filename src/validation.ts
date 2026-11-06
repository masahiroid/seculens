import { readFileSync } from "node:fs";
import { Ajv, type ValidateFunction } from "ajv";
import addFormats from "ajv-formats";
import addInternationalFormats from "ajv-formats-draft2019";

export interface ValidationResult {
  valid: boolean;
  schema: string;
  errors: { path: string; message: string }[];
}
const cache = new Map<string, ValidateFunction>();
function validator(name: string): ValidateFunction {
  const previous = cache.get(name);
  if (previous) return previous;
  const ajv = new Ajv({
    strict: false,
    allErrors: false,
    validateFormats: true,
  });
  (addFormats as unknown as (ajv: Ajv) => void)(ajv);
  addInternationalFormats(ajv);
  const load = (file: string) =>
    JSON.parse(
      readFileSync(new URL(`../schemas/${file}`, import.meta.url), "utf8"),
    );
  for (const file of [
    "spdx.schema.json",
    "jsf-0.82.schema.json",
    "cryptography-defs.schema.json",
  ])
    ajv.addSchema(load(file));
  const compiled = ajv.compile(load(name));
  cache.set(name, compiled);
  return compiled;
}
export function validateDocument(
  input: unknown,
  kind: "sbom" | "report" = "sbom",
): ValidationResult {
  let schema: string;
  if (kind === "report")
    schema =
      (input as { schemaVersion?: unknown } | null)?.schemaVersion === "1.1"
        ? "report-1.1.schema.json"
        : "report-1.2.schema.json";
  else if (kind !== "sbom") throw new Error("Kind must be sbom or report");
  else {
    const d = input as Record<string, unknown> | null;
    if (
      d &&
      typeof d === "object" &&
      !Array.isArray(d) &&
      d.bomFormat === "CycloneDX" &&
      ["1.4", "1.5", "1.6", "1.7"].includes(String(d.specVersion))
    )
      schema = `bom-${d.specVersion}.schema.json`;
    else if (
      d &&
      typeof d === "object" &&
      !Array.isArray(d) &&
      ["SPDX-2.2", "SPDX-2.3"].includes(String(d.spdxVersion))
    )
      schema = `spdx-${String(d.spdxVersion).slice(5)}.schema.json`;
    else
      return {
        valid: false,
        schema: "",
        errors: [
          { path: "", message: "Expected supported SPDX or CycloneDX version" },
        ],
      };
  }
  const check = validator(schema);
  const valid = Boolean(check(input));
  return {
    valid,
    schema,
    errors: (check.errors || []).map((e) => ({
      path: e.instancePath,
      message: e.message || e.keyword,
    })),
  };
}
