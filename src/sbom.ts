import { PackageURL } from "packageurl-js";
import type { Component, Sbom } from "./types.js";
function identity(purl?: string): Partial<Component> {
  if (!purl) return {};
  try {
    const p = PackageURL.fromString(purl);
    const ecosystem = (
      { npm: "npm", pypi: "PyPI", composer: "Packagist" } as const
    )[p.type as "npm"];
    return {
      ecosystem,
      name: p.namespace ? `${p.namespace}/${p.name}` : p.name,
      version: p.version || undefined,
    };
  } catch {
    return {};
  }
}
function text(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}
export function parseSbom(input: unknown): Sbom {
  if (!input || typeof input !== "object")
    throw new Error("SBOM must be a JSON object");
  const d = input as any;
  let components: Component[] = [];
  let format: Sbom["format"];
  let version: string;
  const dependencies: Sbom["dependencies"] = [];
  const warnings: string[] = [];
  if (d.bomFormat === "CycloneDX") {
    format = "CycloneDX";
    version = d.specVersion;
    if (!["1.4", "1.5", "1.6", "1.7"].includes(version))
      throw new Error(`Unsupported CycloneDX version: ${version}`);
    if (d.components !== undefined && !Array.isArray(d.components))
      throw new Error("CycloneDX components must be an array");
    const collect = (list: any[], prefix: string) =>
      list.forEach((c, i) => {
        if (!text(c.name)) throw new Error("Component name is required");
        const purl = text(c.purl) ? c.purl : undefined;
        const known = identity(purl);
        const hashes = Array.isArray(c.hashes)
          ? c.hashes
              .filter((h: any) => text(h.alg) && text(h.content))
              .map((h: any) => ({ alg: String(h.alg), content: String(h.content) }))
          : undefined;
        components.push({
          id: c["bom-ref"] || `${prefix}${i}`,
          name: c.group ? `${c.group}/${c.name}` : c.name,
          version: text(c.version) ? c.version : undefined,
          purl,
          ...known,
          licenses: (c.licenses || [])
            .map((l: any) => l.expression || l.license?.id || l.license?.name)
            .filter(text),
          hashes,
        });
        if (Array.isArray(c.components))
          collect(c.components, `${prefix}${i}/`);
      });
    collect(d.components || [], "component-");
    for (const e of d.dependencies || [])
      for (const to of e.dependsOn || [])
        dependencies.push({ from: e.ref, to });
  } else if (text(d.spdxVersion)) {
    format = "SPDX";
    version = d.spdxVersion;
    if (!["SPDX-2.2", "SPDX-2.3"].includes(version))
      throw new Error(
        `Unsupported SPDX version: ${version}. SPDX 3 is not supported yet.`,
      );
    if (!Array.isArray(d.packages))
      throw new Error("SPDX packages must be an array");
    components = d.packages.map((p: any, i: number) => {
      if (!text(p.name)) throw new Error("Package name is required");
      const purl = p.externalRefs?.find(
        (r: any) => r.referenceType === "purl",
      )?.referenceLocator;
      const licenses = [
        p.licenseConcluded && p.licenseConcluded !== "NOASSERTION"
          ? p.licenseConcluded
          : p.licenseDeclared,
      ].filter(text);
      const hashes = Array.isArray(p.checksums)
        ? p.checksums
            .filter((cs: any) => text(cs.algorithm) && text(cs.checksumValue))
            .map((cs: any) => ({
              alg: String(cs.algorithm),
              content: String(cs.checksumValue),
            }))
        : undefined;
      return {
        id: p.SPDXID || `package-${i}`,
        name: p.name,
        version: text(p.versionInfo) ? p.versionInfo : undefined,
        purl,
        ...identity(purl),
        licenses,
        hashes,
      };
    });
    for (const e of d.relationships || []) {
      if (e.relationshipType === "DEPENDS_ON")
        dependencies.push({ from: e.spdxElementId, to: e.relatedSpdxElement });
      if (e.relationshipType === "DEPENDENCY_OF")
        dependencies.push({ from: e.relatedSpdxElement, to: e.spdxElementId });
    }
  } else throw new Error("Expected SPDX JSON or CycloneDX JSON");
  const ids = new Set<string>();
  for (const c of components) {
    if (ids.has(c.id)) throw new Error(`Duplicate component ID: ${c.id}`);
    ids.add(c.id);
    if (c.purl && !identity(c.purl).name)
      warnings.push(`Invalid purl: ${c.id}`);
  }
  for (const e of dependencies)
    if (!ids.has(e.from) || !ids.has(e.to))
      warnings.push(
        `Dependency endpoint not in component list: ${e.from} -> ${e.to}`,
      );
  computeDependencyDepths(components, dependencies);
  return { format, version, components, dependencies, warnings };
}

export function computeDependencyDepths(
  components: Component[],
  dependencies: { from: string; to: string }[],
): void {
  if (dependencies.length === 0) return;
  const adj = new Map<string, string[]>();
  const inDegree = new Map<string, number>();
  for (const c of components) {
    adj.set(c.id, []);
    inDegree.set(c.id, 0);
  }
  for (const dep of dependencies) {
    if (!adj.has(dep.from)) adj.set(dep.from, []);
    adj.get(dep.from)!.push(dep.to);
    inDegree.set(dep.to, (inDegree.get(dep.to) || 0) + 1);
  }

  const roots: string[] = [];
  for (const [id, count] of inDegree.entries()) {
    if (count === 0 && (adj.get(id) || []).length > 0) {
      roots.push(id);
    }
  }

  const depths = new Map<string, number>();
  const queue: { id: string; depth: number }[] = [];
  for (const r of roots) {
    for (const child of adj.get(r) || []) {
      if (!depths.has(child)) {
        depths.set(child, 1);
        queue.push({ id: child, depth: 1 });
      }
    }
  }

  while (queue.length > 0) {
    const { id, depth } = queue.shift()!;
    for (const next of adj.get(id) || []) {
      if (!depths.has(next) || depths.get(next)! > depth + 1) {
        depths.set(next, depth + 1);
        queue.push({ id: next, depth: depth + 1 });
      }
    }
  }

  for (const c of components) {
    c.depth = depths.get(c.id);
  }
}
