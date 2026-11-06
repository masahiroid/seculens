# SecuLens architecture

This is the Node.js/TypeScript implementation. The [Python](https://github.com/masahiroid/seculens-python) and [PHP](https://github.com/masahiroid/seculens-php) implementations run independently and share the report contract and assessment fixtures. They do not depend on a Python runtime or remote assessment service.

## Processing

1. Read an existing SPDX or CycloneDX JSON SBOM, or generate one through npm.
2. Normalize package URLs, identities, licenses and dependency edges.
3. Load an OSV snapshot or explicitly download candidates without a version filter.
4. Match versions locally, preserving unknown coverage.
5. Evaluate license expressions against an explicit customer policy, and rank vulnerabilities when the policy states a `context`.
6. Optionally apply JS/TS AST review rules.
7. Save a versioned JSON result, evidence snapshots and a Word document.

Input and DB hashes bind the report to exact evidence. Matching uses version semantics per ecosystem; it never substitutes string comparison. Advisory alias sets merge duplicates per component. Unsupported inputs remain unassessed. The tool does not execute analyzed source code.

## Cross-language contract

All implementations share `schemas/report-1.2.schema.json`, whose report concepts are: components, dependency edges, checks, findings, database identity, coverage limitations. Use the same advisory fixtures and boundary cases to establish parity. CLI timestamps may differ, but findings should agree for identical inputs, policy and DB snapshots.

## Next releases

- Report templates, reviewer notes, waivers, remediation and baseline diffs.
- Dataflow-based AST rules with documented framework coverage.
- OS package and vendor advisories, and configurable DB providers.
- Schema-aware SPDX 3 and XML adapters.

SecuLens does not claim Trivy feature parity. It focuses on auditable SBOM assessment and reporting.

See the README customer report mode section for severity evidence and layout options.
