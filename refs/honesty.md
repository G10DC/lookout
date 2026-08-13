# Lookout Dependency Security Audit Honesty Bounds

The honesty layer is the operational expression of the **G10DC Trellis Standard**: **the LLM reasons over verified evidence with stated confidence, never hallucinates capabilities or impact.**

## Domain & Scope
**Domain**: CVE & License Compliance Auditing

## Core Epistemic Rules

1. **Advisory Recency: Audit checks against known CVE database snapshots. Zero-day vulnerabilities are outside scope.**
2. **License Scope: Validates package manifest licenses (MIT, Apache, GPL, BSD). Does NOT audit custom source header clauses.**
3. **Confidence Rating: High (audit against verified CVE index), Medium (missing transitive advisories), Low (unindexed packages).**

## Three-Tier Confidence Model

- **High Confidence**: Full AST/schema validation passing, deterministic evidence available, verified state.
- **Medium Confidence**: Heuristic analysis or partial indexing; requires agent verification step.
- **Low Confidence**: Inferred or unindexed target; candidate output ONLY, never auto-committed.

## Epistemic Invariant

> Absence of evidence is not evidence of absence. Output is presented as a structured candidate set with confidence scores so caveats cannot be silently dropped downstream.
