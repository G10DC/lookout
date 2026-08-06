---
name: lookout
description: >-
  Audits declared dependencies for known vulnerabilities and license compliance
  issues -- validates node_modules or equivalent against security advisories and
  license policy before a build ships. Use when checking if a package has known
  CVEs or verifying license compatibility before release. Never review
  application source code logic -- use mirror instead; never actively probe a
  live target -- use siege instead.
---

# lookout

A secure codebase built on a vulnerable dependency is still vulnerable. One rule above all:
**gate the build on the dependency tree, not just on the code you wrote.**

## Golden rules

1. **Scope is the dependency tree, not application code.** Lookout reads manifests
   (`package.json`/lockfiles) and advisory databases — it never inspects the application's own
   logic or diff.
2. **License checks are a hard gate, same as security.** An incompatible license blocks the same
   way a critical CVE does — license risk is not a lower tier of finding.
3. **Transitive dependencies count.** A vulnerability three levels deep in the tree is still a
   finding; scope includes the full resolved tree, not just direct dependencies.
4. **Advisory data must be current, not cached indefinitely.** Stale advisory data produces false
   negatives — refresh before a release-gating run, not just on a schedule.
5. **A finding here is a build gate, not a suggestion.** Structural breakage in dependency health
   should block release the same way `trellis`'s `BLOCK` verdict blocks a merge.

## When to use

<<<<<<< HEAD
- Checking a package or its transitive dependencies for known CVEs before release.
- Verifying license compatibility across the full dependency tree.
- Gating a build on dependency health as part of a verify/release phase.

## When NOT to use

- **The concern is this diff's own logic or injection risk, not a third-party package** →
  use `mirror`. Lookout never reads application code.
- **The goal is to actively probe or exploit a live target, not audit static manifests** →
  use `siege`. Lookout is passive and manifest-scoped; it never touches running services.
=======
Audit package manifest in current directory:
```bash
node lib/lookout.js --manifest "package.json"
```


---

## ⚡ Spark Breakthrough Enhancement

- **Feature**: **Real-Time Vulnerability Egress Guard**
- **Description**: Blocks risky AGPL licenses and compromised package manifests pre-commit.
- **Synergy**: Integrated with `sentinel` (firewall) & `shipwright` (git publisher).
- **Framework**: Applied via the `spark` 4-Lens Lateral Ideation Engine.
>>>>>>> 4b7eb2f (feat(spark): integrate spark breakthrough enhancements into lookout)
