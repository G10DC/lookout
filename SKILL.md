---
name: lookout
status: implemented
description: >-
  Manifest-level dependency policy check: flags a banned licence declared in
  package.json and dependencies pinned to a git+ or http:// URL instead of a
  registry version. Consults NO advisory database and reads no lockfile or
  node_modules, so it cannot tell you whether a package has a known CVE, and it
  does not see transitive or dependency licences -- only the manifest's own.
  Use as a cheap pre-build policy gate. Never treat a PASS as evidence the
  dependency tree was audited -- run a real advisory scanner for that; never
  review application source code logic -- use mirror; never probe a live target
  -- use siege.
---

# lookout

A secure codebase built on a vulnerable dependency is still vulnerable. One rule above all:
**gate the build on the dependency tree, not just on the code you wrote.**

## Golden rules

1. **Scope is the dependency tree, not application code.** Reads `package.json` off disk directly
   — never the app's own logic or diff.
2. **License checks are a hard gate, same as security.** A banned license blocks the same way a
   critical CVE would.
3. **A finding here is a build gate, not a suggestion.** `verdict: BLOCK` should block release the
   same way `trellis`'s `BLOCK` blocks a merge.

## Honest scope

A **manifest-shape linter, not a CVE scanner**. Two local checks only: is the declared `license`
in a banned set (default `GPL-3.0`, `AGPL-3.0`)? Does any dependency point at an unpinned `git+`
or `http://` URL? **It queries no advisory database** (npm audit, OSV, GitHub Advisories) and has
no notion of a CVE; it reads only the direct `dependencies`/`devDependencies` of the one manifest
you point it at, not the resolved transitive tree. Pair with `npm audit`/`pip-audit` for real CVE
coverage — lookout only adds the license gate and unpinned-source check those tools skip.

## When to use

- Checking a `package.json`'s license against policy, or flagging unpinned git/http dependency
  sources, as one gate among several — not your only dependency security check.

## When NOT to use

- **Actual CVE/vulnerability data** → lookout has none; pair with `npm audit` or equivalent.
- **This diff's own logic, not a third-party package** → use `mirror`.
- **Probing or exploiting a live target** → use `siege`; lookout is passive and manifest-scoped.

## Usage (library, not a CLI)

```js
import { LookoutAuditor } from './lib/lookout.js';

const auditor = new LookoutAuditor({ bannedLicenses: ['GPL-3.0', 'AGPL-3.0'] });
const result = auditor.auditPackageJson('/path/to/package.json');
// result.verdict: 'PASS' | 'WARN' | 'BLOCK'
// result.findings: [{ type: 'license'|'security', severity, package, message }, ...]
```
