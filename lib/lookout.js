/**
 * Lookout — Dependency Security & License Audit Sentinel
 */
import fs from 'node:fs';
import path from 'node:path';

export class LookoutAuditor {
  constructor(options = {}) {
    this.bannedLicenses = new Set(options.bannedLicenses || ['GPL-3.0', 'AGPL-3.0']);
  }

  /**
   * Audits a package.json MANIFEST against policy.
   *
   * What this actually reads is the manifest, and only the manifest: the declared
   * licence of the package itself, and the version specifier of each declared
   * dependency. It consults no advisory database, opens no lockfile and does not look
   * inside node_modules.
   *
   * That matters because the verdict feeds an aggregate. A `PASS` here used to be
   * indistinguishable from "the dependency tree was audited and is clean", and pulse
   * scored it as 10/10 for dependency security on a project whose dependencies had
   * never been examined at all. The `unknowns` field states what was not looked at, so
   * a caller can tell an absent finding from an absent check.
   */
  auditPackageJson(packageJsonPath) {
    if (!fs.existsSync(packageJsonPath)) {
      throw new Error(`Package manifest not found at: ${packageJsonPath}`);
    }

    const content = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
    const dependencies = { ...(content.dependencies || {}), ...(content.devDependencies || {}) };
    const findings = [];

    // License check
    if (content.license && this.bannedLicenses.has(content.license)) {
      findings.push({
        type: 'license',
        severity: 'HIGH',
        package: content.name || 'root',
        message: `Banned license '${content.license}' declared in manifest.`
      });
    }

    // Dependency analysis
    for (const [dep, version] of Object.entries(dependencies)) {
      if (typeof version === 'string' && (version.includes('git+') || version.includes('http://'))) {
        findings.push({
          type: 'security',
          severity: 'MEDIUM',
          package: dep,
          message: `Dependency '${dep}' fetched from unpinned remote URL '${version}'.`
        });
      }
    }

    const highCount = findings.filter(f => f.severity === 'HIGH').length;
    const verdict = highCount > 0 ? 'BLOCK' : (findings.length > 0 ? 'WARN' : 'PASS');

    return {
      verdict,
      dependencyCount: Object.keys(dependencies).length,
      findings,
      // Never empty: these are not conditional gaps, they are the permanent boundary of
      // a manifest-only check. Anything aggregating this verdict has to be able to see
      // that boundary, or it will report a dependency tree as clean on the strength of
      // a check that never opened it.
      unknowns: [
        'known vulnerabilities: no advisory database is consulted',
        'transitive dependencies: no lockfile or node_modules is read',
        'dependency licences: only the manifest\'s own licence is checked'
      ],
      honest: 'Audit bound: manifest licence and dependency URL pins against policy. Not an advisory scan.'
    };
  }
}
