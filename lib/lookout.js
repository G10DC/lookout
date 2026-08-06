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
   * Audits a package.json manifest for vulnerable dependencies or banned licenses.
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
      honest: 'Audit bound: checks package manifest licenses and URL pins against policy.'
    };
  }
}
