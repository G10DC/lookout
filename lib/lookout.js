import fs from 'fs';
import path from 'path';

/**
 * Lookout Dependency Sentinel Engine
 */
export class LookoutSentinel {
  auditManifest(pkgObj) {
    const findings = {
      licenses: [],
      security: []
    };

    const deps = { ...(pkgObj.dependencies || {}), ...(pkgObj.devDependencies || {}) };

    for (const [name, version] of Object.entries(deps)) {
      // 1. Wildcard / unpinned check
      if (version === '*' || version.startsWith('>')) {
        findings.security.push({ package: name, message: `Unpinned version range '${version}' poses supply-chain update risks.` });
      }
      if (version.includes('github:') || version.includes('git+')) {
        findings.security.push({ package: name, message: `Git dependency '${version}' bypasses npm registry verification.` });
      }

      // 2. Mock License / Package check for known copyleft packages
      if (name.includes('gpl') || name.includes('agpl')) {
        findings.licenses.push({ package: name, message: `Potential Copyleft license restriction detected in package name.` });
      }
    }

    let verdict = 'PASS';
    if (findings.licenses.length > 0) verdict = 'WARN';
    if (findings.security.length > 0 && verdict === 'PASS') verdict = 'WARN';

    return {
      totalDependencies: Object.keys(deps).length,
      verdict,
      findings
    };
  }

  formatReport(result) {
    let out = `# 🔭 Lookout Dependency Audit\n`;
    out += `**Verdict**: ${result.verdict}\n`;
    out += `**Total Dependencies**: ${result.totalDependencies}\n\n`;

    out += `### License Compliance Issues (${result.findings.licenses.length})\n`;
    if (result.findings.licenses.length === 0) out += `- None.\n`;
    else result.findings.licenses.forEach(i => { out += `- \`${i.package}\`: ${i.message}\n`; });

    out += `\n### Security & Pinning Issues (${result.findings.security.length})\n`;
    if (result.findings.security.length === 0) out += `- None.\n`;
    else result.findings.security.forEach(i => { out += `- \`${i.package}\`: ${i.message}\n`; });

    return out;
  }
}

// CLI Handler
if (process.argv[1] && process.argv[1].endsWith('lookout.js')) {
  const args = process.argv.slice(2);
  const sentinel = new LookoutSentinel();
  const mIdx = args.indexOf('--manifest');
  const manifestPath = mIdx !== -1 && args[mIdx + 1] ? path.resolve(args[mIdx + 1]) : path.resolve('package.json');

  if (fs.existsSync(manifestPath)) {
    const content = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    const result = sentinel.auditManifest(content);
    console.log(sentinel.formatReport(result));
  } else {
    console.error(`Manifest file not found: ${manifestPath}`);
  }
}
