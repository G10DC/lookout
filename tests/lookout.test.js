import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import { LookoutAuditor } from '../lib/lookout.js';

test('LookoutAuditor audits package manifest for non-pinned dependencies', () => {
  const auditor = new LookoutAuditor();
  const tmpPath = path.join(process.cwd(), 'temp_pkg.json');
  fs.writeFileSync(tmpPath, JSON.stringify({
    name: "test-app",
    license: "MIT",
    dependencies: {
      "untrusted-pkg": "git+https://github.com/foo/bar.git"
    }
  }));

  try {
    const res = auditor.auditPackageJson(tmpPath);
    assert.equal(res.verdict, 'WARN');
    assert.equal(res.findings[0].package, 'untrusted-pkg');
  } finally {
    if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath);
  }
});
