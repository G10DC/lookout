import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
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

// The verdict feeds an aggregate. A PASS used to be indistinguishable from "the
// dependency tree was audited and is clean", and pulse scored it as 10/10 for dependency
// security on a project whose dependencies had never been examined.
test('the audit states what it did not look at', () => {
  const auditor = new LookoutAuditor();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lookout-unknowns-'));
  const manifest = path.join(dir, 'package.json');

  fs.writeFileSync(manifest, JSON.stringify({
    name: 'clean', version: '1.0.0', license: 'MIT',
    dependencies: { 'event-stream': '3.3.6', lodash: '4.17.11' }
  }));

  const result = auditor.auditPackageJson(manifest);
  assert.equal(result.verdict, 'PASS');
  assert.equal(result.dependencyCount, 2);
  assert.ok(Array.isArray(result.unknowns) && result.unknowns.length > 0,
    'a PASS with no stated boundary reads as a clean dependency tree');
  assert.ok(result.unknowns.some((u) => /advisory/i.test(u)),
    'the absence of an advisory scan is the one a caller most needs told');
  assert.doesNotMatch(result.honest, /advisor(y|ies) scan\b(?! *\.)/i);
});
