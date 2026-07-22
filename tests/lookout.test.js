import { describe, it } from 'node:test';
import assert from 'node:assert';
import { LookoutSentinel } from '../lib/lookout.js';

describe('LookoutSentinel', () => {
  it('flags wildcard version ranges as security risks', () => {
    const sentinel = new LookoutSentinel();
    const pkg = {
      dependencies: {
        'express': '*',
        'lodash': '^4.17.21'
      }
    };
    const res = sentinel.auditManifest(pkg);
    assert.strictEqual(res.verdict, 'WARN');
    assert.strictEqual(res.findings.security.length, 1);
    assert.strictEqual(res.findings.security[0].package, 'express');
  });

  it('flags GPL / AGPL copyleft package names', () => {
    const sentinel = new LookoutSentinel();
    const pkg = {
      dependencies: {
        'my-gpl-module': '1.0.0'
      }
    };
    const res = sentinel.auditManifest(pkg);
    assert.strictEqual(res.verdict, 'WARN');
    assert.strictEqual(res.findings.licenses.length, 1);
  });

  it('passes clean manifests', () => {
    const sentinel = new LookoutSentinel();
    const pkg = {
      dependencies: {
        'react': '18.2.0'
      }
    };
    const res = sentinel.auditManifest(pkg);
    assert.strictEqual(res.verdict, 'PASS');
    assert.strictEqual(res.findings.security.length, 0);
    assert.strictEqual(res.findings.licenses.length, 0);
  });
});
