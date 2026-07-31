---
name: lookout
description: Dependency security and license audit sentinel. Audits package manifests (package.json, requirements.txt) for risky licenses (GPL/AGPL), deprecated packages, and supply chain security risks.
---

# 🔭 Lookout

Dependency Security & License Audit Sentinel. Lookout inspects project manifests (`package.json`, `package-lock.json`, `requirements.txt`) to audit third-party dependencies for license compliance and security risks.

## 🎯 Features

1. **License Audit**: Identifies copyleft licenses (GPL, AGPL) that may require open-sourcing proprietary code.
2. **Deprecation & Risk Scan**: Flags wildcard dependencies (`"*"`, `">0.0.1"`), unpinned Git URLs, and known risky packages.
3. **Audit Report**: Generates a PASS/WARN/FAIL compliance report.

## 🚀 Execution Guide

Audit package manifest in current directory:
```bash
node C:/Users/GdC/.gemini/config/skills/lookout/lib/lookout.js --manifest "package.json"
```

## When NOT to use
- **Evaluating codebase style, quality, or static code issues**: For static code review of your own JavaScript/Python files before commit → use `mirror` instead.
- **Active network/server pentesting**: For active host scanning and service exploitation → use `siege` instead.
