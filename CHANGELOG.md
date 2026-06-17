# Changelog


## [1.0.1] — 2026-06-17

### Fixed

- Replaced non-existent `cortex/plugins` import with local `types.ts` containing inline type definitions
- Removed broken `cortex/plugins` import map from `deno.json`
- Fixed test files with complete mock contexts (`state.delete`, `state.list`, `config.get/set/getAll`, `logger`, `host`)
- Rewrote scaffold test files to test actual plugin tools instead of template leftovers
- Added `defaultValue` and `default` fields to `ToolParam` type for compatibility

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-06-15

### Added

- Initial release of cortex-plugin-security-audit
- `audit_dependencies` — Scan project dependencies for known vulnerabilities (npm, pip, cargo,
  gomod, auto-detect)
- `audit_secrets` — Detect hardcoded secrets, API keys, tokens, passwords, private keys, and
  connection strings (30+ patterns across 10+ categories)
- `audit_sast` — Static analysis security testing for SQL injection, XSS, command injection, path
  traversal, SSRF, insecure deserialization, hardcoded crypto
- `audit_owasp` — OWASP Top 10 (2021/2017) compliance checking
- `audit_generate_report` — Comprehensive security audit report generation with severity scoring and
  remediation guidance (markdown, json, html)
- `audit_status` — Check available audit capabilities and configuration
- UI configuration: severity threshold, max file size, exclude directories
- OWASP Top 10 mapping for all findings
- Comprehensive secret detection patterns (API keys, tokens, passwords, private keys, connection
  strings)
