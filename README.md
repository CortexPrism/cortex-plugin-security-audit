# Security Audit Agent

Automated security scanning for CortexPrism. Detects dependency vulnerabilities,
hardcoded secrets, SAST issues, and OWASP Top 10 violations. Generates detailed
audit reports with remediation guidance.

## Installation

```bash
# From marketplace
cortex plugin install marketplace:cortex-plugin-security-audit

# From GitHub
cortex plugin install github:CortexPrism/cortex-plugin-security-audit

# Local development
cortex plugin install ./manifest.json
```

## Quick Start

```bash
# Check available audit capabilities
cortex tool call audit_status

# Scan dependencies
cortex tool call audit_dependencies --project_path ./my-project --package_manager npm

# Scan for secrets
cortex tool call audit_secrets --target_path ./src

# Run SAST analysis
cortex tool call audit_sast --target_path ./src --language typescript

# OWASP Top 10 compliance check
cortex tool call audit_owasp --target_path ./

# Generate a combined report from findings
cortex tool call audit_generate_report --findings "$(cat findings.json)" --format html
```

## Tools

| Tool                    | Description                                                           | Key Parameters                                      |
| ----------------------- | --------------------------------------------------------------------- | --------------------------------------------------- |
| `audit_dependencies`    | Scan dependencies for known vulnerabilities (npm, pip, cargo, gomod)  | `project_path`*, `package_manager`, `output_format` |
| `audit_secrets`         | Detect hardcoded secrets, keys, tokens, passwords (30+ patterns)      | `target_path`*, `file_patterns`, `exclude_dirs`     |
| `audit_sast`            | Static analysis for SQL injection, XSS, command injection, SSRF, etc. | `target_path` _, `language`_, `rules`               |
| `audit_owasp`           | OWASP Top 10 compliance check (2021/2017)                             | `target_path`*, `year`                              |
| `audit_generate_report` | Generate comprehensive audit report (markdown/json/html)              | `findings`*, `format`, `include_remediation`        |
| `audit_status`          | Check available capabilities and configuration                        | _(none)_                                            |

### audit_dependencies

Scan project dependencies for known vulnerabilities.

**Parameters:**

- `project_path` (string, required) — Path to the project root directory
- `package_manager` (string, optional, default: "auto") — One of: `npm`, `pip`,
  `cargo`, `gomod`, `auto`
- `output_format` (string, optional, default: "json") — `json` or `markdown`

**Example:**

```bash
cortex tool call audit_dependencies \
  --project_path ./my-node-app \
  --package_manager npm \
  --output_format markdown
```

### audit_secrets

Scan codebase for hardcoded secrets and credentials.

**Parameters:**

- `target_path` (string, required) — Directory or file to scan
- `file_patterns` (string, optional) — Glob patterns, comma-separated (e.g.
  `*.ts,*.js,*.py`)
- `exclude_dirs` (string, optional, default: "node_modules,.git,dist,build") —
  Directories to skip

**Detection Categories (30+ patterns):**

| Category           | Patterns Detected                                                                  |
| ------------------ | ---------------------------------------------------------------------------------- |
| API Keys           | GitHub, OpenAI, Anthropic, Google, Slack, Stripe, Twilio, SendGrid, Heroku, GitLab |
| Cloud Credentials  | AWS Access Key, AWS Secret, GCP API Key, Azure Connection String                   |
| Tokens             | JWT, Bearer, npm Auth, PyPI, Docker Hub, Generic Token                             |
| Passwords          | Hardcoded passwords in assignments                                                 |
| Private Keys       | RSA, DSA, EC, OpenSSH, PGP private key headers                                     |
| Connection Strings | MongoDB, PostgreSQL, MySQL, Redis, JDBC                                            |
| OAuth              | Google OAuth Client ID, Generic Client Secret                                      |
| Encoded Secrets    | Base64, Hex-encoded values near secret/key names                                   |

**Example:**

```bash
cortex tool call audit_secrets \
  --target_path ./src \
  --file_patterns "*.ts,*.js,*.env" \
  --exclude_dirs "node_modules,.git,dist"
```

### audit_sast

Static analysis security testing for common vulnerability patterns.

**Parameters:**

- `target_path` (string, required) — Directory or file to analyze
- `language` (string, required) — `javascript`, `typescript`, `python`, `java`,
  `go`, `php`
- `rules` (string, optional) — Comma-separated rule groups or IDs. Available
  groups: `owasp_top10`, `injection`, `xss`, `auth`, `crypto`. Or individual
  rules: `sql-injection`, `xss`, `command-injection`, `path-traversal`, `ssrf`,
  `insecure-deserialization`, `hardcoded-crypto`

**SAST Rules:**

| Rule                               | Severity | OWASP 2021 |
| ---------------------------------- | -------- | ---------- |
| SQL Injection                      | Critical | A03:2021   |
| Command Injection                  | Critical | A03:2021   |
| Cross-Site Scripting (XSS)         | High     | A03:2021   |
| Path Traversal                     | High     | A01:2021   |
| Server-Side Request Forgery (SSRF) | High     | A10:2021   |
| Insecure Deserialization           | High     | A08:2021   |
| Hardcoded Cryptographic Material   | High     | A02:2021   |

**Example:**

```bash
cortex tool call audit_sast \
  --target_path ./src \
  --language python \
  --rules "injection,xss"
```

### audit_owasp

OWASP Top 10 compliance check.

**Parameters:**

- `target_path` (string, required) — Project directory to check
- `year` (string, optional, default: "2021") — `2021` or `2017`

**Example:**

```bash
cortex tool call audit_owasp --target_path ./ --year 2021
```

### audit_generate_report

Generate a comprehensive security audit report from collected findings.

**Parameters:**

- `findings` (string, required) — JSON array of findings from audit tools
- `format` (string, optional, default: "markdown") — `markdown`, `json`, or
  `html`
- `include_remediation` (boolean, optional, default: true) — Include fix
  guidance

**Example:**

```bash
# Collect findings from multiple tools
FINDINGS=$(cortex tool call audit_dependencies --project_path . --output_format json)
FINDINGS="$FINDINGS$(cortex tool call audit_secrets --target_path ./src)"

# Generate HTML report
cortex tool call audit_generate_report \
  --findings "[$FINDINGS]" \
  --format html \
  --include_remediation true > security-report.html
```

### audit_status

Check what security audit capabilities are available.

**Example:**

```bash
cortex tool call audit_status
```

Output includes available tools, pattern counts, supported languages, and
current configuration.

## Configuration

Configure via Cortex settings UI under the **General** section:

| Setting             | Type   | Default                                    | Description                                              |
| ------------------- | ------ | ------------------------------------------ | -------------------------------------------------------- |
| `severityThreshold` | select | `medium`                                   | Minimum severity to report (low, medium, high, critical) |
| `maxFileSizeMB`     | number | `10`                                       | Maximum file size in MB to scan                          |
| `excludeDirs`       | text   | `node_modules,.git,dist,build,__pycache__` | Directories to exclude from scans                        |

Configuration is loaded in `onLoad` via `ctx.config.get()`.

### Programmatic Configuration

In `~/.cortex/config.json`:

```json
{
  "plugins": {
    "cortex-plugin-security-audit": {
      "enabled": true,
      "config": {
        "severityThreshold": "high",
        "maxFileSizeMB": 5,
        "excludeDirs": "node_modules,.git,dist,target"
      }
    }
  }
}
```

## Capabilities

| Capability      | Required By                                                        | Purpose                              |
| --------------- | ------------------------------------------------------------------ | ------------------------------------ |
| `tools`         | All tools                                                          | Tool registration and execution      |
| `shell:run`     | `audit_dependencies`                                               | Run package manager audit commands   |
| `fs:read`       | `audit_dependencies`, `audit_secrets`, `audit_sast`, `audit_owasp` | Read project files for scanning      |
| `network:fetch` | _(reserved)_                                                       | Fetch vulnerability database updates |

## OWASP Mapping

Each finding includes an OWASP Top 10 category reference for compliance
tracking.

### OWASP 2021

| ID       | Category                    | Detected By                                  |
| -------- | --------------------------- | -------------------------------------------- |
| A01:2021 | Broken Access Control       | Path Traversal (SAST)                        |
| A02:2021 | Cryptographic Failures      | Hardcoded Crypto (SAST)                      |
| A03:2021 | Injection                   | SQL Injection, XSS, Command Injection (SAST) |
| A05:2021 | Security Misconfiguration   | Hardcoded Secrets                            |
| A06:2021 | Vulnerable Components       | Dependency Audit                             |
| A08:2021 | Software Integrity Failures | Insecure Deserialization (SAST)              |
| A10:2021 | SSRF                        | SSRF Detection (SAST)                        |

### Severity Scoring

Each finding has a severity score used for risk assessment:

| Severity | Score | Description                              |
| -------- | ----- | ---------------------------------------- |
| Low      | 1     | Informational, no immediate risk         |
| Medium   | 3     | Potential risk, should be addressed      |
| High     | 7     | Significant risk, prioritize remediation |
| Critical | 10    | Severe risk, immediate action required   |

## Development

```bash
# Install dependencies
deno cache mod.ts

# Run tests
deno task test

# Format code
deno fmt

# Lint
deno lint

# Validate plugin
deno task validate
```

## Publishing

1. Update version in `manifest.json`
2. Update `CHANGELOG.md`
3. Commit and tag: `git tag v1.0.0`
4. Push to GitHub: `git push origin main --tags`

## Troubleshooting

### No files scanned

Ensure `target_path` points to a valid directory and `exclude_dirs` isn't too
aggressive. Try explicit `file_patterns` like `*.ts,*.js`.

### Package manager not detected

Use `--package_manager auto` to auto-detect from lock files (package-lock.json,
requirements.txt, Cargo.toml, go.mod), or specify explicitly.

### Secret patterns not matching

The scanner uses regex-based detection. Custom patterns can be added in the
`SECRET_PATTERNS` array in `mod.ts`.

## License

MIT — See [LICENSE](./LICENSE) file

## Support

- [CortexPrism Docs](https://cortexprism.io/docs/developer-guide)
- [Discord Community](https://discord.gg/y7DkaEbPQC)
- [Report Issues](https://github.com/CortexPrism/cortex-plugin-security-audit/issues)
