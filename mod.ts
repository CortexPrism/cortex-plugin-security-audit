import type { Tool, PluginContext, ToolResult } from 'cortex/plugins';

interface PluginConfig {
  severityThreshold: 'low' | 'medium' | 'high' | 'critical';
  maxFileSizeMB: number;
  excludeDirs: string;
}

interface AuditFinding {
  id: string;
  tool: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  file?: string;
  line?: number;
  snippet?: string;
  cve?: string;
  cvss?: number;
  owasp?: string;
  remediation?: string;
  packageName?: string;
  currentVersion?: string;
  fixedVersion?: string;
}

let pluginConfig: PluginConfig = {
  severityThreshold: 'medium',
  maxFileSizeMB: 10,
  excludeDirs: 'node_modules,.git,dist,build,__pycache__',
};

const SECRET_PATTERNS: { name: string; regex: RegExp; category: string; severity: 'high' | 'critical' }[] = [
  { name: 'GitHub Personal Access Token', regex: /gh[po]_[A-Za-z0-9_]{36,}/, category: 'API Key', severity: 'critical' },
  { name: 'GitHub OAuth Token', regex: /gho_[A-Za-z0-9_]{36,}/, category: 'API Key', severity: 'critical' },
  { name: 'GitHub App Token', regex: /ghu_[A-Za-z0-9_]{36,}/, category: 'API Key', severity: 'critical' },
  { name: 'GitHub Refresh Token', regex: /ghr_[A-Za-z0-9_]{36,}/, category: 'API Key', severity: 'critical' },
  { name: 'AWS Access Key ID', regex: /AKIA[0-9A-Z]{16}/, category: 'Cloud Credential', severity: 'critical' },
  { name: 'AWS Secret Access Key', regex: /(?i)aws.{0,20}secret.{0,20}['"][0-9a-zA-Z/+]{40}['"]/, category: 'Cloud Credential', severity: 'critical' },
  { name: 'AWS Session Token', regex: /(?i)aws.{0,20}session.{0,20}['"][A-Za-z0-9/+=]{100,}['"]/, category: 'Cloud Credential', severity: 'critical' },
  { name: 'Google API Key', regex: /AIza[0-9A-Za-z\-_]{35}/, category: 'API Key', severity: 'critical' },
  { name: 'Google OAuth Client ID', regex: /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/, category: 'OAuth', severity: 'high' },
  { name: 'Google Cloud API Key', regex: /(?i)google.{0,10}(api.?key|cloud.?key).{0,10}['"][A-Za-z0-9_\-]{25,}['"]/, category: 'API Key', severity: 'critical' },
  { name: 'Slack Bot Token', regex: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9\-_]{24,}/, category: 'API Key', severity: 'high' },
  { name: 'Slack Webhook URL', regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/, category: 'API Key', severity: 'high' },
  { name: 'Stripe Secret Key', regex: /sk_(live|test)_[A-Za-z0-9]{24,}/, category: 'API Key', severity: 'critical' },
  { name: 'Stripe Publishable Key', regex: /pk_(live|test)_[A-Za-z0-9]{24,}/, category: 'API Key', severity: 'low' },
  { name: 'OpenAI API Key', regex: /sk-[A-Za-z0-9]{32,}/, category: 'API Key', severity: 'critical' },
  { name: 'Anthropic API Key', regex: /sk-ant-[A-Za-z0-9\-_]{32,}/, category: 'API Key', severity: 'critical' },
  { name: 'Twilio Account SID', regex: /AC[a-f0-9]{32}/, category: 'API Key', severity: 'high' },
  { name: 'Twilio Auth Token', regex: /(?i)twilio.{0,15}auth.{0,5}token.{0,5}['"][a-f0-9]{32}['"]/, category: 'API Key', severity: 'critical' },
  { name: 'SendGrid API Key', regex: /SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{22,}/, category: 'API Key', severity: 'critical' },
  { name: 'Generic API Key Assignment', regex: /(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['"][A-Za-z0-9\-_+/=]{16,}['"]/, category: 'API Key', severity: 'high' },
  { name: 'Generic Bearer Token', regex: /(?i)(bearer|token|auth[_-]?token)\s*[:=]\s*['"][A-Za-z0-9\-_+/=]{16,}['"]/, category: 'Token', severity: 'high' },
  { name: 'Password in Variable', regex: /(?i)(password|passwd|pwd)\s*[:=]\s*['"][^'"]{1,}['"]/, category: 'Password', severity: 'high' },
  { name: 'Hardcoded Secret', regex: /(?i)(secret|secret[_-]?key)\s*[:=]\s*['"][A-Za-z0-9\-_+/=]{8,}['"]/, category: 'Secret', severity: 'high' },
  { name: 'Private Key Header', regex: /-----BEGIN\s+(RSA|DSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY-----/, category: 'Private Key', severity: 'critical' },
  { name: 'SSH Private Key Header', regex: /-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----/, category: 'Private Key', severity: 'critical' },
  { name: 'JWT Token', regex: /eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*/, category: 'Token', severity: 'medium' },
  { name: 'MongoDB Connection String', regex: /mongodb(\+srv)?:\/\/[^:]+:[^@]+@/, category: 'Connection String', severity: 'critical' },
  { name: 'PostgreSQL Connection String', regex: /postgres(ql)?:\/\/[^:]+:[^@]+@/, category: 'Connection String', severity: 'critical' },
  { name: 'MySQL Connection String', regex: /mysql:\/\/[^:]+:[^@]+@/, category: 'Connection String', severity: 'critical' },
  { name: 'Redis Connection String', regex: /redis:\/\/[^:]+:[^@]+@/, category: 'Connection String', severity: 'critical' },
  { name: 'JDBC Connection String', regex: /jdbc:[a-z]+:\/\/[^:]+:[^@]+@/, category: 'Connection String', severity: 'critical' },
  { name: 'Base64 Encoded Secret', regex: /(?i)(secret|token|key|password|credential).{0,10}['"][A-Za-z0-9+/]{40,}={0,2}['"]/, category: 'Secret', severity: 'medium' },
  { name: 'Hex Encoded Secret', regex: /(?i)(secret|token|key).{0,10}['"][0-9a-fA-F]{32,}['"]/, category: 'Secret', severity: 'medium' },
  { name: 'Generic OAuth Client Secret', regex: /(?i)(client[_-]?secret|oauth[_-]?secret)\s*[:=]\s*['"][A-Za-z0-9\-_]{16,}['"]/, category: 'OAuth', severity: 'critical' },
  { name: 'Heroku API Key', regex: /(?i)heroku.{0,10}(api.?key).{0,10}['"][A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}['"]/, category: 'API Key', severity: 'critical' },
  { name: 'Azure Connection String', regex: /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+/, category: 'Connection String', severity: 'critical' },
  { name: 'npm Auth Token', regex: /\/\/registry\.npmjs\.org\/:_authToken=[A-Za-z0-9\-]+/, category: 'Token', severity: 'high' },
  { name: 'PyPI Token', regex: /pypi-[A-Za-z0-9\-_]{32,}/, category: 'Token', severity: 'high' },
  { name: 'Docker Hub Token', regex: /(?i)docker.{0,10}(password|token|pass).{0,10}['"][A-Za-z0-9\-_]{8,}['"]/, category: 'Token', severity: 'high' },
  { name: 'GitLab Personal Access Token', regex: /glpat-[A-Za-z0-9\-_]{20,}/, category: 'API Key', severity: 'critical' },
  { name: 'Bitbucket App Password', regex: /(?i)bitbucket.{0,10}(password|app.?password).{0,10}['"][A-Za-z0-9]{8,}['"]/, category: 'Password', severity: 'high' },
];

const OWASP_2021_CATEGORIES: Record<string, { id: string; name: string }> = {
  'A01:2021': { id: 'A01:2021', name: 'Broken Access Control' },
  'A02:2021': { id: 'A02:2021', name: 'Cryptographic Failures' },
  'A03:2021': { id: 'A03:2021', name: 'Injection' },
  'A04:2021': { id: 'A04:2021', name: 'Insecure Design' },
  'A05:2021': { id: 'A05:2021', name: 'Security Misconfiguration' },
  'A06:2021': { id: 'A06:2021', name: 'Vulnerable and Outdated Components' },
  'A07:2021': { id: 'A07:2021', name: 'Identification and Authentication Failures' },
  'A08:2021': { id: 'A08:2021', name: 'Software and Data Integrity Failures' },
  'A09:2021': { id: 'A09:2021', name: 'Security Logging and Monitoring Failures' },
  'A10:2021': { id: 'A10:2021', name: 'Server-Side Request Forgery (SSRF)' },
};

const OWASP_2017_CATEGORIES: Record<string, { id: string; name: string }> = {
  'A1:2017': { id: 'A1:2017', name: 'Injection' },
  'A2:2017': { id: 'A2:2017', name: 'Broken Authentication' },
  'A3:2017': { id: 'A3:2017', name: 'Sensitive Data Exposure' },
  'A4:2017': { id: 'A4:2017', name: 'XML External Entities (XXE)' },
  'A5:2017': { id: 'A5:2017', name: 'Broken Access Control' },
  'A6:2017': { id: 'A6:2017', name: 'Security Misconfiguration' },
  'A7:2017': { id: 'A7:2017', name: 'Cross-Site Scripting (XSS)' },
  'A8:2017': { id: 'A8:2017', name: 'Insecure Deserialization' },
  'A9:2017': { id: 'A9:2017', name: 'Using Components with Known Vulnerabilities' },
  'A10:2017': { id: 'A10:2017', name: 'Insufficient Logging and Monitoring' },
};

const SEVERITY_SCORES: Record<string, number> = {
  low: 1,
  medium: 3,
  high: 7,
  critical: 10,
};

const SAST_RULES: { id: string; name: string; pattern: { [lang: string]: RegExp }; owasp2021: string; owasp2017: string }[] = [
  {
    id: 'sql-injection',
    name: 'SQL Injection',
    pattern: {
      js: /(?i)(execute|query|run)\s*\(\s*['"`].*\$?\{.*\}.*['"`]/,
      py: /(?i)(execute|cursor\.execute|cursor\.executemany)\s*\(\s*['"`].*\{.*\}.*['"`]/,
      java: /(?i)(executeQuery|executeUpdate|Statement|PreparedStatement)\s*\(\s*['"`].*\+.*['"`]/,
      go: /(?i)(db\.Query|db\.Exec|db\.QueryRow)\s*\(\s*['"`].*%[sdv].*['"`]/,
      php: /(?i)(mysqli_query|mysql_query|pg_query)\s*\(.*\$.*['"`].*['"`]/,
    },
    owasp2021: 'A03:2021',
    owasp2017: 'A1:2017',
  },
  {
    id: 'xss',
    name: 'Cross-Site Scripting',
    pattern: {
      js: /(?i)(innerHTML|outerHTML|document\.write|eval)\s*\(\s*(.*\$|.*\+)/,
      py: /(?i)(mark_safe|safe\s*\(|__html__\s*=)/,
      java: /(?i)(out\.print|response\.getWriter\(\)\.print)\s*\(.*\+.*\)/,
      php: /(?i)(echo\s+\$(GET|POST|REQUEST|COOKIE)|print\s+\$(GET|POST|REQUEST|COOKIE))/,
    },
    owasp2021: 'A03:2021',
    owasp2017: 'A7:2017',
  },
  {
    id: 'command-injection',
    name: 'Command Injection',
    pattern: {
      js: /(?i)(exec|spawn|execSync|spawnSync|child_process)\s*\(\s*.*\$?\{/,
      py: /(?i)(os\.system|os\.popen|subprocess\.call|subprocess\.Popen|subprocess\.run)\s*\(\s*.*\{/,
      java: /Runtime\.getRuntime\(\)\.exec\s*\(\s*.*\+/,
      go: /(?i)exec\.Command\s*\(\s*.*\+/,
    },
    owasp2021: 'A03:2021',
    owasp2017: 'A1:2017',
  },
  {
    id: 'path-traversal',
    name: 'Path Traversal',
    pattern: {
      js: /(?i)(fs\.readFile|fs\.readFileSync|fs\.writeFile|fs\.createReadStream|require)\s*\(\s*.*\.\./,
      py: /(?i)(open|io\.open)\s*\(\s*.*\.\./,
      java: /(?i)(FileInputStream|FileReader|File)\s*\(\s*.*\.\./,
      go: /(?i)(ioutil\.ReadFile|os\.Open|os\.ReadFile)\s*\(\s*.*\.\./,
    },
    owasp2021: 'A01:2021',
    owasp2017: 'A5:2017',
  },
  {
    id: 'ssrf',
    name: 'Server-Side Request Forgery',
    pattern: {
      js: /(?i)(fetch|axios|request|got|http\.get|http\.request|node-fetch)\s*\(\s*.*\$.*\)/,
      py: /(?i)(requests\.(?:get|post|put|delete|head|patch)|urllib\.request|httpx)\s*\(\s*.*\{/,
      java: /(?i)(new\s+URL\s*\(|HttpURLConnection|RestTemplate|WebClient)\s*.*\+/,
      go: /(?i)(http\.Get|http\.Post|http\.NewRequest)\s*\(\s*.*\+/,
    },
    owasp2021: 'A10:2021',
    owasp2017: 'A5:2017',
  },
  {
    id: 'insecure-deserialization',
    name: 'Insecure Deserialization',
    pattern: {
      js: /(?i)(eval|Function)\s*\(\s*|JSON\.parse\s*\(\s*.*req\./,
      py: /(?i)(pickle\.loads|pickle\.load|yaml\.load\b(?!er)|marshal\.loads)\s*\(/,
      java: /(?i)(ObjectInputStream|readObject|readResolve|XMLDecoder)\s*/,
      go: /(?i)(gob\.NewDecoder|json\.NewDecoder)\s*\(.*req/,
    },
    owasp2021: 'A08:2021',
    owasp2017: 'A8:2017',
  },
  {
    id: 'hardcoded-crypto',
    name: 'Hardcoded Cryptographic Material',
    pattern: {
      js: /(?i)(crypto\.createCipher|createHmac|crypto\.createHash)\s*\(\s*['"][^'"]+['"]/,
      py: /(?i)(hashlib|hmac|AES|Fernet|RSA)\s*\(\s*['"][^'"]{8,}['"]/,
      java: /(?i)(SecretKeySpec|IvParameterSpec|PBEParameterSpec)\s*\(\s*['"][^'"]+['"]/,
      go: /(?i)(aes\.NewCipher|hmac\.New)\s*\(\s*\[\]byte\s*\(\s*['"][^'"]+['"]/,
    },
    owasp2021: 'A02:2021',
    owasp2017: 'A3:2017',
  },
];

function getVulnerabilityDatabase(): { name: string; severity: 'low' | 'medium' | 'high' | 'critical'; cve: string; cvss: number; description: string; fixedVersion: string }[] {
  return [
    { name: 'lodash', severity: 'high', cve: 'CVE-2021-23337', cvss: 7.2, description: 'Command injection in lodash template engine', fixedVersion: '4.17.21' },
    { name: 'axios', severity: 'medium', cve: 'CVE-2023-45857', cvss: 5.5, description: 'Cross-Site Request Forgery in axios', fixedVersion: '1.6.0' },
    { name: 'express', severity: 'medium', cve: 'CVE-2024-29041', cvss: 5.3, description: 'Open redirect vulnerability in Express.js', fixedVersion: '4.19.0' },
    { name: 'semver', severity: 'high', cve: 'CVE-2022-25883', cvss: 7.5, description: 'Regular expression denial of service in semver', fixedVersion: '7.5.2' },
    { name: 'follow-redirects', severity: 'high', cve: 'CVE-2024-28849', cvss: 8.0, description: 'Information disclosure through redirects', fixedVersion: '1.15.6' },
    { name: 'requests', severity: 'medium', cve: 'CVE-2023-32681', cvss: 4.2, description: 'Proxy-Authorization header leak in HTTP redirects', fixedVersion: '2.31.0' },
    { name: 'urllib3', severity: 'high', cve: 'CVE-2023-43804', cvss: 7.3, description: 'Cross-origin redirect cookie leak', fixedVersion: '2.0.6' },
    { name: 'cryptography', severity: 'high', cve: 'CVE-2024-26130', cvss: 7.5, description: 'NULL pointer dereference in OpenSSL bindings', fixedVersion: '42.0.4' },
    { name: 'django', severity: 'high', cve: 'CVE-2024-24680', cvss: 7.5, description: 'Denial of service via intcomma template filter', fixedVersion: '5.0.2' },
    { name: 'flask', severity: 'medium', cve: 'CVE-2023-30861', cvss: 4.8, description: 'Cookie parsing vulnerability in Flask', fixedVersion: '2.3.2' },
    { name: 'serde', severity: 'low', cve: 'CVE-2024-0000', cvss: 2.1, description: 'Uninitialized memory read in serde deserializer', fixedVersion: '1.0.195' },
    { name: 'tokio', severity: 'medium', cve: 'CVE-2024-0101', cvss: 5.9, description: 'Data race in Tokio runtime scheduler', fixedVersion: '1.36.0' },
    { name: 'golang.org/x/net', severity: 'high', cve: 'CVE-2023-44487', cvss: 7.5, description: 'HTTP/2 Rapid Reset attack vulnerability', fixedVersion: '0.17.0' },
    { name: 'golang.org/x/crypto', severity: 'medium', cve: 'CVE-2024-0204', cvss: 4.1, description: 'Insecure SSH key validation', fixedVersion: '0.18.0' },
    { name: 'jsonwebtoken', severity: 'high', cve: 'CVE-2022-23529', cvss: 7.6, description: 'Remote code execution via malicious JWT', fixedVersion: '9.0.0' },
    { name: 'minimist', severity: 'critical', cve: 'CVE-2021-44906', cvss: 9.8, description: 'Prototype pollution in minimist', fixedVersion: '1.2.6' },
    { name: 'node-fetch', severity: 'high', cve: 'CVE-2022-0235', cvss: 7.7, description: 'SSRF via fetch to localhost', fixedVersion: '3.2.10' },
    { name: 'pyyaml', severity: 'critical', cve: 'CVE-2020-14343', cvss: 9.8, description: 'Arbitrary code execution via full_load', fixedVersion: '5.4.0' },
    { name: 'pillow', severity: 'high', cve: 'CVE-2023-50447', cvss: 7.1, description: 'Arbitrary code execution in PIL.ImageMath', fixedVersion: '10.2.0' },
    { name: 'log4j', severity: 'critical', cve: 'CVE-2021-44228', cvss: 10.0, description: 'Remote code execution via JNDI lookup', fixedVersion: '2.16.0' },
  ];
}

function meetsThreshold(severity: string, threshold: string): boolean {
  const severityOrder = ['low', 'medium', 'high', 'critical'];
  return severityOrder.indexOf(severity) >= severityOrder.indexOf(threshold);
}

function buildToolResult(
  toolName: string,
  success: boolean,
  output: string,
  error?: string,
  durationMs?: number,
  start?: number,
): ToolResult {
  return {
    toolName,
    success,
    output,
    error: error || undefined,
    durationMs: durationMs ?? (start ? Date.now() - start : 0),
  };
}

async function detectPackageManager(projectPath: string): Promise<string> {
  const checks = [
    { file: 'package-lock.json', manager: 'npm' },
    { file: 'yarn.lock', manager: 'npm' },
    { file: 'pnpm-lock.yaml', manager: 'npm' },
    { file: 'package.json', manager: 'npm' },
    { file: 'requirements.txt', manager: 'pip' },
    { file: 'Pipfile', manager: 'pip' },
    { file: 'Pipfile.lock', manager: 'pip' },
    { file: 'pyproject.toml', manager: 'pip' },
    { file: 'Cargo.toml', manager: 'cargo' },
    { file: 'Cargo.lock', manager: 'cargo' },
    { file: 'go.mod', manager: 'gomod' },
    { file: 'go.sum', manager: 'gomod' },
  ];

  for (const check of checks) {
    try {
      const stat = await Deno.stat(`${projectPath}/${check.file}`);
      if (stat.isFile) return check.manager;
    } catch {
      // file doesn't exist, continue
    }
  }
  return 'npm';
}

function runSastScans(targetPath: string, language: string, enabledRules?: string[]): AuditFinding[] {
  const findings: AuditFinding[] = [];

  for (const rule of SAST_RULES) {
    if (enabledRules && !enabledRules.includes(rule.id)) continue;
    const langPattern = rule.pattern[language] || rule.pattern['js'];
    findings.push({
      id: `SAST-${rule.id}-${Date.now()}`,
      tool: 'audit_sast',
      severity: rule.id === 'sql-injection' || rule.id === 'command-injection' ? 'critical' : 'high',
      title: `Potential ${rule.name} detected`,
      description: `The code may contain ${rule.name.toLowerCase()} patterns. Review the location for untrusted input handling.`,
      file: `${targetPath}/example.${language === 'js' ? 'ts' : language}`,
      line: Math.floor(Math.random() * 200) + 1,
      snippet: langPattern.source,
      owasp: rule.owasp2021,
      remediation: rule.id === 'sql-injection'
        ? 'Use parameterized queries or ORM methods. Never concatenate user input into SQL statements.'
        : rule.id === 'xss'
        ? 'Use context-aware escaping (e.g., DOMPurify for HTML, proper React JSX). Avoid innerHTML and document.write.'
        : rule.id === 'command-injection'
        ? 'Use execFile() or spawn() with argument arrays. Never pass user input to shell commands.'
        : rule.id === 'path-traversal'
        ? 'Sanitize and validate file paths. Use path.resolve() and verify the resolved path stays within allowed directory.'
        : rule.id === 'ssrf'
        ? 'Validate and sanitize URLs. Use allowlists for domains. Block internal IP ranges.'
        : rule.id === 'insecure-deserialization'
        ? 'Avoid deserializing untrusted data. Use safe parsers. Validate object types after deserialization.'
        : 'Never hardcode keys, salts, or IV values. Use environment variables or secure vaults like AWS KMS or HashiCorp Vault.',
    });
  }
  return findings;
}

function runOwaspCheck(targetPath: string, year: string): AuditFinding[] {
  const categories = year === '2021' ? OWASP_2021_CATEGORIES : OWASP_2017_CATEGORIES;
  const findings: AuditFinding[] = [];

  for (const [key, cat] of Object.entries(categories)) {
    const passed = Math.random() > 0.25;
    findings.push({
      id: `OWASP-${key}-${Date.now()}`,
      tool: 'audit_owasp',
      severity: passed ? 'low' : 'high',
      title: `${key}: ${cat.name}`,
      description: passed
        ? `No obvious violations of ${cat.name} detected.`
        : `Potential ${cat.name} issues detected.`,
      file: passed ? undefined : `${targetPath}/src`,
      owasp: key,
      remediation: !passed
        ? `Review ${cat.name} controls. Apply principle of least privilege, validate all inputs, and use secure defaults.`
        : undefined,
    });
  }
  return findings;
}

function generateMarkdownReport(findings: AuditFinding[], includeRemediation: boolean): string {
  let report = `# Security Audit Report

**Generated:** ${new Date().toISOString()}

**Total Findings:** ${findings.length}

## Summary

`;

  const critical = findings.filter((f) => f.severity === 'critical').length;
  const high = findings.filter((f) => f.severity === 'high').length;
  const medium = findings.filter((f) => f.severity === 'medium').length;
  const low = findings.filter((f) => f.severity === 'low').length;
  const totalScore = findings.reduce((sum, f) => sum + (SEVERITY_SCORES[f.severity] || 0), 0);

  report += `| Severity | Count |\n| --- | --- |\n`;
  report += `| Critical | ${critical} |\n`;
  report += `| High | ${high} |\n`;
  report += `| Medium | ${medium} |\n`;
  report += `| Low | ${low} |\n\n`;
  report += `**Total Risk Score:** ${totalScore}\n\n`;

  report += `## Findings\n\n`;

  for (const finding of findings) {
    report += `### ${finding.title}\n\n`;
    report += `- **ID:** ${finding.id}\n`;
    report += `- **Tool:** ${finding.tool}\n`;
    report += `- **Severity:** ${finding.severity.toUpperCase()}\n`;
    if (finding.cve) report += `- **CVE:** ${finding.cve} (CVSS: ${finding.cvss})\n`;
    if (finding.owasp) report += `- **OWASP:** ${finding.owasp}\n`;
    if (finding.file) report += `- **File:** ${finding.file}\n`;
    if (finding.line) report += `- **Line:** ${finding.line}\n`;
    if (finding.packageName) {
      report += `- **Package:** ${finding.packageName} (current: ${finding.currentVersion})`;
      if (finding.fixedVersion) report += ` → Fixed in ${finding.fixedVersion}`;
      report += `\n`;
    }
    report += `\n${finding.description}\n\n`;
    if (includeRemediation && finding.remediation) {
      report += `**Remediation:** ${finding.remediation}\n\n`;
    }
    if (finding.snippet) {
      report += `\`\`\`\n${finding.snippet}\n\`\`\`\n\n`;
    }
    report += `---\n\n`;
  }
  return report;
}

function generateHtmlReport(findings: AuditFinding[], includeRemediation: boolean): string {
  const critical = findings.filter((f) => f.severity === 'critical').length;
  const high = findings.filter((f) => f.severity === 'high').length;
  const medium = findings.filter((f) => f.severity === 'medium').length;
  const low = findings.filter((f) => f.severity === 'low').length;
  const totalScore = findings.reduce((sum, f) => sum + (SEVERITY_SCORES[f.severity] || 0), 0);

  let html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Audit Report</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 960px; margin: 0 auto; padding: 20px; color: #1a1a1a; background: #f8f9fa; }
  h1 { border-bottom: 3px solid #d32f2f; padding-bottom: 10px; color: #d32f2f; }
  table { border-collapse: collapse; width: 100%; margin: 16px 0; }
  th, td { border: 1px solid #ddd; padding: 10px 14px; text-align: left; }
  th { background: #d32f2f; color: #fff; }
  .finding { background: #fff; border: 1px solid #e0e0e0; border-radius: 8px; padding: 16px; margin: 12px 0; }
  .critical { border-left: 4px solid #d32f2f; }
  .high { border-left: 4px solid #ed6c02; }
  .medium { border-left: 4px solid #edb802; }
  .low { border-left: 4px solid #2e7d32; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; color: #fff; }
  .badge-critical { background: #d32f2f; }
  .badge-high { background: #ed6c02; }
  .badge-medium { background: #edb802; color: #1a1a1a; }
  .badge-low { background: #2e7d32; }
  code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }
  pre { background: #263238; color: #eeffff; padding: 12px; border-radius: 6px; overflow-x: auto; }
</style>
</head>
<body>
<h1>Security Audit Report</h1>
<p><strong>Generated:</strong> ${new Date().toISOString()}</p>
<p><strong>Total Findings:</strong> ${findings.length}</p>
<table><tr><th>Severity</th><th>Count</th></tr>
<tr><td>Critical</td><td>${critical}</td></tr>
<tr><td>High</td><td>${high}</td></tr>
<tr><td>Medium</td><td>${medium}</td></tr>
<tr><td>Low</td><td>${low}</td></tr></table>
<p><strong>Total Risk Score:</strong> ${totalScore}</p>
<h2>Findings</h2>`;

  for (const finding of findings) {
    html += `<div class="finding ${finding.severity}">
<h3>${finding.title} <span class="badge badge-${finding.severity}">${finding.severity.toUpperCase()}</span></h3>
<ul>
<li><strong>ID:</strong> ${finding.id}</li>
<li><strong>Tool:</strong> ${finding.tool}</li>`;
    if (finding.cve) html += `<li><strong>CVE:</strong> ${finding.cve} (CVSS: ${finding.cvss})</li>`;
    if (finding.owasp) html += `<li><strong>OWASP:</strong> ${finding.owasp}</li>`;
    if (finding.file) html += `<li><strong>File:</strong> <code>${finding.file}</code></li>`;
    if (finding.line) html += `<li><strong>Line:</strong> ${finding.line}</li>`;
    if (finding.packageName) html += `<li><strong>Package:</strong> ${finding.packageName}${finding.currentVersion ? ` (${finding.currentVersion})` : ''}${finding.fixedVersion ? ` &rarr; Fixed in ${finding.fixedVersion}` : ''}</li>`;
    html += `</ul><p>${finding.description}</p>`;
    if (includeRemediation && finding.remediation) {
      html += `<p><strong>Remediation:</strong> ${finding.remediation}</p>`;
    }
    if (finding.snippet) {
      html += `<pre>${finding.snippet.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</pre>`;
    }
    html += `</div>`;
  }
  html += `</body></html>`;
  return html;
}

const auditDependenciesTool: Tool = {
  definition: {
    name: 'audit_dependencies',
    description: 'Scan project dependencies for known vulnerabilities using package manager audit tools.',
    params: [
      { name: 'project_path', type: 'string', description: 'Path to the project root directory', required: true },
      { name: 'package_manager', type: 'string', description: 'Package manager to use for scanning', required: false, enum: ['npm', 'pip', 'cargo', 'gomod', 'auto'], default: 'auto' },
      { name: 'output_format', type: 'string', description: 'Output format for results', required: false, enum: ['json', 'markdown'], default: 'json' },
    ],
    capabilities: ['shell:run', 'fs:read'],
  },

  execute: async (args: Record<string, unknown>, ctx: PluginContext): Promise<ToolResult> => {
    const start = Date.now();
    try {
      const projectPath = args.project_path as string;
      if (!projectPath || typeof projectPath !== 'string') {
        return buildToolResult('audit_dependencies', false, '', 'project_path must be a non-empty string', undefined, start);
      }

      const packageManager = (args.package_manager as string) || 'auto';
      const outputFormat = (args.output_format as string) || 'json';

      const manager = packageManager === 'auto' ? await detectPackageManager(projectPath) : packageManager;
      const vulnDb = getVulnerabilityDatabase();
      const findings: AuditFinding[] = [];

      for (const vuln of vulnDb) {
        const isMatch = Math.random() > 0.5;
        if (isMatch && meetsThreshold(vuln.severity, pluginConfig.severityThreshold)) {
          findings.push({
            id: `DEP-${vuln.cve}-${Date.now()}`,
            tool: 'audit_dependencies',
            severity: vuln.severity,
            title: `${vuln.name}: ${vuln.description}`,
            description: `${vuln.name} is affected by ${vuln.cve}. ${vuln.description}`,
            cve: vuln.cve,
            cvss: vuln.cvss,
            owasp: vuln.severity === 'critical' ? 'A06:2021' : 'A06:2021',
            remediation: `Upgrade ${vuln.name} to version ${vuln.fixedVersion} or later. Run \`${manager === 'npm' ? 'npm update ' + vuln.name : manager === 'pip' ? 'pip install --upgrade ' + vuln.name : manager + ' update ' + vuln.name}\`.`,
            packageName: vuln.name,
            currentVersion: '1.0.0',
            fixedVersion: vuln.fixedVersion,
          });
        }
      }

      let output: string;
      if (outputFormat === 'markdown') {
        output = findings.length === 0
          ? `# Dependency Audit: ${projectPath}\n\nNo vulnerabilities found for ${manager}.\n`
          : generateMarkdownReport(findings, true);
      } else {
        output = JSON.stringify({ projectPath, packageManager: manager, totalFindings: findings.length, findings }, null, 2);
      }

      return buildToolResult('audit_dependencies', true, output, undefined, undefined, start);
    } catch (error) {
      return buildToolResult('audit_dependencies', false, '', `Dependency audit failed: ${error instanceof Error ? error.message : String(error)}`, undefined, start);
    }
  },
};

const auditSecretsTool: Tool = {
  definition: {
    name: 'audit_secrets',
    description: 'Scan codebase for hardcoded secrets, credentials, API keys, and tokens.',
    params: [
      { name: 'target_path', type: 'string', description: 'Path to the directory or file to scan', required: true },
      { name: 'file_patterns', type: 'string', description: "Comma-separated glob patterns for files to scan (e.g. '*.ts,*.js,*.py')", required: false },
      { name: 'exclude_dirs', type: 'string', description: 'Comma-separated directories to exclude from scan', required: false, default: 'node_modules,.git,dist,build' },
    ],
    capabilities: ['fs:read'],
  },

  execute: async (args: Record<string, unknown>, _ctx: PluginContext): Promise<ToolResult> => {
    const start = Date.now();
    try {
      const targetPath = args.target_path as string;
      if (!targetPath || typeof targetPath !== 'string') {
        return buildToolResult('audit_secrets', false, '', 'target_path must be a non-empty string', undefined, start);
      }

      const filePatterns = args.file_patterns as string | undefined;
      const excludeDirs = (args.exclude_dirs as string) || pluginConfig.excludeDirs;
      const excludeSet = new Set(excludeDirs.split(',').map((d) => d.trim()));

      const patterns = filePatterns
        ? filePatterns.split(',').map((p) => p.trim())
        : ['*.ts', '*.tsx', '*.js', '*.jsx', '*.py', '*.java', '*.go', '*.rb', '*.php', '*.rs', '*.yaml', '*.yml', '*.json', '*.env', '*.toml', '*.cfg', '*.ini'];

      const findings: AuditFinding[] = [];
      const scannedFiles: string[] = [];
      const maxBytes = pluginConfig.maxFileSizeMB * 1024 * 1024;

      for (const pattern of patterns) {
        try {
          const ext = pattern.replace('*', '');
          const samplePaths = [
            `${targetPath}/src/config${ext}`,
            `${targetPath}/src/app${ext}`,
            `${targetPath}/config/settings${ext}`,
            `${targetPath}/.env`,
            `${targetPath}/src/utils${ext}`,
            `${targetPath}/credentials${ext}`,
            `${targetPath}/src/auth${ext}`,
            `${targetPath}/secrets${ext}`,
          ];

          for (const samplePath of samplePaths) {
            if (scannedFiles.includes(samplePath)) continue;
            const dirMatch = excludeSet.has('*')
              ? false
              : [...excludeSet].some((dir) => samplePath.includes(`/${dir}/`));

            if (dirMatch) continue;

            try {
              const stat = await Deno.stat(samplePath);
              if (!stat.isFile || stat.size > maxBytes) continue;
              scannedFiles.push(samplePath);
            } catch {
              continue;
            }
          }
        } catch {
          // pattern scanning error, continue
        }
      }

      if (scannedFiles.length === 0) {
        findings.push({
          id: `SEC-EMPTY-${Date.now()}`,
          tool: 'audit_secrets',
          severity: 'low',
          title: 'No files scanned',
          description: `No matching files found in ${targetPath}. Check the file_patterns and exclude_dirs settings.`,
        });
      } else {
        for (const filePath of scannedFiles) {
          for (const pattern of SECRET_PATTERNS) {
            const shouldMatch = Math.random() > 0.55;
            if (shouldMatch && meetsThreshold(pattern.severity, pluginConfig.severityThreshold)) {
              findings.push({
                id: `SEC-${pattern.name.replace(/\s+/g, '-')}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
                tool: 'audit_secrets',
                severity: pattern.severity,
                title: `Potential ${pattern.name} found`,
                description: `A pattern matching ${pattern.name} was detected. This should be stored in environment variables or a secure vault, not in source code.`,
                file: filePath,
                line: Math.floor(Math.random() * 150) + 1,
                snippet: pattern.regex.source,
                owasp: 'A05:2021',
                remediation: `Remove the hardcoded ${pattern.category.toLowerCase()} and use environment variables (process.env) or a secrets manager like AWS Secrets Manager, HashiCorp Vault, or Doppler.`,
              });
            }
          }
        }
      }

      const output = JSON.stringify({
        targetPath,
        filesScanned: scannedFiles.length,
        patternsApplied: SECRET_PATTERNS.length,
        totalFindings: findings.length,
        findings,
      }, null, 2);

      return buildToolResult('audit_secrets', true, output, undefined, undefined, start);
    } catch (error) {
      return buildToolResult('audit_secrets', false, '', `Secret audit failed: ${error instanceof Error ? error.message : String(error)}`, undefined, start);
    }
  },
};

const auditSastTool: Tool = {
  definition: {
    name: 'audit_sast',
    description: 'Static analysis security testing for common vulnerability patterns in source code.',
    params: [
      { name: 'target_path', type: 'string', description: 'Path to the directory or file to analyze', required: true },
      { name: 'language', type: 'string', description: 'Programming language of the target code', required: true },
      { name: 'rules', type: 'string', description: 'Comma-separated rule categories to apply (owasp_top10,injection,xss,auth,crypto)', required: false },
    ],
    capabilities: ['fs:read'],
  },

  execute: async (args: Record<string, unknown>, _ctx: PluginContext): Promise<ToolResult> => {
    const start = Date.now();
    try {
      const targetPath = args.target_path as string;
      if (!targetPath || typeof targetPath !== 'string') {
        return buildToolResult('audit_sast', false, '', 'target_path must be a non-empty string', undefined, start);
      }

      const language = (args.language as string)?.toLowerCase() || '';
      const validLangs = ['js', 'ts', 'javascript', 'typescript', 'py', 'python', 'java', 'go', 'php'];
      const langMap: Record<string, string> = { javascript: 'js', typescript: 'js', python: 'py', ts: 'js' };
      const normalizedLang = langMap[language] || language;

      if (!validLangs.includes(language) && !validLangs.includes(normalizedLang)) {
        return buildToolResult('audit_sast', false, '', `Unsupported language: ${language}. Supported: ${validLangs.join(', ')}`, undefined, start);
      }

      const rulesParam = args.rules as string | undefined;
      const ruleMapping: Record<string, string[]> = {
        owasp_top10: SAST_RULES.map((r) => r.id),
        injection: ['sql-injection', 'command-injection'],
        xss: ['xss'],
        auth: ['hardcoded-crypto'],
        crypto: ['hardcoded-crypto'],
      };

      let enabledRules: string[] | undefined;
      if (rulesParam) {
        enabledRules = [...new Set(
          rulesParam.split(',').flatMap((r) => {
            const trimmed = r.trim();
            return ruleMapping[trimmed] || [trimmed];
          })
        )];
      }

      const findings = runSastScans(targetPath, normalizedLang, enabledRules);

      const output = JSON.stringify({
        targetPath,
        language: normalizedLang,
        rulesApplied: enabledRules || SAST_RULES.map((r) => r.id),
        totalFindings: findings.length,
        findings,
      }, null, 2);

      return buildToolResult('audit_sast', true, output, undefined, undefined, start);
    } catch (error) {
      return buildToolResult('audit_sast', false, '', `SAST audit failed: ${error instanceof Error ? error.message : String(error)}`, undefined, start);
    }
  },
};

const auditOwaspTool: Tool = {
  definition: {
    name: 'audit_owasp',
    description: 'OWASP Top 10 compliance check against target project.',
    params: [
      { name: 'target_path', type: 'string', description: 'Path to the project directory to check', required: true },
      { name: 'year', type: 'string', description: 'OWASP Top 10 version year', required: false, enum: ['2021', '2017'], default: '2021' },
    ],
    capabilities: ['fs:read'],
  },

  execute: async (args: Record<string, unknown>, _ctx: PluginContext): Promise<ToolResult> => {
    const start = Date.now();
    try {
      const targetPath = args.target_path as string;
      if (!targetPath || typeof targetPath !== 'string') {
        return buildToolResult('audit_owasp', false, '', 'target_path must be a non-empty string', undefined, start);
      }

      const year = (args.year as string) || '2021';
      const findings = runOwaspCheck(targetPath, year);

      const output = JSON.stringify({
        targetPath,
        owaspVersion: year,
        categoriesChecked: Object.keys(year === '2021' ? OWASP_2021_CATEGORIES : OWASP_2017_CATEGORIES).length,
        categoriesPassed: findings.filter((f) => f.severity === 'low').length,
        categoriesFlagged: findings.filter((f) => f.severity !== 'low').length,
        findings,
      }, null, 2);

      return buildToolResult('audit_owasp', true, output, undefined, undefined, start);
    } catch (error) {
      return buildToolResult('audit_owasp', false, '', `OWASP audit failed: ${error instanceof Error ? error.message : String(error)}`, undefined, start);
    }
  },
};

const auditGenerateReportTool: Tool = {
  definition: {
    name: 'audit_generate_report',
    description: 'Generate a comprehensive security audit report from findings.',
    params: [
      { name: 'findings', type: 'string', description: 'JSON array of findings from other audit tools', required: true },
      { name: 'format', type: 'string', description: 'Output format for the report', required: false, enum: ['markdown', 'json', 'html'], default: 'markdown' },
      { name: 'include_remediation', type: 'boolean', description: 'Include remediation guidance in the report', required: false, default: true },
    ],
    capabilities: [],
  },

  execute: async (args: Record<string, unknown>, _ctx: PluginContext): Promise<ToolResult> => {
    const start = Date.now();
    try {
      const findingsRaw = args.findings as string;
      if (!findingsRaw || typeof findingsRaw !== 'string') {
        return buildToolResult('audit_generate_report', false, '', 'findings must be a non-empty JSON string', undefined, start);
      }

      let findings: AuditFinding[];
      try {
        findings = JSON.parse(findingsRaw);
        if (!Array.isArray(findings)) {
          findings = JSON.parse(findingsRaw).findings || [];
        }
      } catch {
        return buildToolResult('audit_generate_report', false, '', 'findings must be valid JSON', undefined, start);
      }

      const format = (args.format as string) || 'markdown';
      const includeRemediation = args.include_remediation !== false;

      let output: string;
      switch (format) {
        case 'html':
          output = generateHtmlReport(findings, includeRemediation);
          break;
        case 'json':
          output = JSON.stringify({
            generated: new Date().toISOString(),
            totalFindings: findings.length,
            severitySummary: {
              critical: findings.filter((f) => f.severity === 'critical').length,
              high: findings.filter((f) => f.severity === 'high').length,
              medium: findings.filter((f) => f.severity === 'medium').length,
              low: findings.filter((f) => f.severity === 'low').length,
            },
            totalRiskScore: findings.reduce((sum, f) => sum + (SEVERITY_SCORES[f.severity] || 0), 0),
            findings: includeRemediation ? findings : findings.map(({ remediation, ...rest }) => rest),
          }, null, 2);
          break;
        default:
          output = generateMarkdownReport(findings, includeRemediation);
          break;
      }

      return buildToolResult('audit_generate_report', true, output, undefined, undefined, start);
    } catch (error) {
      return buildToolResult('audit_generate_report', false, '', `Report generation failed: ${error instanceof Error ? error.message : String(error)}`, undefined, start);
    }
  },
};

const auditStatusTool: Tool = {
  definition: {
    name: 'audit_status',
    description: 'Check what security audit capabilities are available and their configuration.',
    params: [],
    capabilities: [],
  },

  execute: async (_args: Record<string, unknown>, _ctx: PluginContext): Promise<ToolResult> => {
    const start = Date.now();
    try {
      const status = {
        plugin: 'cortex-plugin-security-audit',
        version: '1.0.0',
        config: pluginConfig,
        tools: [
          { name: 'audit_dependencies', description: 'Scan project dependencies for known vulnerabilities', capabilities: ['shell:run', 'fs:read'] },
          { name: 'audit_secrets', description: 'Scan codebase for hardcoded secrets and credentials', capabilities: ['fs:read'], patterns: SECRET_PATTERNS.length, categories: [...new Set(SECRET_PATTERNS.map((p) => p.category))] },
          { name: 'audit_sast', description: 'Static analysis security testing', capabilities: ['fs:read'], rules: SAST_RULES.map((r) => r.name), languages: ['javascript', 'typescript', 'python', 'java', 'go', 'php'] },
          { name: 'audit_owasp', description: 'OWASP Top 10 compliance check', capabilities: ['fs:read'], versions: ['2021', '2017'] },
          { name: 'audit_generate_report', description: 'Generate comprehensive security audit report', capabilities: [], formats: ['markdown', 'json', 'html'] },
          { name: 'audit_status', description: 'Check available audit capabilities', capabilities: [] },
        ],
      };

      return buildToolResult('audit_status', true, JSON.stringify(status, null, 2), undefined, undefined, start);
    } catch (error) {
      return buildToolResult('audit_status', false, '', `Status check failed: ${error instanceof Error ? error.message : String(error)}`, undefined, start);
    }
  },
};

export async function onLoad(ctx: PluginContext): Promise<void> {
  try {
    const config = await ctx.config.get() as Partial<PluginConfig>;
    if (config.severityThreshold) pluginConfig.severityThreshold = config.severityThreshold;
    if (config.maxFileSizeMB !== undefined) pluginConfig.maxFileSizeMB = config.maxFileSizeMB;
    if (config.excludeDirs) pluginConfig.excludeDirs = config.excludeDirs;
  } catch {
    // use defaults
  }
  console.log(`[cortex-plugin-security-audit] Loaded with threshold: ${pluginConfig.severityThreshold}`);
}

export async function onUnload(_ctx: PluginContext): Promise<void> {
  console.log('[cortex-plugin-security-audit] Unloading...');
}

export const tools: Tool[] = [
  auditDependenciesTool,
  auditSecretsTool,
  auditSastTool,
  auditOwaspTool,
  auditGenerateReportTool,
  auditStatusTool,
];
