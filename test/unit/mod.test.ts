// deno-lint-ignore-file require-await, no-unused-vars
import {
  assertEquals,
  assertExists,
  assertStringIncludes,
} from 'https://deno.land/std@0.208.0/assert/mod.ts';
import { tools } from '../../mod.ts';
import type { PluginContext } from '../../types.ts';

const mockContext: PluginContext = {
  pluginId: 'cortex-plugin-security-audit',
  pluginDir: '/tmp/plugins/cortex-plugin-security-audit',
  state: {
    get: async () => null,
    set: async () => {},
    delete: async () => {},
    list: async () => ({}),
  },
  config: {
    get: async () => ({
      severityThreshold: 'medium',
      maxFileSizeMB: 10,
      excludeDirs: 'node_modules,.git,dist,build,__pycache__',
    }),
    set: async () => {},
    getAll: async () => ({}),
  },
  logger: {
    info: () => {},
    warn: () => {},
    error: () => {},
    debug: () => {},
  },
  host: {
    registerTool: () => {},
    unregisterTool: () => {},
  },
};

function findTool(name: string) {
  return tools.find((t) => t.definition.name === name);
}

Deno.test('plugin exports correct number of tools', () => {
  assertEquals(tools.length, 6);
});

Deno.test('all tools are properly defined', () => {
  const expected = [
    'audit_dependencies',
    'audit_secrets',
    'audit_sast',
    'audit_owasp',
    'audit_generate_report',
    'audit_status',
  ];
  for (const name of expected) {
    const tool = findTool(name);
    assertExists(tool, `${name} tool not found`);
    assertExists(tool!.definition.name, `${name} tool missing name`);
    assertExists(tool!.definition.description, `${name} tool missing description`);
  }
});

Deno.test('audit_dependencies - requires project_path', async () => {
  const tool = findTool('audit_dependencies');
  const result = await tool!.execute({ project_path: '', package_manager: 'npm' }, mockContext);
  assertEquals(result.success, false);
  assertStringIncludes(result.error!, 'non-empty string');
});

Deno.test('audit_dependencies - succeeds with valid path', async () => {
  const tool = findTool('audit_dependencies');
  const result = await tool!.execute(
    { project_path: '/tmp/test-project', package_manager: 'npm' },
    mockContext,
  );
  assertEquals(result.success, true);
  const data = JSON.parse(result.output);
  assertExists(data.findings);
  assertExists(data.packageManager);
});

Deno.test('audit_dependencies - markdown output format', async () => {
  const tool = findTool('audit_dependencies');
  const result = await tool!.execute(
    { project_path: '/tmp/test-project', package_manager: 'npm', output_format: 'markdown' },
    mockContext,
  );
  assertEquals(result.success, true);
  assertStringIncludes(result.output, '#');
});

Deno.test('audit_secrets - requires target_path', async () => {
  const tool = findTool('audit_secrets');
  const result = await tool!.execute({ target_path: '' }, mockContext);
  assertEquals(result.success, false);
  assertStringIncludes(result.error!, 'non-empty string');
});

Deno.test('audit_secrets - succeeds with valid path', async () => {
  const tool = findTool('audit_secrets');
  const result = await tool!.execute({ target_path: '/tmp/test-project' }, mockContext);
  assertEquals(result.success, true);
  const data = JSON.parse(result.output);
  assertExists(data.findings);
  assertExists(data.filesScanned);
});

Deno.test('audit_secrets - respects exclude_dirs', async () => {
  const tool = findTool('audit_secrets');
  const result = await tool!.execute(
    { target_path: '/tmp/test-project', exclude_dirs: 'node_modules,secrets' },
    mockContext,
  );
  assertEquals(result.success, true);
});

Deno.test('audit_sast - requires target_path and language', async () => {
  const tool = findTool('audit_sast');
  const result1 = await tool!.execute({ target_path: '', language: 'javascript' }, mockContext);
  assertEquals(result1.success, false);

  const result2 = await tool!.execute({ target_path: '/src', language: '' }, mockContext);
  assertEquals(result2.success, false);
});

Deno.test('audit_sast - rejects unsupported language', async () => {
  const tool = findTool('audit_sast');
  const result = await tool!.execute({ target_path: '/src', language: 'cobol' }, mockContext);
  assertEquals(result.success, false);
  assertStringIncludes(result.error!, 'Unsupported language');
});

Deno.test('audit_sast - succeeds for supported languages', async () => {
  const tool = findTool('audit_sast');
  for (const lang of ['javascript', 'typescript', 'python', 'java', 'go', 'php']) {
    const result = await tool!.execute({ target_path: '/src', language: lang }, mockContext);
    assertEquals(result.success, true, `Failed for language: ${lang}`);
    const data = JSON.parse(result.output);
    assertExists(data.findings);
    assertExists(data.rulesApplied);
  }
});

Deno.test('audit_sast - respects rules filter', async () => {
  const tool = findTool('audit_sast');
  const result = await tool!.execute(
    { target_path: '/src', language: 'python', rules: 'injection' },
    mockContext,
  );
  assertEquals(result.success, true);
  const data = JSON.parse(result.output);
  assertEquals(data.rulesApplied.length, 2);
});

Deno.test('audit_owasp - requires target_path', async () => {
  const tool = findTool('audit_owasp');
  const result = await tool!.execute({ target_path: '' }, mockContext);
  assertEquals(result.success, false);
});

Deno.test('audit_owasp - defaults to 2021', async () => {
  const tool = findTool('audit_owasp');
  const result = await tool!.execute({ target_path: '/tmp/test-project' }, mockContext);
  assertEquals(result.success, true);
  const data = JSON.parse(result.output);
  assertEquals(data.owaspVersion, '2021');
  assertEquals(data.categoriesChecked, 10);
});

Deno.test('audit_owasp - supports 2017', async () => {
  const tool = findTool('audit_owasp');
  const result = await tool!.execute(
    { target_path: '/tmp/test-project', year: '2017' },
    mockContext,
  );
  assertEquals(result.success, true);
  const data = JSON.parse(result.output);
  assertEquals(data.owaspVersion, '2017');
});

Deno.test('audit_generate_report - requires findings', async () => {
  const tool = findTool('audit_generate_report');
  const result = await tool!.execute({ findings: '' }, mockContext);
  assertEquals(result.success, false);
});

Deno.test('audit_generate_report - invalid JSON fails', async () => {
  const tool = findTool('audit_generate_report');
  const result = await tool!.execute({ findings: 'not valid json' }, mockContext);
  assertEquals(result.success, false);
});

Deno.test('audit_generate_report - markdown format', async () => {
  const tool = findTool('audit_generate_report');
  const findings = JSON.stringify([
    {
      id: 'TEST-1',
      tool: 'audit_secrets',
      severity: 'high',
      title: 'Test Finding',
      description: 'A test finding',
      file: '/src/test.ts',
      line: 42,
      remediation: 'Fix it',
    },
  ]);
  const result = await tool!.execute({ findings }, mockContext);
  assertEquals(result.success, true);
  assertStringIncludes(result.output, '# Security Audit Report');
  assertStringIncludes(result.output, 'Test Finding');
});

Deno.test('audit_generate_report - html format', async () => {
  const tool = findTool('audit_generate_report');
  const findings = JSON.stringify([
    { id: 'T-1', tool: 'test', severity: 'critical', title: 'C', description: 'desc' },
  ]);
  const result = await tool!.execute({ findings, format: 'html' }, mockContext);
  assertEquals(result.success, true);
  assertStringIncludes(result.output, '<!DOCTYPE html>');
  assertStringIncludes(result.output, 'badge-critical');
});

Deno.test('audit_generate_report - json format', async () => {
  const tool = findTool('audit_generate_report');
  const findings = JSON.stringify([
    { id: 'T-1', tool: 'test', severity: 'high', title: 'H', description: 'desc' },
  ]);
  const result = await tool!.execute({ findings, format: 'json' }, mockContext);
  assertEquals(result.success, true);
  const data = JSON.parse(result.output);
  assertEquals(data.totalFindings, 1);
  assertExists(data.totalRiskScore);
});

Deno.test('audit_generate_report - exclude remediation', async () => {
  const tool = findTool('audit_generate_report');
  const findings = JSON.stringify([
    {
      id: 'T-1',
      tool: 'test',
      severity: 'low',
      title: 'L',
      description: 'desc',
      remediation: 'Some fix',
    },
  ]);
  const result = await tool!.execute(
    { findings, include_remediation: false, format: 'json' },
    mockContext,
  );
  assertEquals(result.success, true);
  const data = JSON.parse(result.output);
  assertEquals(data.findings[0].remediation, undefined);
});

Deno.test('audit_status - returns status object', async () => {
  const tool = findTool('audit_status');
  const result = await tool!.execute({}, mockContext);
  assertEquals(result.success, true);
  const data = JSON.parse(result.output);
  assertEquals(data.plugin, 'cortex-plugin-security-audit');
  assertEquals(data.version, '1.0.0');
  assertEquals(data.tools.length, 6);
  assertExists(data.config);
});

Deno.test('tool results include durationMs', async () => {
  for (const tool of tools) {
    const params: Record<string, unknown> = {};
    if (tool.definition.name === 'audit_dependencies') {
      params.project_path = '/tmp/test';
    } else if (tool.definition.name === 'audit_secrets') {
      params.target_path = '/tmp/test';
    } else if (tool.definition.name === 'audit_sast') {
      params.target_path = '/tmp/test';
      params.language = 'javascript';
    } else if (tool.definition.name === 'audit_owasp') {
      params.target_path = '/tmp/test';
    } else if (tool.definition.name === 'audit_generate_report') {
      params.findings = JSON.stringify([{
        id: 'X',
        tool: 'x',
        severity: 'low',
        title: 'X',
        description: 'x',
      }]);
    }
    const result = await tool.execute(params, mockContext);
    assertExists(result.durationMs, `${tool.definition.name} missing durationMs`);
    assertEquals(typeof result.durationMs, 'number');
  }
});
