// V0.4: structured security architecture model.
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const Module = require('module');
const { makeProject, OUT } = require('./helpers');
const { analyzeProject } = require(path.join(OUT, 'analyzeProject.js'));
const { buildArchitectureModel, emptyArchitectureModel, summarizeArchitecture } = require(path.join(OUT, 'architecture', 'architectureModelBuilder.js'));
const { matchDependencyRule, normalizePackageName, isRoleBearingCategory, databaseLabelForImage } = require(path.join(OUT, 'architecture', 'architectureRules.js'));
const { formatArchitectureReport, formatArchitectureSummary } = require(path.join(OUT, 'architecture', 'formatArchitectureModel.js'));
const { COMPONENT_TYPES, RELATIONSHIP_TYPES } = require(path.join(OUT, 'architecture', 'types.js'));

async function model(files) {
  const r = await analyzeProject(makeProject(files), 'proj');
  return r.architecture;
}
const byType = (m, type) => m.components.filter((c) => c.type === type);
const comp = (m, name, type) => m.components.find((c) => c.name === name && (!type || c.type === type));
const rels = (m, type) => m.relationships.filter((r) => r.type === type);
const rel = (m, type, srcName, dstName) => {
  const id = (n) => m.components.find((c) => c.name === n)?.id;
  return m.relationships.find((r) => r.type === type && r.sourceId === id(srcName) && r.targetId === id(dstName));
};

/* ------------------------------ structure & types ------------------------------ */

test('component and relationship vocabularies match the spec', () => {
  assert.deepStrictEqual([...COMPONENT_TYPES],
    ['Application', 'Frontend', 'Backend', 'Database', 'External Service', 'Container', 'Library/Dependency', 'Unknown']);
  // Every relationship type is a declaration; no runtime-traffic type exists.
  assert.ok(!RELATIONSHIP_TYPES.some((t) => /connect|call|request|traffic|send|reads|writes/.test(t)), RELATIONSHIP_TYPES.join(','));
});

/* ------------------------------ empty / insufficient evidence ------------------------------ */

test('empty workspace: only the Application component, no relationships, uncertainty recorded, no crash', async () => {
  const m = await model({});
  assert.strictEqual(m.components.length, 1);
  assert.strictEqual(m.relationships.length, 0);
  const app = m.components[0];
  assert.strictEqual(app.type, 'Application');
  assert.strictEqual(app.name, 'proj');
  assert.strictEqual(app.certainty, 'inferred');
  assert.ok(app.uncertainty.some((u) => /No project manifest/.test(u)));
  assert.ok(app.uncertainty.some((u) => /not determined/.test(u)));
  assert.strictEqual(app.evidence[0].rule, 'workspace-root');
  assert.strictEqual(app.evidence[0].source, '.');
});

test('workspace with files but no manifests: Application only', async () => {
  const m = await model({ 'src/a.txt': 'x', 'README.md': 'x' });
  assert.strictEqual(m.components.length, 1);
  assert.strictEqual(m.relationships.length, 0);
});

test('manifest with zero dependencies adds no library components or relationships', async () => {
  const m = await model({ 'package.json': '{}' });
  assert.strictEqual(m.components.length, 1);
  assert.strictEqual(m.relationships.length, 0);
});

test('unrecognised dependencies become Library/Dependency only; no role is invented', async () => {
  const m = await model({ 'package.json': JSON.stringify({ dependencies: { 'left-pad': '^1.3.0', lodash: '4.17.21' } }) });
  assert.deepStrictEqual(m.components.map((c) => c.type).sort(), ['Application', 'Library/Dependency', 'Library/Dependency']);
  assert.deepStrictEqual(m.relationships.map((r) => r.type), ['declares-dependency', 'declares-dependency']);
});

/* ------------------------------ Application + libraries + versions ------------------------------ */

test('Application component carries workspace name, ecosystems, runtime technology and manifest evidence', async () => {
  const m = await model({ 'package.json': JSON.stringify({ dependencies: { 'left-pad': '1' }, engines: { node: '>=18' } }) });
  const app = byType(m, 'Application')[0];
  assert.deepStrictEqual(app.ecosystems, ['Node.js']);
  assert.ok(app.evidence.some((e) => e.rule === 'project-manifest' && e.source === 'package.json'));
  const node = app.technologies.find((t) => t.name === 'Node.js');
  assert.deepStrictEqual([node.version, node.kind, node.source], ['>=18', 'runtime', 'package.json']);
  assert.ok(app.evidence.some((e) => e.kind === 'technology-declaration' && e.detail.version === '>=18'));
});

test('declared versions are preserved exactly (ranges, v-prefix, properties, null, empty)', async () => {
  const m = await model({
    'package.json': JSON.stringify({ dependencies: { a: '^4.18.2', b: '~2.31.0', c: '>=3.0.0 <4', d: 'v1.2.3', e: '1.2.3', f: '' }, devDependencies: { g: '*' } }),
    'requirements.txt': 'flask>=3.0.0\nrequests==2.31.0\npandas\n',
    'go.mod': 'module x\nrequire github.com/a/b v1.2.3-0.20230101-abcdef // indirect\n',
    'pom.xml': '<project><properties><v>9.9</v></properties><dependencies><dependency><groupId>g</groupId><artifactId>x</artifactId><version>${v}</version></dependency></dependencies></project>',
  });
  const v = (name) => comp(m, name, 'Library/Dependency').technologies[0];
  assert.strictEqual(v('a').version, '^4.18.2');
  assert.strictEqual(v('b').version, '~2.31.0');
  assert.strictEqual(v('c').version, '>=3.0.0 <4');
  assert.strictEqual(v('d').version, 'v1.2.3');
  assert.strictEqual(v('e').version, '1.2.3');
  assert.strictEqual(v('f').version, '');
  assert.strictEqual(v('g').version, '*');
  assert.strictEqual(v('g').category, 'devDependencies');
  assert.strictEqual(v('flask').version, '>=3.0.0');
  assert.strictEqual(v('requests').version, '==2.31.0');
  assert.strictEqual(v('pandas').version, null);
  assert.strictEqual(v('github.com/a/b').version, 'v1.2.3-0.20230101-abcdef');
  assert.strictEqual(v('g:x').version, '${v}');
  assert.strictEqual(v('g:x').resolvedVersion, '9.9');
});

test('the same package declared in two manifests yields two separate declarations, each with its own version', async () => {
  const m = await model({
    'package.json': JSON.stringify({ dependencies: { shared: '^1.0.0' } }),
    'web/package.json': JSON.stringify({ dependencies: { shared: '^2.0.0' } }),
  });
  const libs = m.components.filter((c) => c.name === 'shared');
  assert.strictEqual(libs.length, 2);
  assert.deepStrictEqual(libs.map((l) => l.technologies[0].version).sort(), ['^1.0.0', '^2.0.0']);
  assert.notStrictEqual(libs[0].id, libs[1].id);
});

test('multiple constraints for one package (Poetry) are kept on one component, each exact', async () => {
  const m = await model({ 'pyproject.toml': '[tool.poetry.dependencies]\nmulti = [{ version = "^1.0" }, { version = "^2.0" }]\n' });
  const multi = comp(m, 'multi');
  assert.deepStrictEqual(multi.technologies.map((t) => t.version), ['^1.0', '^2.0']);
  assert.strictEqual(multi.evidence.length, 2);
  assert.strictEqual(rels(m, 'declares-dependency').length, 1, 'one relationship, two pieces of evidence');
  assert.strictEqual(rels(m, 'declares-dependency')[0].evidence.length, 2);
});

/* ------------------------------ role inference ------------------------------ */

test('react + express => Frontend and Backend inside the Application; NO relationship between them', async () => {
  const m = await model({ 'package.json': JSON.stringify({ dependencies: { react: '^18.2.0', 'react-dom': '^18.2.0', express: '^4.18.2' } }) });
  const fe = byType(m, 'Frontend')[0];
  const be = byType(m, 'Backend')[0];
  assert.strictEqual(fe.name, 'Frontend (React)');
  assert.strictEqual(be.name, 'Backend (Express)');
  assert.strictEqual(fe.certainty, 'inferred');
  assert.deepStrictEqual(fe.technologies.map((t) => `${t.name}@${t.version}`), ['react@^18.2.0', 'react-dom@^18.2.0']);
  assert.ok(rel(m, 'contains', 'proj', fe.name));
  assert.ok(rel(m, 'contains', 'proj', be.name));
  assert.ok(rel(m, 'built-with', fe.name, 'react'));
  assert.ok(rel(m, 'built-with', be.name, 'express'));
  assert.ok(!m.relationships.some((r) => (r.sourceId === fe.id && r.targetId === be.id) || (r.sourceId === be.id && r.targetId === fe.id)));
  assert.ok(fe.uncertainty.length > 0 && be.uncertainty.length > 0);
  assert.ok(fe.evidence.every((e) => e.rule === 'frontend-framework-dependency' && e.source === 'package.json'));
});

test('dev-only / transitive / test dependencies never trigger a role (library component still exists)', async () => {
  const m = await model({
    'package.json': JSON.stringify({ devDependencies: { react: '^18', express: '^4', pg: '^8' } }),
    'go.mod': 'module x\nrequire github.com/gin-gonic/gin v1.9.1 // indirect\n',
    'Cargo.toml': '[dev-dependencies]\naxum = "0.7"\n',
  });
  assert.strictEqual(byType(m, 'Frontend').length + byType(m, 'Backend').length + byType(m, 'Database').length, 0);
  for (const n of ['react', 'express', 'pg', 'github.com/gin-gonic/gin', 'axum']) assert.ok(comp(m, n, 'Library/Dependency'), n);
});

test('database client library => inferred Database linked ONLY from the library, never directly from the application', async () => {
  const m = await model({ 'package.json': JSON.stringify({ dependencies: { pg: '^8.11.0', 'pg-promise': '^11.0.0', mysql2: '^3.0.0' } }) });
  const dbs = byType(m, 'Database');
  assert.deepStrictEqual(dbs.map((d) => d.name).sort(), ['MySQL', 'PostgreSQL']);
  const pgDb = comp(m, 'PostgreSQL', 'Database');
  assert.strictEqual(pgDb.certainty, 'inferred');
  assert.strictEqual(pgDb.technologies.length, 2, 'both Postgres drivers listed on one component');
  assert.ok(rel(m, 'client-library-for', 'pg', 'PostgreSQL'));
  assert.ok(rel(m, 'client-library-for', 'pg-promise', 'PostgreSQL'));
  assert.ok(!m.relationships.some((r) => r.targetId === pgDb.id && r.sourceId.startsWith('app:')), 'no application -> database edge');
  assert.ok(pgDb.uncertainty.some((u) => /not determined/.test(u)));
});

test('external service SDK => inferred External Service', async () => {
  const m = await model({ 'package.json': JSON.stringify({ dependencies: { stripe: '^14.0.0', '@aws-sdk/client-s3': '^3.0.0', '@aws-sdk/client-sqs': '^3.0.0' } }) });
  assert.deepStrictEqual(byType(m, 'External Service').map((c) => c.name).sort(), ['AWS', 'Stripe']);
  assert.strictEqual(comp(m, 'AWS').technologies.length, 2);
  assert.ok(rel(m, 'client-library-for', 'stripe', 'Stripe'));
  assert.ok(comp(m, 'Stripe').uncertainty.some((u) => /not determined/.test(u)));
});

test('ORMs do not identify a database, so no Database is inferred', async () => {
  const m = await model({ 'package.json': JSON.stringify({ dependencies: { sequelize: '^6', typeorm: '^0.3', '@prisma/client': '^5' } }) });
  assert.strictEqual(byType(m, 'Database').length, 0);
});

/* ------------------------------ Docker ------------------------------ */

test('Dockerfile base images => Container components + builds-on-image (stages merged, stage refs and scratch skipped)', async () => {
  const m = await model({
    'package.json': '{}',
    Dockerfile: 'FROM node:20-alpine AS build\nFROM build AS test\nFROM scratch AS e\nFROM nginx:1.25\nFROM node:20-alpine\n',
  });
  const containers = byType(m, 'Container');
  assert.deepStrictEqual(containers.map((c) => c.name), ['node:20-alpine', 'nginx:1.25']);
  assert.strictEqual(containers[0].certainty, 'declared');
  assert.strictEqual(containers[0].technologies[0].version, '20-alpine');
  assert.strictEqual(rels(m, 'builds-on-image').length, 2);
  assert.strictEqual(rel(m, 'builds-on-image', 'proj', 'node:20-alpine').evidence.length, 2, 'two FROM lines, one relationship, both as evidence');
  assert.ok(containers.every((c) => c.evidence.every((e) => e.rule === 'dockerfile-base-image' && e.source === 'Dockerfile')));
});

test('compose: database images => Database; others => Container with unknown role; build-only service omitted', async () => {
  const m = await model({
    'docker-compose.yml': 'services:\n  db:\n    image: postgres:16\n  cache:\n    image: redis:7.2\n  proxy:\n    image: nginx:1.25\n  web:\n    build: .\n',
  });
  assert.strictEqual(comp(m, 'db').type, 'Database');
  assert.strictEqual(comp(m, 'db').certainty, 'inferred');
  assert.strictEqual(comp(m, 'cache').type, 'Database');
  assert.strictEqual(comp(m, 'proxy').type, 'Container');
  assert.strictEqual(comp(m, 'proxy').certainty, 'declared');
  assert.ok(comp(m, 'proxy').uncertainty.some((u) => /role .* not determined/.test(u)));
  assert.ok(comp(m, 'db').uncertainty.some((u) => /how the application connects/.test(u)));
  assert.strictEqual(comp(m, 'web'), undefined);
  assert.strictEqual(rels(m, 'declares-service').length, 3);
  assert.strictEqual(comp(m, 'db').technologies[0].version, '16');
  assert.strictEqual(comp(m, 'db').evidence[0].rule, 'compose-database-image');
});

test('app + compose database: NO connection is invented between them (even with a matching driver)', async () => {
  const m = await model({
    'package.json': JSON.stringify({ dependencies: { pg: '^8' } }),
    'docker-compose.yml': 'services:\n  db:\n    image: postgres:16\n',
  });
  const composeDb = comp(m, 'db', 'Database');
  const driverDb = comp(m, 'PostgreSQL', 'Database');
  assert.notStrictEqual(composeDb.id, driverDb.id, 'not merged: nothing links the app to that service');
  const allowed = new Set(['declares-service']);
  assert.ok(m.relationships.filter((r) => r.targetId === composeDb.id).every((r) => allowed.has(r.type)));
  assert.ok(!m.relationships.some((r) => r.sourceId === driverDb.id && r.targetId === composeDb.id));
});

test('variables / missing tags are recorded as uncertainty, not resolved or invented', async () => {
  const m = await model({ Dockerfile: 'FROM node:${V}\nFROM nginx\n', 'compose.yml': 'services:\n  x:\n    image: ${REGISTRY}/app:${TAG}\n' });
  assert.ok(comp(m, 'node:${V}').uncertainty.some((u) => /variable/.test(u)));
  assert.strictEqual(comp(m, 'nginx').technologies[0].version, null);
  assert.ok(comp(m, 'x').uncertainty.some((u) => /variable/.test(u)));
});

/* ------------------------------ monorepo / modules ------------------------------ */

test('sub-directory manifests become Unknown modules contained by the Application; deps attach to the right module', async () => {
  const m = await model({
    'package.json': JSON.stringify({ dependencies: { express: '^4' } }),
    'api/requirements.txt': 'flask>=3.0.0\n',
    'api/Dockerfile': 'FROM python:3.12\n',
    'svc/go.mod': 'module x\ngo 1.21\nrequire github.com/gin-gonic/gin v1.9.1\n',
    'deploy/Dockerfile': 'FROM alpine:3.19\n',
  });
  const api = comp(m, 'api'), svc = comp(m, 'svc');
  assert.strictEqual(api.type, 'Unknown');
  assert.strictEqual(api.certainty, 'unknown');
  assert.ok(api.uncertainty.some((u) => /not determined/.test(u)));
  assert.deepStrictEqual(api.ecosystems, ['Python']);
  assert.ok(rel(m, 'contains', 'proj', 'api'));
  assert.ok(rel(m, 'contains', 'proj', 'svc'));
  assert.ok(rel(m, 'declares-dependency', 'api', 'flask'));
  assert.ok(rel(m, 'declares-dependency', 'proj', 'express'));
  assert.ok(!rel(m, 'declares-dependency', 'proj', 'flask'));
  assert.ok(rel(m, 'builds-on-image', 'api', 'python:3.12'), 'api/Dockerfile belongs to api');
  assert.ok(rel(m, 'builds-on-image', 'proj', 'alpine:3.19'), 'deploy/Dockerfile has no module; falls back to the root application');
  assert.ok(!comp(m, 'deploy'));
  assert.strictEqual(byType(m, 'Backend').length, 3, 'Express in root, Flask in api, Gin in svc');
  assert.strictEqual(svc.technologies.find((t) => t.name === 'Go').version, '1.21');
});

test('nested modules are contained by their nearest module', async () => {
  const m = await model({ 'web/package.json': '{}', 'web/packages/ui/package.json': '{}' });
  assert.ok(rel(m, 'contains', 'proj', 'web'));
  assert.ok(rel(m, 'contains', 'web', 'web/packages/ui'));
  assert.ok(!rel(m, 'contains', 'proj', 'web/packages/ui'));
});

test('root with no manifest but sub-modules records the missing-root-manifest uncertainty', async () => {
  const m = await model({ 'svc/go.mod': 'module x\n' });
  assert.ok(byType(m, 'Application')[0].uncertainty.some((u) => /No project manifest/.test(u)));
});

/* ------------------------------ parse errors ------------------------------ */

test('malformed manifest: module still exists, uncertainty + warning recorded, other manifests unaffected', async () => {
  const m = await model({
    'package.json': '{ "dependencies": ',
    'good/package.json': JSON.stringify({ dependencies: { lodash: '^4' } }),
    'bad/Cargo.toml': '[dependencies\n',
  });
  assert.ok(byType(m, 'Application')[0].uncertainty.some((u) => /package\.json could not be read/.test(u)));
  assert.ok(comp(m, 'bad').uncertainty.some((u) => /Cargo\.toml could not be read/.test(u)));
  assert.ok(m.warnings.some((w) => /bad\/Cargo\.toml/.test(w)));
  assert.ok(rel(m, 'declares-dependency', 'good', 'lodash'));
  assert.ok(!JSON.stringify(m).includes('"dependencies": '), 'no file content in the model');
});

test('partially parsed manifest is flagged on its module', async () => {
  const m = await model({ 'requirements.txt': 'flask>=3\ngit+https://example.com/x.git\n' });
  assert.ok(byType(m, 'Application')[0].uncertainty.some((u) => /partially read/.test(u)));
});

/* ------------------------------ identifiers ------------------------------ */

const FULL = {
  'package.json': JSON.stringify({ dependencies: { react: '^18', express: '^4', pg: '^8', stripe: '^14' }, devDependencies: { jest: '^29' } }),
  'api/requirements.txt': 'flask>=3\nredis==5\n',
  Dockerfile: 'FROM node:20 AS b\nFROM nginx:1\n',
  'docker-compose.yml': 'services:\n  db:\n    image: postgres:16\n  q:\n    image: rabbitmq:3\n',
};

test('identifiers are unique, non-empty, and relationships only reference existing components', async () => {
  const m = await model(FULL);
  const ids = m.components.map((c) => c.id);
  assert.strictEqual(new Set(ids).size, ids.length);
  assert.ok(ids.every((i) => typeof i === 'string' && i.length > 0));
  const rids = m.relationships.map((r) => r.id);
  assert.strictEqual(new Set(rids).size, rids.length);
  const known = new Set(ids);
  for (const r of m.relationships) {
    assert.ok(known.has(r.sourceId) && known.has(r.targetId), r.id);
    assert.notStrictEqual(r.sourceId, r.targetId);
  }
});

test('identifiers and ordering are deterministic across runs and independent of absolute path', async () => {
  const a = await model(FULL);
  const b = await model(FULL); // different temp directory
  const strip = (m) => JSON.stringify({ components: m.components, relationships: m.relationships, warnings: m.warnings });
  assert.strictEqual(strip(a), strip(b));
});

/* ------------------------------ evidence / traceability ------------------------------ */

test('every component and relationship has evidence with a workspace-relative source and a known rule', async () => {
  const r = await analyzeProject(makeProject(FULL), 'proj');
  const m = r.architecture;
  const knownFiles = new Set([...r.scan.files, '.']);
  const rules = new Set(Object.values(require(path.join(OUT, 'architecture', 'architectureRules.js')).RULE_IDS));
  const check = (what, evidence) => {
    assert.ok(evidence.length >= 1, `${what} has no evidence`);
    for (const e of evidence) {
      assert.ok(knownFiles.has(e.source), `${what}: source ${e.source} is not a scanned file`);
      assert.ok(!path.isAbsolute(e.source) && !/^[A-Za-z]:/.test(e.source), `${what}: absolute path in evidence`);
      assert.ok(rules.has(e.rule), `${what}: unknown rule ${e.rule}`);
      assert.ok(e.description.length > 0);
    }
  };
  m.components.forEach((c) => check(`component ${c.id}`, c.evidence));
  m.relationships.forEach((rl) => check(`relationship ${rl.id}`, rl.evidence));
});

test('evidence detail reproduces the declared name/version/category exactly (traceable to the manifest entry)', async () => {
  const m = await model({ 'package.json': JSON.stringify({ dependencies: { express: '^4.18.2' } }) });
  const express = comp(m, 'Backend (Express)');
  const e = express.evidence[0];
  assert.deepStrictEqual(e.detail, { name: 'express', version: '^4.18.2', category: 'dependencies' });
  assert.strictEqual(e.source, 'package.json');
  const lib = rel(m, 'declares-dependency', 'proj', 'express');
  assert.deepStrictEqual(lib.evidence[0].detail, { name: 'express', version: '^4.18.2', category: 'dependencies' });
});

/* ------------------------------ secrets ------------------------------ */

test('secrets and environment values never reach the model or the report', async () => {
  const files = {
    'docker-compose.yml': 'services:\n  db:\n    image: postgres:16\n    environment:\n      POSTGRES_PASSWORD: SECRET_ENV_VALUE_1\n      API_KEY=SECRET_ENV_VALUE_2\n    env_file: .env\n',
    Dockerfile: 'FROM node:20\nENV TOKEN=SECRET_ENV_VALUE_3\nARG NPM_TOKEN=SECRET_ENV_VALUE_4\n',
    '.env': 'DB_PASSWORD=SECRET_ENV_VALUE_5\n',
    'requirements.txt': '--index-url https://user:SECRET_ENV_VALUE_6@pypi.example.com/simple\nflask==3\n',
  };
  const r = await analyzeProject(makeProject(files), 'proj');
  const blob = JSON.stringify(r.architecture) + formatArchitectureReport(r.architecture).join('\n');
  assert.ok(!/SECRET_ENV_VALUE/.test(blob));
});

test('credentials embedded in an image reference are redacted; tag+digest references are not damaged', () => {
  const scan = { workspaceName: 'p', workspacePath: '/p', projectTypes: ['Docker'], fileCount: 1, directoryCount: 0, configurationFiles: ['Dockerfile'], files: ['Dockerfile'], directories: [], excludedDirectories: [], warnings: [], truncated: false };
  const tech = (reference, name, version) => ({ name, version, ecosystem: 'Docker', source: 'Dockerfile', reference, scope: { kind: 'build-stage', index: 1 } });
  const inv = { dependencies: [], sources: [{ path: 'Dockerfile', ecosystem: 'Docker', status: 'parsed', dependencyCount: 0, technologyCount: 2 }], warnings: [],
    technologies: [tech('user:hunter2@registry.example.com/team/app:1', 'user', null), tech('node:20@sha256:abc123', 'node', '20')] };
  const m = buildArchitectureModel(scan, inv);
  assert.ok(!JSON.stringify(m).includes('hunter2'));
  assert.ok(m.components.some((c) => c.name === 'node:20@sha256:abc123'), 'digest reference untouched');
});

/* ------------------------------ builder robustness (fabricated inputs) ------------------------------ */

test('builder tolerates a truncated scan and records a model warning', () => {
  const scan = { workspaceName: 'p', workspacePath: '/p', projectTypes: [], fileCount: 0, directoryCount: 0, configurationFiles: [], files: [], directories: [], excludedDirectories: [], warnings: [], truncated: true };
  const m = buildArchitectureModel(scan, { dependencies: [], technologies: [], sources: [], warnings: [] });
  assert.ok(m.warnings.some((w) => /truncated/.test(w)));
});

test('emptyArchitectureModel carries the warning and formats without error', () => {
  const m = emptyArchitectureModel('p', 'boom');
  assert.deepStrictEqual([m.components.length, m.relationships.length, m.warnings], [0, 0, ['boom']]);
  assert.match(formatArchitectureReport(m).join('\n'), /Architecture model is empty\./);
});

test('analyzeProject survives a failing model builder (V0.2/V0.3 results kept)', async () => {
  const builderPath = path.join(OUT, 'architecture', 'architectureModelBuilder.js');
  const real = require(builderPath);
  const originalBuild = real.buildArchitectureModel;
  Object.defineProperty(real, 'buildArchitectureModel', { value: () => { throw new Error('simulated failure'); }, configurable: true });
  try {
    const r = await analyzeProject(makeProject({ 'package.json': JSON.stringify({ dependencies: { a: '1' } }) }), 'p');
    assert.strictEqual(r.technology.dependencies.length, 1);
    assert.strictEqual(r.scan.fileCount, 1);
    assert.strictEqual(r.architecture.components.length, 0);
    assert.match(r.architecture.warnings[0], /simulated failure/);
  } finally {
    Object.defineProperty(real, 'buildArchitectureModel', { value: originalBuild, configurable: true });
  }
});

/* ------------------------------ rules ------------------------------ */

test('rule matching: normalisation, categories, image labels', () => {
  assert.strictEqual(normalizePackageName('Python', 'Psycopg2_Binary'), 'psycopg2-binary');
  assert.strictEqual(matchDependencyRule({ name: 'Flask', ecosystem: 'Python', category: 'requirements' }).label, 'Flask');
  assert.strictEqual(matchDependencyRule({ name: 'psycopg2_binary', ecosystem: 'Python', category: 'dependencies' }).label, 'PostgreSQL');
  assert.strictEqual(matchDependencyRule({ name: 'react', ecosystem: 'Python', category: 'dependencies' }), undefined, 'ecosystem must match');
  assert.strictEqual(matchDependencyRule({ name: 'org.springframework.boot:spring-boot-starter-webflux', ecosystem: 'Java', category: 'implementation' }).label, 'Spring Web');
  assert.strictEqual(matchDependencyRule({ name: 'express', ecosystem: 'Node.js', category: 'devDependencies' }), undefined);
  for (const c of ['devDependencies', 'peerDependencies', 'dev-packages', 'test', 'testImplementation', 'require (indirect)', 'dependency-groups:lint', 'optional-dependencies:dev', 'group:test', 'build-system', 'target.cfg(unix).dev-dependencies']) {
    assert.strictEqual(isRoleBearingCategory(c), false, c);
  }
  for (const c of ['dependencies', 'requirements', 'implementation', 'compile', 'require', 'packages', 'workspace.dependencies', 'optionalDependencies']) {
    assert.strictEqual(isRoleBearingCategory(c), true, c);
  }
  assert.strictEqual(databaseLabelForImage('bitnami/postgresql'), 'PostgreSQL');
  assert.strictEqual(databaseLabelForImage('mcr.microsoft.com/mssql/server'), 'SQL Server');
  assert.strictEqual(databaseLabelForImage('postgres-exporter'), undefined);
  assert.strictEqual(databaseLabelForImage('nginx'), undefined);
});

/* ------------------------------ report / summary ------------------------------ */

test('summary counts agree with the model and the report states them', async () => {
  const m = await model(FULL);
  const s = summarizeArchitecture(m);
  assert.strictEqual(s.componentCount, m.components.length);
  assert.strictEqual(s.relationshipCount, m.relationships.length);
  assert.strictEqual(Object.values(s.componentsByType).reduce((a, b) => a + b, 0), m.components.length);
  assert.strictEqual(Object.values(s.relationshipsByType).reduce((a, b) => a + b, 0), m.relationships.length);
  const text = formatArchitectureReport(m).join('\n');
  assert.match(text, new RegExp(`Components \\(${s.componentCount}\\):`));
  assert.match(text, new RegExp(`Relationships \\(${s.relationshipCount}\\):`));
  assert.match(text, /\[Backend\] Backend \(Express\) \(inferred\)/);
  assert.match(text, /uncertainty: /);
  assert.match(text, /evidence: .*\[rule: /);
  assert.match(text, /NOT inferred/);
  assert.match(formatArchitectureSummary(m), new RegExp(`${s.componentCount} components, ${s.relationshipCount} relationships`));
  assert.match(formatArchitectureSummary(emptyArchitectureModel('p', 'x')), /0 components, 0 relationships/);
});

test('report caps very long listings', async () => {
  const deps = {};
  const compose = ['services:'];
  for (let i = 0; i < 80; i++) compose.push(`  s${i}:`, `    image: busybox:${i}`);
  const m = await model({ 'docker-compose.yml': compose.join('\n'), 'package.json': JSON.stringify({ dependencies: deps }) });
  const text = formatArchitectureReport(m).join('\n');
  assert.match(text, /and 2[0-9] more component\(s\) not listed/);
  assert.match(text, /and 2[0-9] more relationship\(s\) not listed/);
});

/* ------------------------------ command integration (mocked vscode) ------------------------------ */

test('Analyze Project command shows the architecture section and counts; no-workspace behaviour unchanged', async () => {
  const ui = { out: [], info: [], warn: [], err: [] };
  const state = { folders: undefined, handler: null };
  const vscodeMock = {
    window: {
      createOutputChannel: () => ({ appendLine: (l) => ui.out.push(l), clear: () => { ui.out.length = 0; }, show() {}, dispose() {} }),
      showInformationMessage: (m) => ui.info.push(m), showWarningMessage: (m) => ui.warn.push(m), showErrorMessage: (m) => ui.err.push(m),
    },
    workspace: { get workspaceFolders() { return state.folders; } },
    commands: { registerCommand: (id, h) => { assert.strictEqual(id, 'securityArchitectureAssessment.analyzeProject'); state.handler = h; return { dispose() {} }; } },
  };
  const originalLoad = Module._load;
  Module._load = function (request, ...rest) { return request === 'vscode' ? vscodeMock : originalLoad.call(this, request, ...rest); };
  try {
    delete require.cache[require.resolve(path.join(OUT, 'extension.js'))];
    require(path.join(OUT, 'extension.js')).activate({ subscriptions: [] });

    state.folders = undefined; await state.handler();
    assert.deepStrictEqual(ui.warn, ['Please open a workspace before running the security analysis.']);

    const root = makeProject(FULL);
    state.folders = [{ name: 'proj', uri: { scheme: 'file', fsPath: root } }];
    ui.out.length = 0; await state.handler();
    const text = ui.out.join('\n');
    assert.match(text, /Security Architecture Scan/);
    assert.match(text, /Technology \/ Dependency Detection/);
    assert.match(text, /Security Architecture Model/);
    assert.match(text, /Architecture model built successfully\./);
    assert.match(ui.info[ui.info.length - 1], /Architecture model: \d+ components, \d+ relationships\./);
    assert.strictEqual(ui.err.length, 0);

    state.folders = [{ name: 'empty', uri: { scheme: 'file', fsPath: makeProject({}) } }];
    ui.out.length = 0; await state.handler();
    assert.match(ui.out.join('\n'), /Components \(1\):/);
    assert.strictEqual(ui.err.length, 0);
  } finally {
    Module._load = originalLoad;
  }
});
