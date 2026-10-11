// V0.4 audit regression tests: one block per defect found in the audit (D1-D13) plus cross-cutting invariants.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const Module = require('module');
const { makeProject, OUT } = require('./helpers');
const { analyzeProject } = require(path.join(OUT, 'analyzeProject.js'));
const { sanitizeErrorMessage, redactAbsolutePaths, redactCredentials, stripControlCharacters } = require(path.join(OUT, 'common', 'sanitize.js'));
const { buildArchitectureModel } = require(path.join(OUT, 'architecture', 'architectureModelBuilder.js'));
const { databaseLabelForImage } = require(path.join(OUT, 'architecture', 'architectureRules.js'));
const { formatArchitectureReport } = require(path.join(OUT, 'architecture', 'formatArchitectureModel.js'));
const { formatTechnologyReport } = require(path.join(OUT, 'scanner', 'technology', 'formatTechnologyInventory.js'));
const { formatScanReport } = require(path.join(OUT, 'scanner', 'formatScanResult.js'));
const { COMPONENT_TYPES, RELATIONSHIP_TYPES } = require(path.join(OUT, 'architecture', 'types.js'));
const { RULE_IDS } = require(path.join(OUT, 'architecture', 'architectureRules.js'));

const allText = (r) => JSON.stringify(r.architecture) + JSON.stringify(r.technology) + [...formatScanReport(r.scan), ...formatTechnologyReport(r.technology), ...formatArchitectureReport(r.architecture)].join('\n');
const comp = (m, name) => m.components.find((c) => c.name === name);
const types = (m, t) => m.components.filter((c) => c.type === t);

/** Run the real command with a mocked vscode; returns what the user would see. */
async function runCommand(folders, { patch } = {}) {
  const ui = { out: [], info: [], warn: [], err: [] };
  let handler;
  const mock = {
    window: {
      createOutputChannel: () => ({ appendLine: (l) => ui.out.push(l), clear: () => { ui.out.length = 0; }, show() {}, dispose() {} }),
      showInformationMessage: (m) => ui.info.push(m), showWarningMessage: (m) => ui.warn.push(m), showErrorMessage: (m) => ui.err.push(m),
    },
    workspace: { workspaceFolders: folders },
    commands: { registerCommand: (id, h) => { handler = h; return { dispose() {} }; } },
  };
  const originalLoad = Module._load;
  Module._load = function (request, ...rest) { return request === 'vscode' ? mock : originalLoad.call(this, request, ...rest); };
  const restore = patch ? patch() : () => {};
  try {
    delete require.cache[require.resolve(path.join(OUT, 'extension.js'))];
    require(path.join(OUT, 'extension.js')).activate({ subscriptions: [] });
    await handler();
  } finally {
    restore();
    Module._load = originalLoad;
  }
  return ui;
}
const stub = (modulePath, name, impl) => () => {
  const mod = require(path.join(OUT, modulePath));
  const original = mod[name];
  Object.defineProperty(mod, name, { value: impl, configurable: true });
  return () => Object.defineProperty(mod, name, { value: original, configurable: true });
};

/* ---------------- D1: parse errors never echo file content ---------------- */
test('D1 invalid JSON: message carries only a position, never file content', async () => {
  const r = await analyzeProject(makeProject({ 'package.json': '{"k": hunter2-plaintext}', 'good/package.json': '{"dependencies":{"a":"1"}}' }), 'p');
  const src = r.technology.sources.find((s) => s.path === 'package.json');
  assert.strictEqual(src.status, 'error');
  assert.match(src.message, /^Invalid JSON \(syntax error/);
  assert.ok(!/hunter2|plaintext/.test(allText(r)));
  assert.strictEqual(r.technology.dependencies.length, 1, 'other manifests still parsed');
});

test('D1 invalid TOML / POM messages carry no file content either', async () => {
  const r = await analyzeProject(makeProject({ 'Cargo.toml': 'api_token = "TOPSECRET" junk\n', 'pyproject.toml': '[project\nkey="TOPSECRET2"', 'pom.xml': '<notapom>TOPSECRET3</notapom>' }), 'p');
  assert.ok(!/TOPSECRET/.test(allText(r)));
  assert.strictEqual(r.technology.sources.filter((s) => s.status === 'error').length, 3);
});

/* ---------------- D2/D4/D11: absolute paths never reach model, reports, toasts or logs ---------------- */
test('D2 sanitizeErrorMessage: POSIX, Windows, UNC and multi-line messages', () => {
  assert.strictEqual(sanitizeErrorMessage(new Error("EACCES: permission denied, open '/home/bob/proj/package.json'")), "EACCES: permission denied, open '<path>'");
  assert.strictEqual(sanitizeErrorMessage(new Error("EPERM: operation not permitted, open 'C:\\Users\\bob\\proj\\package.json'")), "EPERM: operation not permitted, open '<path>'");
  assert.strictEqual(sanitizeErrorMessage(new Error('ENOENT \\\\server\\share\\x.json')), 'ENOENT <path>');
  assert.strictEqual(sanitizeErrorMessage(new Error('first line\nsecond line /etc/passwd')), 'first line');
  assert.strictEqual(redactAbsolutePaths("Unexpected token '/'"), "Unexpected token '/'");
  assert.strictEqual(redactAbsolutePaths('read and/or write failed'), 'read and/or write failed');
  assert.strictEqual(sanitizeErrorMessage('plain string'), 'plain string');
});

test('D2b redactAbsolutePaths leaves ordinary text alone (quoted slashes, relative paths, URLs, prose)', () => {
  const keep = [
    "Unexpected token '/'", 'Unexpected token "/"', "Unexpected token '/*'", "Unexpected token '//'", 'Unexpected token "//comment"',
    'read and/or write failed', 'relative ./a/b and ../x/y and src/a.ts', 'see https://example.com/docs/x for details',
    'registry http://localhost:5000/v2/', 'protocol-relative //cdn.example.com/x', 'key a:/b is odd', 'ratio 3/4 and 10/12/2024',
    "unexpected '\\' here", 'plain text with no paths', '', 'a / b and / alone', 'git+ssh://git@github.com/org/repo.git',
  ];
  for (const text of keep) assert.strictEqual(redactAbsolutePaths(text), text, JSON.stringify(text));
});

test('D2b redactAbsolutePaths still redacts genuine POSIX, Windows-drive, UNC and file-URL paths', () => {
  const cases = [
    ["EACCES: permission denied, open '/home/bob/proj/package.json'", "EACCES: permission denied, open '<path>'"],
    ['at /home/bob/proj/x.js:10:5', 'at <path>'],
    ['path=/var/tmp/x', 'path=<path>'],
    ["open '/package.json'", "open '<path>'"],
    ['(/usr/lib/node_modules/x)', '(<path>)'],
    ['dir "/Users/bob/My Project/x" failed', 'dir "<path>" failed'],
    ["open '/Users/Bob Smith/My Project/package.json'", "open '<path>'"],
    ["EPERM open 'C:\\Users\\Bob Smith\\proj\\f.json'", "EPERM open '<path>'"],
    ["ENOENT '\\\\fileserver\\my share\\x.json'", "ENOENT '<path>'"], // space in the SHARE name (server names cannot contain spaces)
    ["EPERM open 'C:\\Users\\bob\\proj\\f.json'", "EPERM open '<path>'"],
    ['EPERM open c:\\users\\bob\\proj (VS Code style lowercase drive)', 'EPERM open <path> (VS Code style lowercase drive)'],
    ['open C:/Users/bob/p/f.json failed', 'open <path> failed'],
    ['ENOENT \\\\server\\share\\x.json', 'ENOENT <path>'],
    ['file:///home/bob/p/x.json', 'file://<path>'],
    ['file:///C:/Users/bob/x.json', 'file://<path>'],
    ['both /etc/a and C:\\b\\c in one line', 'both <path> and <path> in one line'],
  ];
  for (const [input, expected] of cases) {
    const out = redactAbsolutePaths(input);
    assert.strictEqual(out, expected, input);
    assert.ok(!/bob|Bob|Smith|Project|Users|\/home|\/etc|\\b\\c/.test(out), `leaked fragment in ${JSON.stringify(out)}`);
  }
});

test('D2b sanitizeErrorMessage keeps wording intact and removes only the path', () => {
  assert.strictEqual(sanitizeErrorMessage(new Error("Unexpected token '/'")), "Unexpected token '/'");
  assert.strictEqual(sanitizeErrorMessage(new Error("Unexpected token '/*' in file /home/bob/p/a.json")), "Unexpected token '/*' in file <path>");
  assert.strictEqual(sanitizeErrorMessage(new Error('fetch failed for https://example.com/a/b')), 'fetch failed for https://example.com/a/b');
  assert.strictEqual(sanitizeErrorMessage({ toString: () => 'object error /tmp/x' }), 'object error <path>');
});

test('D3b redactCredentials: no false positives on scoped npm aliases, scp-style git, registry ports, plain URLs', () => {
  for (const same of ['npm:@scope/pkg@^1.0.0', 'git@github.com:org/repo.git', 'registry.io:5000/a/b:1', 'https://github.com/org/repo/archive/v1@2.tgz',
    'github.com/x/y@v1.2.3', 'node:20-alpine', 'https://example.com/path?email=a@b.c', '']) {
    assert.strictEqual(redactCredentials(same), same, same);
  }
  assert.strictEqual(redactCredentials('ftp://user:pw@host/file'), 'ftp://***@host/file');
});

test('D9b stripControlCharacters keeps ordinary text, including non-ASCII, and replaces only control characters', () => {
  assert.strictEqual(stripControlCharacters('café — naïve 日本語 🚀 plain'), 'café — naïve 日本語 🚀 plain');
  assert.strictEqual(stripControlCharacters('a\tb'), 'a b');
  assert.strictEqual(stripControlCharacters(''), '');
});

test('D2 read error and unreadable directory: no absolute path in model, warnings or reports', async () => {
  const root = makeProject({ 'package.json': '{}', 'a/x.txt': 'x' });
  const realRead = fs.promises.readFile, realDir = fs.promises.readdir;
  fs.promises.readFile = async (p, ...a) => { if (String(p).endsWith('package.json')) throw new Error(`EACCES: permission denied, open '${p}'`); return realRead(p, ...a); };
  fs.promises.readdir = async (p, o) => { if (String(p).endsWith(`${path.sep}a`)) throw new Error(`EACCES: permission denied, scandir '${p}'`); return realDir(p, o); };
  let r;
  try { r = await analyzeProject(root, 'p'); } finally { fs.promises.readFile = realRead; fs.promises.readdir = realDir; }
  assert.ok(r.architecture.warnings.length > 0 && r.scan.warnings.length > 0, 'the problems are still reported');
  assert.ok(!allText(r).includes(root), 'absolute root path leaked');
  assert.ok(!allText(r).includes(path.dirname(root)), 'parent directory leaked');
});

test('D4 the architecture model stores no absolute path and the scan report does not print one', async () => {
  const root = makeProject({ 'package.json': '{"dependencies":{"express":"^4"}}', Dockerfile: 'FROM node:20\n' });
  const r = await analyzeProject(root, 'p');
  assert.ok(!('workspacePath' in r.architecture));
  assert.ok(!allText(r).includes(root));
  assert.ok(!formatScanReport(r.scan).join('\n').includes(root));
  assert.match(formatScanReport(r.scan).join('\n'), /Workspace: p/);
});

test('D2/D11 command: unreadable workspace shows a sanitised error; log and channel contain no absolute path', async () => {
  const missing = path.join(makeProject({}), 'does-not-exist');
  const ui = await runCommand([{ name: 'gone', uri: { scheme: 'file', fsPath: missing } }]);
  assert.strictEqual(ui.err.length, 1);
  assert.match(ui.err[0], /Cannot access workspace folder/);
  assert.ok(!ui.err[0].includes(missing) && !ui.out.join('\n').includes(missing));
  const okRoot = makeProject({ 'package.json': '{}' });
  const ui2 = await runCommand([{ name: 'p', uri: { scheme: 'file', fsPath: okRoot } }]);
  assert.ok(![...ui2.out, ...ui2.info].join('\n').includes(okRoot));
});

/* ---------------- D3: credentials ---------------- */
test('D3 redactCredentials: URL userinfo and image credentials removed; ssh git@, ranges and digests untouched', () => {
  assert.strictEqual(redactCredentials('git+https://user:ghp_TOKEN@github.com/o/r.git'), 'git+https://***@github.com/o/r.git');
  assert.strictEqual(redactCredentials('https://TOKENONLY@host/x.tgz'), 'https://***@host/x.tgz');
  assert.strictEqual(redactCredentials('git+ssh://git@github.com/o/r.git'), 'git+ssh://git@github.com/o/r.git');
  assert.strictEqual(redactCredentials('user:pass@registry.io/team/app:1'), 'registry.io/team/app:1');
  for (const same of ['^4.18.2', '>=3.0.0 <4', 'npm:other@^1.0.0', 'node:20@sha256:abc', 'reg:5000/team/app:1@sha256:abc', 'github:user/repo#main', 'file:../x']) {
    assert.strictEqual(redactCredentials(same), same, same);
  }
});

test('D3 npm specifiers with embedded credentials never reach the inventory, model or reports; other versions stay exact', async () => {
  const r = await analyzeProject(makeProject({ 'package.json': JSON.stringify({ dependencies: {
    priv: 'git+https://user:ghp_SECRETTOKEN1@github.com/org/r.git', tok: 'https://SECRETTOKEN2@host/x.tgz', ssh: 'git+ssh://git@github.com/org/r.git', ok: '^1.2.3' } }) }), 'p');
  assert.ok(!/SECRETTOKEN/.test(allText(r)));
  const v = (n) => r.technology.dependencies.find((d) => d.name === n);
  assert.strictEqual(v('priv').version, 'git+https://***@github.com/org/r.git');
  assert.match(v('priv').notes, /credentials .* redacted/);
  assert.strictEqual(v('ssh').version, 'git+ssh://git@github.com/org/r.git');
  assert.strictEqual(v('ok').version, '^1.2.3');
  assert.strictEqual(r.architecture.components.find((c) => c.name === 'ok').technologies[0].version, '^1.2.3');
});

test('D3 image references with credentials are redacted at the source and parsed sensibly', async () => {
  const r = await analyzeProject(makeProject({ Dockerfile: 'FROM user:hunter2@registry.example.com/team/app:1.2\nFROM node:20@sha256:abc123\n' }), 'p');
  assert.ok(!/hunter2/.test(allText(r)));
  const [a, b] = r.technology.technologies;
  assert.deepStrictEqual([a.name, a.version], ['registry.example.com/team/app', '1.2']);
  assert.match(a.notes, /credentials .* redacted/);
  assert.deepStrictEqual([b.name, b.version], ['node', '20'], 'tag+digest left intact');
  assert.ok(r.architecture.components.some((c) => c.name === 'node:20@sha256:abc123'));
});

/* ---------------- D5: earlier/later stage failures ---------------- */
test('D5 a V0.3 failure is surfaced in the model (warning + uncertainty); V0.2 results are kept', async () => {
  const restore = stub('scanner/technology/technologyDetector.js', 'detectTechnologies', async () => { throw new Error('simulated V0.3 failure'); })();
  let r;
  try {
    delete require.cache[require.resolve(path.join(OUT, 'analyzeProject.js'))];
    r = await require(path.join(OUT, 'analyzeProject.js')).analyzeProject(makeProject({ 'package.json': '{"dependencies":{"a":"1"}}' }), 'p');
  } finally { restore(); delete require.cache[require.resolve(path.join(OUT, 'analyzeProject.js'))]; }
  assert.strictEqual(r.scan.fileCount, 1, 'V0.2 result preserved');
  assert.ok(r.technology.warnings.some((w) => /simulated V0.3 failure/.test(w)));
  assert.ok(r.architecture.warnings.some((w) => /Technology detection failed/.test(w)));
  assert.ok(r.architecture.components[0].uncertainty.some((u) => /Technology detection failed/.test(u)));
  assert.match(formatArchitectureReport(r.architecture).join('\n'), /built with warnings/);
});

test('D5 command: a V0.4 failure keeps the V0.2 and V0.3 sections and shows no error toast', async () => {
  const ui = await runCommand(
    [{ name: 'p', uri: { scheme: 'file', fsPath: makeProject({ 'package.json': '{"dependencies":{"a":"^1"}}' }) } }],
    { patch: stub('architecture/architectureModelBuilder.js', 'buildArchitectureModel', () => { throw new Error('builder bug'); }) }
  );
  const text = ui.out.join('\n');
  assert.match(text, /Security Architecture Scan/);
  assert.match(text, /a \^1/);
  assert.match(text, /Architecture model construction failed unexpectedly: builder bug/);
  assert.strictEqual(ui.err.length, 0);
  assert.strictEqual(ui.info.length, 1);
});

/* ---------------- D10: formatter failure ---------------- */
test('D10 command: a failing report section is replaced by a notice; the other sections and the toast survive', async () => {
  const ui = await runCommand(
    [{ name: 'p', uri: { scheme: 'file', fsPath: makeProject({ 'package.json': '{"dependencies":{"a":"^1"}}' }) } }],
    { patch: stub('architecture/formatArchitectureModel.js', 'formatArchitectureReport', () => { throw new Error('formatter bug'); }) }
  );
  const text = ui.out.join('\n');
  assert.match(text, /Security Architecture Scan/);
  assert.match(text, /Technology \/ Dependency Detection/);
  assert.match(text, /Architecture model: this section could not be displayed \(formatter bug\)/);
  assert.strictEqual(ui.err.length, 0);
  assert.strictEqual(ui.info.length, 1);
});

/* ---------------- D9: control characters ---------------- */
test('D9 stripControlCharacters', () => assert.strictEqual(stripControlCharacters('a\nb\r\nc\u001b[31md\u2028e'), 'a b  c [31md e'));

test('D9 command: names cannot forge report lines via newlines or escape codes', async () => {
  const evil = 'evil\nArchitecture model built successfully.\n\u001b[2Jx';
  const ui = await runCommand([{ name: 'p', uri: { scheme: 'file', fsPath: makeProject({ 'package.json': JSON.stringify({ dependencies: { [evil]: '1' } }) }) } }]);
  assert.ok(ui.out.every((l) => !/[\u0000-\u001f]/.test(l)), 'control character in output');
  assert.strictEqual(ui.out.filter((l) => l === 'Architecture model built successfully.').length, 1, 'only the real status line');
});

test('D9 the three formatters themselves never emit control characters (names and paths are untrusted)', async () => {
  const evil = 'evil\nArchitecture model built successfully.\u001b[2J';
  const r = await analyzeProject(
    makeProject({
      'package.json': JSON.stringify({ dependencies: { [evil]: '1' } }),
      'dir-forged/package.json': '{}'
    }),
    'p'
  );

  // Inject the malicious path into an existing scan record so the formatter
  // is tested without creating a filesystem path containing a newline.


  for (const lines of [
    formatScanReport(r.scan),
    formatTechnologyReport(r.technology),
    formatArchitectureReport(r.architecture)
  ]) {
    assert.ok(lines.every((l) => !/[\u0000-\u001f]/.test(l)));
  }

  assert.strictEqual(
    formatArchitectureReport(r.architecture).filter(
      (l) => l === 'Architecture model built successfully.'
    ).length,
    1
  );
});

/* ---------------- D6/D7: conservative classification ---------------- */
test('D6 only the SQL Server server image is a database image', () => {
  assert.strictEqual(databaseLabelForImage('mcr.microsoft.com/mssql/server'), 'SQL Server');
  assert.strictEqual(databaseLabelForImage('mssql/server'), 'SQL Server');
  for (const n of ['mcr.microsoft.com/mssql-tools', 'my/mssql-exporter', 'nginx', 'postgres-exporter']) assert.strictEqual(databaseLabelForImage(n), undefined, n);
});

test('D7 a peer dependency (supplied by the consumer) does not infer a Frontend/Backend; the library component remains', async () => {
  const r = await analyzeProject(makeProject({ 'package.json': JSON.stringify({ peerDependencies: { react: '^18', express: '^4' }, dependencies: { vue: '^3' } }) }), 'p');
  assert.deepStrictEqual(types(r.architecture, 'Frontend').map((c) => c.name), ['Frontend (Vue)']);
  assert.strictEqual(types(r.architecture, 'Backend').length, 0);
  assert.ok(comp(r.architecture, 'react') && comp(r.architecture, 'express'));
});

/* ---------------- D8/D13: build stages vs running services ---------------- */
test('D8 Dockerfile base images are build-base-image; compose services are compose-service; never mixed', async () => {
  const r = await analyzeProject(makeProject({
    Dockerfile: 'FROM golang:1.22 AS build\nFROM alpine:3.19\n',
    'docker-compose.yml': 'services:\n  db:\n    image: postgres:16\n  proxy:\n    image: nginx:1.25\n',
  }), 'p');
  const m = r.architecture;
  const roles = Object.fromEntries(m.components.filter((c) => c.containerRole).map((c) => [c.name, c.containerRole]));
  assert.deepStrictEqual(roles, { 'golang:1.22': 'build-base-image', 'alpine:3.19': 'build-base-image', db: 'compose-service', proxy: 'compose-service' });
  for (const c of m.components.filter((c) => c.containerRole === 'build-base-image')) {
    assert.ok(c.uncertainty.some((u) => /not evidence of a running service/.test(u)));
    assert.strictEqual(c.type, 'Container');
    assert.ok(m.relationships.filter((x) => x.targetId === c.id).every((x) => x.type === 'builds-on-image'));
  }
  for (const c of m.components.filter((c) => c.containerRole === 'compose-service')) {
    assert.ok(m.relationships.filter((x) => x.targetId === c.id).every((x) => x.type === 'declares-service'));
  }
  const report = formatArchitectureReport(m).join('\n');
  assert.match(report, /\[Container\] alpine:3\.19 \(declared\) — build base image/);
  assert.match(report, /\[Database\] db \(inferred\) — compose service/);
  assert.match(report, /\[Container\] proxy \(declared\) — compose service/);
  assert.ok(types(m, 'Library/Dependency').every((c) => !c.containerRole));
});

test('D13 a Docker file outside the module directory records that the owning module is not determined', async () => {
  const r = await analyzeProject(makeProject({
    'package.json': '{}', 'deploy/Dockerfile': 'FROM alpine:3.19\n', 'api/requirements.txt': 'flask\n', 'api/Dockerfile': 'FROM python:3.12\n',
    'deploy/docker-compose.yml': 'services:\n  cache:\n    image: redis:7\n',
  }), 'p');
  const m = r.architecture;
  assert.ok(comp(m, 'alpine:3.19').uncertainty.some((u) => /outside the directory of the module/.test(u)));
  assert.ok(comp(m, 'cache').uncertainty.some((u) => /outside the directory of the module/.test(u)));
  assert.ok(!comp(m, 'python:3.12').uncertainty.some((u) => /outside the directory/.test(u)), 'api/Dockerfile sits in api/');
});

/* ---------------- invariants over varied / malformed projects ---------------- */
const PROJECTS = {
  empty: {},
  noManifest: { 'src/a.ts': 'x' },
  node: { 'package.json': JSON.stringify({ dependencies: { express: '^4', react: '^18', pg: '^8', stripe: '^14', sequelize: '^6' }, devDependencies: { jest: '^29' }, peerDependencies: { vue: '^3' }, engines: { node: '>=18' } }) },
  monorepo: { 'package.json': '{"dependencies":{"a":"1"}}', 'web/package.json': '{"dependencies":{"react":"^18"}}', 'web/packages/ui/package.json': '{}', 'api/pom.xml': '<project><dependencies><dependency><groupId>g</groupId><artifactId>x</artifactId></dependency></dependencies></project>', 'svc/go.mod': 'module m\ngo 1.21\nrequire github.com/gin-gonic/gin v1.9.1\n' },
  docker: { Dockerfile: 'FROM node:20 AS b\nFROM nginx\n', 'docker-compose.yml': 'services:\n  db:\n    image: postgres:16\n  q:\n    image: rabbitmq:3\n  web:\n    build: .\n', 'sub/compose.yml': 'services:\n  db:\n    image: mysql:8\n' },
  malformed: { 'package.json': '{ nope', 'Cargo.toml': '[x', 'pom.xml': 'garbage', 'go.mod': '@@@', 'requirements.txt': '\u0000\u0001', Dockerfile: 'FROM', 'compose.yml': 'services: [: :', 'build.gradle': '}}}{{{', Pipfile: '[[[' },
  mixed: { 'package.json': '{"dependencies":{"express":"^4"}}', 'bad/package.json': '{', 'api/requirements.txt': 'flask>=3\n-r other.txt\ngit+https://x/y.git\n', Dockerfile: 'FROM node:${V}\n' },
};

for (const [name, files] of Object.entries(PROJECTS)) {
  test(`invariants hold for project "${name}"`, async () => {
    const root = makeProject(files);
    const r = await analyzeProject(root, 'proj');
    const m = r.architecture;
    const known = new Set([...r.scan.files, '.']);
    const ids = m.components.map((c) => c.id);
    assert.strictEqual(new Set(ids).size, ids.length, 'unique component ids');
    const rids = m.relationships.map((x) => x.id);
    assert.strictEqual(new Set(rids).size, rids.length, 'unique relationship ids');
    const triples = m.relationships.map((x) => `${x.type}|${x.sourceId}|${x.targetId}`);
    assert.strictEqual(new Set(triples).size, triples.length, 'no duplicate relationships');
    assert.ok(m.components.length >= 1 && m.components[0].type === 'Application', 'always an Application first');
    for (const c of m.components) {
      assert.ok(COMPONENT_TYPES.includes(c.type));
      assert.ok(c.evidence.length >= 1, `${c.id} has evidence`);
      if (c.certainty === 'unknown') assert.ok(c.uncertainty.length > 0);
      if (c.certainty === 'inferred') assert.ok(c.uncertainty.length > 0, `${c.id} inferred => uncertainty recorded`);
    }
    for (const x of m.relationships) {
      assert.ok(RELATIONSHIP_TYPES.includes(x.type));
      assert.ok(ids.includes(x.sourceId) && ids.includes(x.targetId), `${x.id} dangling`);
      assert.notStrictEqual(x.sourceId, x.targetId);
      assert.ok(x.evidence.length >= 1);
    }
    const rules = new Set(Object.values(RULE_IDS));
    for (const e of [...m.components.flatMap((c) => c.evidence), ...m.relationships.flatMap((x) => x.evidence)]) {
      assert.ok(known.has(e.source), `evidence source ${e.source} is a scanned file`);
      assert.ok(!path.isAbsolute(e.source) && !e.source.includes('\\') && !/^[A-Za-z]:/.test(e.source));
      assert.ok(rules.has(e.rule) && e.description.length > 0);
    }
    assert.ok(!allText(r).includes(root), 'no absolute path anywhere');
    assert.ok(!m.relationships.some((x) => x.type === 'contains' && /^(frontend|backend):/.test(x.sourceId) && /^(frontend|backend):/.test(x.targetId)), 'no frontend<->backend edge');
    assert.ok(!m.relationships.some((x) => x.sourceId.startsWith('app:') && /^(db|ext):/.test(x.targetId)), 'no application -> database/service edge from a mere dependency');
  });
}

test('identical project content yields identical ids and ordering regardless of file creation order or location', async () => {
  const entries = Object.entries(PROJECTS.monorepo).concat(Object.entries(PROJECTS.docker));
  const a = await analyzeProject(makeProject(Object.fromEntries(entries)), 'proj');
  const b = await analyzeProject(makeProject(Object.fromEntries([...entries].reverse())), 'proj');
  const pick = (r) => JSON.stringify({ c: r.architecture.components, r: r.architecture.relationships, w: r.architecture.warnings });
  assert.strictEqual(pick(a), pick(b));
});

test('same-named compose services in different compose files stay distinct (no merge, no contradiction)', async () => {
  const m = (await analyzeProject(makeProject(PROJECTS.docker), 'p')).architecture;
  const dbs = m.components.filter((c) => c.name === 'db');
  assert.strictEqual(dbs.length, 2);
  assert.deepStrictEqual(dbs.map((d) => d.technologies[0].name).sort(), ['mysql', 'postgres']);
  assert.notStrictEqual(dbs[0].id, dbs[1].id);
});

test('ORM alone does not create a Database; a driver does, as inferred, linked only from the library', async () => {
  const orm = (await analyzeProject(makeProject({ 'package.json': '{"dependencies":{"sequelize":"^6","typeorm":"^0.3","@prisma/client":"^5"}}' }), 'p')).architecture;
  assert.strictEqual(types(orm, 'Database').length, 0);
  const drv = (await analyzeProject(makeProject({ 'package.json': '{"dependencies":{"sequelize":"^6","pg":"^8"}}' }), 'p')).architecture;
  assert.deepStrictEqual(types(drv, 'Database').map((d) => [d.name, d.certainty]), [['PostgreSQL', 'inferred']]);
});

/* ---------------- packaging configuration ---------------- */
test('.vscodeignore keeps sources, tests and dev config out of the packaged extension', () => {
  const ignore = fs.readFileSync(path.join(__dirname, '..', '.vscodeignore'), 'utf8').split(/\r?\n/);
  for (const needed of ['src/**', 'test/**', '.vscode/**', 'tsconfig.json']) assert.ok(ignore.includes(needed), needed);
  assert.ok(!ignore.some((l) => /^\s*(out|node_modules)/.test(l)), 'compiled output and runtime dependencies must be packaged');
  const pkg = require('../package.json');
  assert.ok(fs.existsSync(path.join(__dirname, '..', pkg.main)), 'main entry exists after compile');
});
