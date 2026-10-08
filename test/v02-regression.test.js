// V0.2 regression: the workspace scanner must behave exactly as before V0.3.
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { makeProject, OUT } = require('./helpers');
const { scanWorkspace } = require(path.join(OUT, 'scanner', 'workspaceScanner.js'));
const { WorkspaceScanError } = require(path.join(OUT, 'scanner', 'types.js'));

const NODE_DOCKER = {
  'src/app.ts': 'x', 'src/server.ts': 'x', 'tests/a.test.ts': 'x', 'package.json': '{}', 'README.md': 'x', Dockerfile: 'FROM node:20',
  'node_modules/x/package.json': '{}', '.git/config': 'x', '.vscode/settings.json': '{}',
  'out/a.js': 'x', 'dist/b.js': 'x', 'build/c.js': 'x', 'coverage/d.json': '{}',
};

test('Node+Docker project: types, counts, config files, exclusions', async () => {
  const r = await scanWorkspace(makeProject(NODE_DOCKER), 'my-project');
  assert.deepStrictEqual(r.projectTypes, ['Node.js', 'Docker']);
  assert.deepStrictEqual(r.configurationFiles, ['Dockerfile', 'package.json']);
  assert.strictEqual(r.fileCount, 6);
  assert.strictEqual(r.directoryCount, 2);
  assert.deepStrictEqual(r.excludedDirectories, ['.git', '.vscode', 'build', 'coverage', 'dist', 'node_modules', 'out']);
  assert.strictEqual(r.workspaceName, 'my-project');
  assert.ok(!r.files.some((f) => f.startsWith('node_modules/')));
});

test('empty workspace does not crash', async () => {
  const r = await scanWorkspace(makeProject({}));
  assert.strictEqual(r.fileCount, 0);
  assert.strictEqual(r.directoryCount, 0);
  assert.deepStrictEqual(r.projectTypes, []);
});

test('every V0.2 project type rule still fires', async () => {
  const r = await scanWorkspace(makeProject({
    'a/pom.xml': '', 'b/package.json': '', 'c/go.mod': '', 'd/Pipfile': '', 'e/pyproject.toml': '',
    'f/requirements.txt': '', 'g/Cargo.toml': '', 'h/build.gradle.kts': '', 'i/build.gradle': '', 'compose.yml': '', 'docker-compose.yml': '',
  }));
  assert.deepStrictEqual(r.projectTypes, ['Node.js', 'Python', 'Java', 'Go', 'Rust', 'Docker']);
  assert.strictEqual(r.configurationFiles.length, 11);
});

test('missing root throws WorkspaceScanError', async () => {
  await assert.rejects(scanWorkspace(path.join(makeProject({}), 'nope')), WorkspaceScanError);
});
