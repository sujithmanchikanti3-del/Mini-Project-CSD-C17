// V0.3: technology / dependency / version detection.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { makeProject, OUT } = require('./helpers');
const { analyzeProject } = require(path.join(OUT, 'analyzeProject.js'));
const { parseRequirement } = require(path.join(OUT, 'scanner', 'technology', 'parsers', 'pythonParser.js'));
const { parseImageReference } = require(path.join(OUT, 'scanner', 'technology', 'parsers', 'dockerParser.js'));
const { formatTechnologyReport, formatTechnologySummary } = require(path.join(OUT, 'scanner', 'technology', 'formatTechnologyInventory.js'));

async function analyze(files) {
  const { technology } = await analyzeProject(makeProject(files), 'proj');
  return technology;
}
const dep = (inv, name, category) => inv.dependencies.find((d) => d.name === name && (!category || d.category === category));
const tech = (inv, name) => inv.technologies.filter((t) => t.name === name);

/* ---------------- TEST 1: Node.js ---------------- */
test('Node.js: four sections, exact version ranges, engines', async () => {
  const inv = await analyze({
    'package.json': JSON.stringify({
      name: 'app',
      dependencies: { express: '^4.18.2', react: '~18.2.0', jsonwebtoken: '9.0.2', local: 'file:../local', aliased: 'npm:other@^1.0.0', empty: '' },
      devDependencies: { typescript: '>=5.4.0 <6' },
      peerDependencies: { 'react-dom': '^18 || ^19' },
      optionalDependencies: { fsevents: 'v2.3.3' },
      engines: { node: '>=18' },
    }),
  });
  assert.strictEqual(dep(inv, 'express').version, '^4.18.2');
  assert.strictEqual(dep(inv, 'react').version, '~18.2.0');
  assert.strictEqual(dep(inv, 'jsonwebtoken').version, '9.0.2');
  assert.strictEqual(dep(inv, 'typescript', 'devDependencies').version, '>=5.4.0 <6');
  assert.strictEqual(dep(inv, 'react-dom', 'peerDependencies').version, '^18 || ^19');
  assert.strictEqual(dep(inv, 'fsevents', 'optionalDependencies').version, 'v2.3.3');
  assert.strictEqual(dep(inv, 'express').category, 'dependencies');
  assert.strictEqual(dep(inv, 'express').ecosystem, 'Node.js');
  assert.strictEqual(dep(inv, 'express').source, 'package.json');
  assert.strictEqual(dep(inv, 'local').notes, 'non-registry specifier');
  assert.match(dep(inv, 'aliased').notes, /alias for other@\^1\.0\.0/);
  assert.strictEqual(dep(inv, 'empty').version, '');
  assert.strictEqual(tech(inv, 'Node.js')[0].version, '>=18');
  assert.strictEqual(inv.dependencies.length, 9);
});

test('Node.js: empty sections, non-object section, non-string version', async () => {
  const inv = await analyze({ 'package.json': JSON.stringify({ dependencies: {}, devDependencies: 'oops', peerDependencies: { x: 5 } }) });
  assert.strictEqual(inv.dependencies.length, 1);
  assert.strictEqual(dep(inv, 'x').version, null);
  assert.ok(inv.warnings.some((w) => /devDependencies" is not an object/.test(w)));
});

/* ---------------- TEST 2: Python ---------------- */
test('Python requirements.txt: specifiers preserved, options/comments/URLs handled', async () => {
  const inv = await analyze({
    'requirements.txt': [
      '# comment', '', 'flask>=3.0.0', 'requests==2.31.0  # pinned', 'numpy~=1.26', 'django>=4.2,<5.0', 'SQLAlchemy[asyncio] (>=2.0)',
      'pandas', 'pytest==8.0.0 ; python_version >= "3.8" --hash=sha256:abc',
      'long-pkg>=1.0,\\', '<2.0', '-r other.txt', '--index-url https://user:SECRET@example.com/simple',
      '-e git+https://github.com/x/y.git#egg=y', 'git+https://github.com/x/z.git', 'direct @ https://user:SECRET@host/pkg.whl',
    ].join('\n'),
  });
  assert.strictEqual(dep(inv, 'flask').version, '>=3.0.0');
  assert.strictEqual(dep(inv, 'requests').version, '==2.31.0');
  assert.strictEqual(dep(inv, 'numpy').version, '~=1.26');
  assert.strictEqual(dep(inv, 'django').version, '>=4.2,<5.0');
  assert.strictEqual(dep(inv, 'SQLAlchemy').version, '>=2.0');
  assert.strictEqual(dep(inv, 'pandas').version, null);
  assert.strictEqual(dep(inv, 'pytest').version, '==8.0.0');
  assert.strictEqual(dep(inv, 'long-pkg').version, '>=1.0,<2.0');
  assert.strictEqual(dep(inv, 'direct').notes, 'direct URL reference');
  assert.strictEqual(dep(inv, 'flask').ecosystem, 'Python');
  // Credentials in options / URLs must never appear anywhere in the output.
  assert.ok(!JSON.stringify(inv).includes('SECRET'));
  assert.ok(inv.warnings.length >= 1);
});

test('Python parseRequirement edge cases', () => {
  assert.deepStrictEqual(parseRequirement('flask>=3.0.0'), { name: 'flask', version: '>=3.0.0' });
  assert.strictEqual(parseRequirement('==1.0'), null);
  assert.strictEqual(parseRequirement('git+https://x/y.git'), null);
  assert.strictEqual(parseRequirement('name notaversion'), null);
});

test('Python pyproject.toml: PEP 621, optional, groups, build-system, Poetry', async () => {
  const inv = await analyze({
    'pyproject.toml': `
[build-system]
requires = ["setuptools>=61", "wheel"]
[project]
requires-python = ">=3.9"
dependencies = ["fastapi>=0.110,<1", "pydantic==2.6.1", "uvicorn[standard]"]
[project.optional-dependencies]
dev = ["pytest>=8"]
[dependency-groups]
lint = ["ruff~=0.3", {include-group = "dev"}]
[tool.poetry.dependencies]
python = "^3.10"
httpx = "^0.27.0"
gitpkg = { git = "https://example.com/x.git" }
multi = [{ version = "^1.0", python = "<3.9" }, { version = "^2.0", python = ">=3.9" }]
[tool.poetry.group.test.dependencies]
coverage = { version = "7.4.1", extras = ["toml"] }
`,
  });
  assert.strictEqual(dep(inv, 'fastapi').version, '>=0.110,<1');
  assert.strictEqual(dep(inv, 'pydantic').version, '==2.6.1');
  assert.strictEqual(dep(inv, 'uvicorn').version, null);
  assert.strictEqual(dep(inv, 'pytest', 'optional-dependencies:dev').version, '>=8');
  assert.strictEqual(dep(inv, 'ruff', 'dependency-groups:lint').version, '~=0.3');
  assert.strictEqual(dep(inv, 'setuptools', 'build-system').version, '>=61');
  assert.strictEqual(dep(inv, 'httpx', 'dependencies').version, '^0.27.0');
  assert.strictEqual(dep(inv, 'gitpkg').notes, 'git dependency');
  assert.deepStrictEqual(inv.dependencies.filter((d) => d.name === 'multi').map((d) => d.version), ['^1.0', '^2.0']);
  assert.strictEqual(dep(inv, 'coverage', 'group:test').version, '7.4.1');
  assert.strictEqual(dep(inv, 'python'), undefined, 'poetry "python" is a technology, not a dependency');
  assert.deepStrictEqual(tech(inv, 'Python').map((t) => t.version).sort(), ['>=3.9', '^3.10']);
});

test('Python Pipfile', async () => {
  const inv = await analyze({
    Pipfile: `[packages]\nrequests = "*"\nflask = "==3.0.0"\ndjango = {version = ">=4.2", extras = ["bcrypt"]}\n[dev-packages]\npytest = "*"\n[requires]\npython_version = "3.11"\n`,
  });
  assert.strictEqual(dep(inv, 'requests').version, '*');
  assert.strictEqual(dep(inv, 'flask').version, '==3.0.0');
  assert.strictEqual(dep(inv, 'django').version, '>=4.2');
  assert.strictEqual(dep(inv, 'pytest', 'dev-packages').version, '*');
  assert.strictEqual(tech(inv, 'Python')[0].version, '3.11');
});

/* ---------------- TEST 3: Java ---------------- */
const POM = `<?xml version="1.0"?>
<project>
  <!-- <dependency><groupId>commented</groupId><artifactId>out</artifactId><version>9</version></dependency> -->
  <parent><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId><version>3.2.1</version></parent>
  <properties><java.version>17</java.version><jackson.version>2.16.0</jackson.version></properties>
  <dependencyManagement><dependencies>
    <dependency><groupId>org.mgd</groupId><artifactId>managed</artifactId><version>1.0</version><scope>import</scope></dependency>
  </dependencies></dependencyManagement>
  <dependencies>
    <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId></dependency>
    <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>\${jackson.version}</version>
      <exclusions><exclusion><groupId>excluded.group</groupId><artifactId>excluded</artifactId></exclusion></exclusions></dependency>
    <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13.2</version><scope>test</scope></dependency>
    <dependency><groupId>x</groupId><artifactId>undef</artifactId><version>\${undefined.prop}</version></dependency>
  </dependencies>
  <build><plugins><plugin><artifactId>p</artifactId>
    <dependencies><dependency><groupId>plug.group</groupId><artifactId>plug-dep</artifactId><version>2.0</version></dependency></dependencies>
  </plugin></plugins></build>
</project>`;

test('Java pom.xml: parent, scopes, properties, exclusions, comments, plugin deps, managed', async () => {
  const inv = await analyze({ 'pom.xml': POM });
  assert.strictEqual(dep(inv, 'org.springframework.boot:spring-boot-starter-parent').category, 'parent');
  assert.strictEqual(dep(inv, 'org.springframework.boot:spring-boot-starter-web').version, null);
  const jackson = dep(inv, 'com.fasterxml.jackson.core:jackson-databind');
  assert.strictEqual(jackson.version, '${jackson.version}', 'declared version stays verbatim');
  assert.strictEqual(jackson.resolvedVersion, '2.16.0');
  assert.strictEqual(dep(inv, 'junit:junit').category, 'test');
  assert.strictEqual(dep(inv, 'junit:junit').version, '4.13.2');
  assert.strictEqual(dep(inv, 'x:undef').resolvedVersion, undefined);
  assert.match(dep(inv, 'x:undef').notes, /not defined/);
  assert.strictEqual(dep(inv, 'plug.group:plug-dep').category, 'plugin-dependency');
  assert.strictEqual(dep(inv, 'org.mgd:managed').category, 'dependencyManagement');
  assert.strictEqual(dep(inv, 'excluded.group:excluded'), undefined);
  assert.strictEqual(dep(inv, 'commented:out'), undefined);
  assert.strictEqual(tech(inv, 'Java')[0].version, '17');
});

test('Java build.gradle (Groovy) and build.gradle.kts', async () => {
  const inv = await analyze({
    'build.gradle': `
plugins { id 'java' }
dependencies {
  implementation 'org.springframework.boot:spring-boot-starter-web:3.2.1'
  implementation "com.google.guava:guava:$guavaVersion"
  testImplementation 'junit:junit:4.13.2'
  runtimeOnly 'org.postgresql:postgresql'
  implementation group: 'org.apache.commons', name: 'commons-lang3', version: '3.14.0'
  implementation platform('org.springframework.boot:spring-boot-dependencies:3.2.1')
  api 'com.squareup.okhttp3:okhttp:4.12.0@aar'
  implementation libs.some.catalog.entry
  implementation project(':core')
  // implementation 'commented:out:1.0'
}`,
    'sub/build.gradle.kts': `dependencies {\n  implementation("io.ktor:ktor-server-core:2.3.7")\n  testImplementation(kotlin("test"))\n}`,
  });
  assert.strictEqual(dep(inv, 'org.springframework.boot:spring-boot-starter-web').version, '3.2.1');
  assert.strictEqual(dep(inv, 'com.google.guava:guava').version, '$guavaVersion');
  assert.strictEqual(dep(inv, 'junit:junit').category, 'testImplementation');
  assert.strictEqual(dep(inv, 'org.postgresql:postgresql').version, null);
  assert.strictEqual(dep(inv, 'org.apache.commons:commons-lang3').version, '3.14.0');
  assert.match(dep(inv, 'org.springframework.boot:spring-boot-dependencies').notes, /platform/);
  assert.strictEqual(dep(inv, 'com.squareup.okhttp3:okhttp').version, '4.12.0');
  assert.strictEqual(dep(inv, 'commented:out'), undefined);
  assert.strictEqual(dep(inv, 'io.ktor:ktor-server-core').version, '2.3.7');
  assert.strictEqual(dep(inv, 'io.ktor:ktor-server-core').source, 'sub/build.gradle.kts');
  assert.ok(inv.warnings.some((w) => /version-catalog/.test(w)));
});

/* ---------------- TEST 4: Go ---------------- */
test('Go go.mod: go directive, require block + single, indirect, pseudo-versions', async () => {
  const inv = await analyze({
    'go.mod': `module example.com/app\n\ngo 1.21\n\nrequire github.com/gin-gonic/gin v1.9.1\n\nrequire (\n\tgithub.com/stretchr/testify v1.8.4\n\tgolang.org/x/sys v0.0.0-20230901123456-abcdef123456 // indirect\n)\n\nreplace github.com/a/b => ../b\n`,
  });
  assert.strictEqual(dep(inv, 'github.com/gin-gonic/gin').version, 'v1.9.1');
  assert.strictEqual(dep(inv, 'github.com/stretchr/testify').category, 'require');
  assert.strictEqual(dep(inv, 'golang.org/x/sys').category, 'require (indirect)');
  assert.strictEqual(dep(inv, 'golang.org/x/sys').version, 'v0.0.0-20230901123456-abcdef123456');
  assert.strictEqual(inv.dependencies.length, 3);
  assert.strictEqual(tech(inv, 'Go')[0].version, '1.21');
});

/* ---------------- TEST 5: Rust ---------------- */
test('Rust Cargo.toml: string/table/dotted/renamed/git/path/workspace/target', async () => {
  const inv = await analyze({
    'Cargo.toml': `
[package]
name = "app"
rust-version = "1.75"
[dependencies]
serde = "1.0.195"
tokio = { version = "1", features = ["full"] }
mylocal = { path = "../mylocal" }
fromgit = { git = "https://example.com/x.git" }
shared = { workspace = true }
alias = { package = "real-crate", version = "0.3" }
[dependencies.rand]
version = "0.8.5"
[dev-dependencies]
criterion = "0.5"
[build-dependencies]
cc = "1.0"
[target.'cfg(unix)'.dependencies]
libc = "0.2"
[workspace.dependencies]
anyhow = "1"
`,
  });
  assert.strictEqual(dep(inv, 'serde').version, '1.0.195');
  assert.strictEqual(dep(inv, 'tokio').version, '1');
  assert.strictEqual(dep(inv, 'rand').version, '0.8.5');
  assert.strictEqual(dep(inv, 'mylocal').version, null);
  assert.strictEqual(dep(inv, 'mylocal').notes, 'path dependency');
  assert.strictEqual(dep(inv, 'fromgit').notes, 'git dependency');
  assert.strictEqual(dep(inv, 'shared').notes, 'version managed by workspace');
  assert.strictEqual(dep(inv, 'real-crate').version, '0.3');
  assert.match(dep(inv, 'real-crate').notes, /declared as "alias"/);
  assert.strictEqual(dep(inv, 'criterion', 'dev-dependencies').version, '0.5');
  assert.strictEqual(dep(inv, 'cc', 'build-dependencies').version, '1.0');
  assert.strictEqual(dep(inv, 'libc').category, 'target.cfg(unix).dependencies');
  assert.strictEqual(dep(inv, 'anyhow').category, 'workspace.dependencies');
  assert.strictEqual(tech(inv, 'Rust')[0].version, '1.75');
});

/* ---------------- TEST 6: Docker ---------------- */
test('Dockerfile: multi-stage, platform flag, scratch, digest, variables, untagged', async () => {
  const inv = await analyze({
    Dockerfile: `# syntax=docker/dockerfile:1
ARG V=20
FROM --platform=$BUILDPLATFORM node:20-alpine AS build
RUN echo hi
FROM build AS test
FROM scratch AS empty
FROM localhost:5000/team/app:1.2 AS app
FROM ubuntu@sha256:abc123
FROM nginx
FROM node:\${V}
`,
  });
  const names = inv.technologies.map((t) => t.reference);
  assert.deepStrictEqual(names, ['node:20-alpine', 'localhost:5000/team/app:1.2', 'ubuntu@sha256:abc123', 'nginx', 'node:${V}']);
  assert.strictEqual(inv.technologies[0].name, 'node');
  assert.strictEqual(inv.technologies[0].version, '20-alpine');
  assert.strictEqual(inv.technologies[1].name, 'localhost:5000/team/app');
  assert.strictEqual(inv.technologies[1].version, '1.2');
  assert.strictEqual(inv.technologies[2].version, 'sha256:abc123');
  assert.strictEqual(inv.technologies[3].version, null);
  assert.match(inv.technologies[3].notes, /latest/);
  assert.match(inv.technologies[4].notes, /variable/);
});

test('docker-compose.yml / compose.yml: images per service, build-only skipped', async () => {
  const inv = await analyze({
    'docker-compose.yml': `version: "3.9"\nservices:\n  db:\n    image: postgres:16 # comment\n    environment:\n      image: not-an-image-key-here\n  web:\n    build: .\n  cache:\n    image: "redis:7.2"\nvolumes:\n  image: ignored\n`,
    'compose.yml': `services:\n  mq:\n    image: rabbitmq:3-management\n`,
  });
  const refs = inv.technologies.map((t) => `${t.source}|${t.reference}`);
  assert.deepStrictEqual(refs.sort(), ['compose.yml|rabbitmq:3-management', 'docker-compose.yml|postgres:16', 'docker-compose.yml|redis:7.2'].sort());
  assert.match(inv.technologies.find((t) => t.reference === 'postgres:16').notes, /service "db"/);
});

test('parseImageReference', () => {
  assert.deepStrictEqual(parseImageReference('node:20'), { name: 'node', tag: '20', digest: null });
  assert.deepStrictEqual(parseImageReference('reg:5000/a/b'), { name: 'reg:5000/a/b', tag: null, digest: null });
  assert.deepStrictEqual(parseImageReference('a/b:1@sha256:x'), { name: 'a/b', tag: '1', digest: 'sha256:x' });
});

/* ---------------- TEST 7: malformed configuration ---------------- */
test('malformed manifests never crash; others in the same workspace still parse', async () => {
  const inv = await analyze({
    'package.json': '{ "dependencies": { "express": ',
    'good/package.json': JSON.stringify({ dependencies: { lodash: '^4.17.21' } }),
    'pyproject.toml': '[project\ndependencies = SECRET_CONTENT_MARKER',
    'Cargo.toml': 'not = [valid',
    'pom.xml': '<notapom/>',
    'go.mod': 'garbage that is not go',
    'requirements.txt': '\u0000\u0001 binary junk !!!',
    Dockerfile: '',
    'compose.yml': 'services: [: :',
    'build.gradle': '}}}{{{ ((( unbalanced',
    'Pipfile': '[[[',
  });
  const bad = (p) => inv.sources.find((s) => s.path === p);
  assert.strictEqual(bad('package.json').status, 'error');
  assert.match(bad('package.json').message, /Invalid JSON/);
  assert.strictEqual(bad('pyproject.toml').status, 'error');
  assert.match(bad('pyproject.toml').message, /Invalid TOML/);
  assert.strictEqual(bad('Cargo.toml').status, 'error');
  assert.strictEqual(bad('pom.xml').status, 'error');
  assert.strictEqual(bad('Pipfile').status, 'error');
  assert.strictEqual(dep(inv, 'lodash').version, '^4.17.21');
  assert.ok(!JSON.stringify(inv).includes('SECRET_CONTENT_MARKER'), 'file content must not leak into messages');
  assert.strictEqual(inv.sources.length, 11);
});

test('unreadable manifest and oversized manifest are reported, not thrown', async () => {
  const root = makeProject({ 'package.json': '{}', 'Cargo.toml': '[dependencies]\n' + 'a = "1"\n'.repeat(10) });
  const realReadFile = fs.promises.readFile;
  fs.promises.readFile = async (p, ...rest) => {
    if (String(p).endsWith('Cargo.toml')) { const e = new Error('EACCES: permission denied'); e.code = 'EACCES'; throw e; }
    return realReadFile(p, ...rest);
  };
  try {
    const { technology } = await analyzeProject(root, 'x');
    assert.strictEqual(technology.sources.find((s) => s.path === 'Cargo.toml').status, 'error');
    assert.match(technology.sources.find((s) => s.path === 'Cargo.toml').message, /Could not read file/);
    assert.strictEqual(technology.sources.find((s) => s.path === 'package.json').status, 'parsed');
  } finally {
    fs.promises.readFile = realReadFile;
  }
});

test('empty workspace / no manifests / empty manifests', async () => {
  const inv = await analyze({});
  assert.deepStrictEqual([inv.dependencies, inv.technologies, inv.sources, inv.warnings], [[], [], [], []]);
  const inv2 = await analyze({ 'package.json': '{}', 'requirements.txt': '', 'go.mod': '', 'Cargo.toml': '' });
  assert.strictEqual(inv2.dependencies.length, 0);
  assert.ok(inv2.sources.every((s) => s.status !== 'error'));
});

test('UTF-8 BOM in package.json / requirements.txt is tolerated', async () => {
  const inv = await analyze({ 'package.json': '\uFEFF{"dependencies":{"a":"1.0.0"}}', 'requirements.txt': '\uFEFFflask==3.0' });
  assert.strictEqual(dep(inv, 'a').version, '1.0.0');
  assert.strictEqual(dep(inv, 'flask').version, '==3.0');
});

/* ---------------- safety: read-only, offline, excluded dirs ---------------- */
test('analysis does not modify the project', async () => {
  const files = { 'package.json': '{"dependencies":{"a":"^1"}}', 'Dockerfile': 'FROM node:20', 'src/x.ts': 'x' };
  const root = makeProject(files);
  const snapshot = () => JSON.stringify(
    fs.readdirSync(root, { recursive: true }).sort().map((f) => { const s = fs.statSync(path.join(root, f)); return [f, s.mtimeMs, s.size]; })
  );
  const before = snapshot();
  await analyzeProject(root, 'x');
  assert.strictEqual(snapshot(), before);
});

test('no network / process-spawning modules are loaded by the V0.3 code', () => {
  const dir = path.join(__dirname, '..', 'src');
  const forbidden = /require\(['"](https?|net|dgram|child_process|tls|dns)['"]\)|from ['"](https?|net|dgram|child_process|tls|dns|node:http|node:https|node:net|node:child_process)['"]|\bfetch\(|XMLHttpRequest/;
  const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]));
  for (const f of walk(dir).filter((f) => f.endsWith('.ts'))) {
    assert.ok(!forbidden.test(fs.readFileSync(f, 'utf8')), `forbidden API in ${f}`);
  }
});

test('dependencies inside excluded directories are not read', async () => {
  const inv = await analyze({
    'package.json': '{"dependencies":{"real":"1"}}',
    'node_modules/pkg/package.json': '{"dependencies":{"ghost":"1"}}',
    'dist/package.json': '{"dependencies":{"ghost2":"1"}}',
  });
  assert.deepStrictEqual(inv.dependencies.map((d) => d.name), ['real']);
});

/* ---------------- formatting ---------------- */
test('report formatting preserves ranges and describes failures', async () => {
  const inv = await analyze({
    'package.json': JSON.stringify({ dependencies: { express: '^4.18.2' } }),
    'bad/Cargo.toml': '[x',
    Dockerfile: 'FROM node:20',
  });
  const text = formatTechnologyReport(inv).join('\n');
  assert.match(text, /express \^4\.18\.2/);
  assert.match(text, /FAILED — Invalid TOML/);
  assert.match(text, /node 20/);
  assert.match(text, /completed with 1 unreadable manifest/);
  assert.match(formatTechnologySummary(inv), /1 dependency, 1 technology detected; 1 manifest\(s\) could not be read\./);
});
