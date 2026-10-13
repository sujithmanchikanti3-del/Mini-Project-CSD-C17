// V0.5: deterministic STRIDE threat analysis (engine, rules, determinism, invariants, formatting).
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { makeProject, OUT } = require('./helpers');
const { analyzeProject } = require(path.join(OUT, 'analyzeProject.js'));
const { analyzeStride, summarizeStride, emptyStrideAnalysis } = require(path.join(OUT, 'stride', 'strideAnalyzer.js'));
const { STRIDE_RULES, CONTROL_LIBRARIES, matchesControl, GLOBAL_LIMITATIONS } = require(path.join(OUT, 'stride', 'strideRules.js'));
const { formatStrideReport, formatStrideSummary } = require(path.join(OUT, 'stride', 'formatStrideAnalysis.js'));
const { STRIDE_CATEGORIES } = require(path.join(OUT, 'stride', 'types.js'));

/* ------------------------------ helpers ------------------------------ */

async function run(files) {
  const r = await analyzeProject(makeProject(files), 'proj');
  return { ...r, a: analyzeStride(r.architecture) };
}
const ids = (a, ruleId) => a.threats.filter((t) => t.ruleId === `STRIDE-${ruleId}`);
const has = (a, ruleId) => ids(a, ruleId).length > 0;
const notAssessed = (a, ruleId) => a.notAssessed.filter((n) => n.ruleId === `STRIDE-${ruleId}`);
const node = (deps, extra = {}) => ({ 'package.json': JSON.stringify({ dependencies: deps, ...extra }) });
const clone = (x) => JSON.parse(JSON.stringify(x));

/* A hand-built minimal model, for cases the scanner cannot produce. */
const ev = (source = 'package.json', rule = 'manifest-declares-dependency', detail) => ({ kind: 'dependency-declaration', source, rule, description: `evidence from ${source}`, ...(detail ? { detail } : {}) });
const comp = (id, type, name, extra = {}) => ({ id, type, name, certainty: 'inferred', evidence: [ev()], technologies: [], uncertainty: [], ...extra });
const rel = (type, sourceId, targetId) => ({ id: `rel:${type}|${sourceId}|${targetId}`, type, sourceId, targetId, description: 'd', evidence: [ev()] });
const model = (components, relationships = [], warnings = []) => ({ workspaceName: 'm', components, relationships, warnings });
const expressTech = { name: 'express', version: '^4', ecosystem: 'Node.js', kind: 'dependency', category: 'dependencies', source: 'package.json' };

/* ------------------------------ catalog ------------------------------ */

test('catalog: 15 rules, unique well-formed ids, every STRIDE category covered, observed rules are exactly T-001..T-003', () => {
  assert.strictEqual(STRIDE_RULES.length, 15);
  const rid = STRIDE_RULES.map((r) => r.id);
  assert.strictEqual(new Set(rid).size, 15);
  for (const r of STRIDE_RULES) {
    assert.match(r.id, /^STRIDE-[STRIDE]-\d{3}$/);
    assert.ok(STRIDE_CATEGORIES.includes(r.category));
    assert.ok(r.summary.length > 20);
    assert.ok(['observed', 'assumption-dependent'].includes(r.basis));
    assert.strictEqual(r.id[7], { Spoofing: 'S', Tampering: 'T', Repudiation: 'R', 'Information Disclosure': 'I', 'Denial of Service': 'D', 'Elevation of Privilege': 'E' }[r.category]);
  }
  for (const c of STRIDE_CATEGORIES) assert.ok(STRIDE_RULES.filter((r) => r.category === c).length >= 2, c);
  assert.deepStrictEqual(STRIDE_RULES.filter((r) => r.basis === 'observed').map((r) => r.id).sort(), ['STRIDE-T-001', 'STRIDE-T-002', 'STRIDE-T-003']);
});

test('control tables: normalised matching, ecosystem-specific, Spring Security counts for both authN and authZ', () => {
  assert.ok(matchesControl('authentication', 'Python', 'Flask_Login'));
  assert.ok(matchesControl('authentication', 'Node.js', 'passport-jwt'));
  assert.ok(matchesControl('authentication', 'Java', 'org.springframework.boot:spring-boot-starter-security'));
  assert.ok(matchesControl('authorization', 'Java', 'org.springframework.security:spring-security-web'));
  assert.ok(!matchesControl('authentication', 'Python', 'passport'), 'Node library name in a Python manifest is not a match');
  assert.ok(!matchesControl('logging', 'Python', 'logging'), 'logging is not assessed for Python');
  assert.ok(!matchesControl('authentication', 'Node.js', 'left-pad'));
  assert.deepStrictEqual(Object.keys(CONTROL_LIBRARIES.logging).sort(), ['Node.js', 'Rust']);
});

/* ------------------------------ SPOOFING ------------------------------ */

test('S-001: backend without a recognised authentication library => assumption-dependent threat with evidence, assumptions and limitations', async () => {
  const { a } = await run(node({ express: '^4.18.2' }));
  const [t] = ids(a, 'S-001');
  assert.ok(t);
  assert.strictEqual(t.category, 'Spoofing');
  assert.strictEqual(t.basis, 'assumption-dependent');
  assert.strictEqual(t.target.kind, 'component');
  assert.strictEqual(t.target.name, 'Backend (Express)');
  assert.match(t.observations[0].statement, /inferred from declared framework dependencies \(express \^4\.18\.2\)/);
  assert.ok(t.observations.some((o) => /No recognised authentication library is declared/.test(o.statement)));
  assert.ok(t.observations.every((o) => o.evidence.length >= 1 && o.evidence.every((e) => e.source === 'package.json')));
  assert.ok(t.assumptions.length >= 2 && t.assumptions.every((x) => /not established|cannot see|not implemented/.test(x)));
  assert.ok(t.limitations.some((l) => /inferred from declared framework/.test(l)), 'backend uncertainty carried over');
  assert.ok(t.limitations.some((l) => /finite and curated/.test(l)));
});

test('S-001 negative: runtime authentication library declared => no S-001; dev-only or peer-only does not count and is disclosed', async () => {
  assert.ok(!has((await run(node({ express: '^4', passport: '^0.7' }))).a, 'S-001'));
  assert.ok(!has((await run(node({ express: '^4', 'passport-jwt': '^4' }))).a, 'S-001'), 'prefix match');
  const dev = (await run({ 'package.json': JSON.stringify({ dependencies: { express: '^4' }, devDependencies: { passport: '^0.7' } }) })).a;
  assert.ok(has(dev, 'S-001'));
  assert.ok(ids(dev, 'S-001')[0].observations.some((o) => /declared only in the non-runtime category "devDependencies" and is not counted/.test(o.statement)));
  const peer = (await run({ 'package.json': JSON.stringify({ dependencies: { express: '^4' }, peerDependencies: { passport: '^0.7' } }) })).a;
  assert.ok(has(peer, 'S-001'));
});

test('S-001 across ecosystems: Flask+flask-login ok, Spring+starter-security ok; Django and Hapi are NOT ASSESSED (built-in facilities)', async () => {
  assert.ok(!has((await run({ 'requirements.txt': 'flask\nflask-login\n' })).a, 'S-001'));
  assert.ok(has((await run({ 'requirements.txt': 'flask\n' })).a, 'S-001'));
  const spring = (g) => ({ 'pom.xml': `<project><dependencies><dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId></dependency>${g}</dependencies></project>` });
  assert.ok(has((await run(spring(''))).a, 'S-001'));
  assert.ok(!has((await run(spring('<dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-security</artifactId></dependency>'))).a, 'S-001'));
  const dj = (await run({ 'requirements.txt': 'django>=4\n' })).a;
  assert.ok(!has(dj, 'S-001') && !has(dj, 'E-001'));
  assert.match(notAssessed(dj, 'S-001')[0].reason, /Django includes built-in authentication facilities/);
  assert.match(notAssessed(dj, 'E-001')[0].reason, /built-in authorization facilities/);
  const hapi = (await run(node({ '@hapi/hapi': '^21' }))).a;
  assert.ok(!has(hapi, 'S-001') && notAssessed(hapi, 'S-001').length === 1);
});

test('S-001 scope: only the same module counts; an auth library in a sibling module is not credited, and the limitation says so', async () => {
  const { a } = await run({ 'api/package.json': JSON.stringify({ dependencies: { express: '^4' } }), 'auth/package.json': JSON.stringify({ dependencies: { passport: '^0.7' } }) });
  const [t] = ids(a, 'S-001');
  assert.ok(t);
  assert.strictEqual(t.relatedComponentIds.length, 1);
  assert.match(t.limitations.join(' '), /other modules, in source code, or in infrastructure is not visible/);
});

test('S-002: External Service from an SDK => threat; none without an SDK', async () => {
  const { a } = await run(node({ stripe: '^14' }));
  const [t] = ids(a, 'S-002');
  assert.strictEqual(t.target.name, 'Stripe');
  assert.strictEqual(t.basis, 'assumption-dependent');
  assert.ok(t.assumptions.some((x) => /over a network \(not established/.test(x)));
  assert.ok(!has((await run(node({ 'left-pad': '1' }))).a, 'S-002'));
});

/* ------------------------------ TAMPERING ------------------------------ */

test('T-001: mutable image references are OBSERVED threats (no tag, latest, any case); pinned/explicit/variable are not', async () => {
  const { a, architecture } = await run({
    Dockerfile: 'FROM node:latest\nFROM debian\nFROM nginx:1.25\nFROM alpine@sha256:abc123\nFROM busybox:LATEST\nFROM node:${V}\n',
  });
  const t = ids(a, 'T-001');
  assert.deepStrictEqual(t.map((x) => x.target.name).sort(), ['busybox:LATEST', 'debian', 'node:latest']);
  assert.ok(t.every((x) => x.basis === 'observed' && x.category === 'Tampering'));
  assert.strictEqual(t.find((x) => x.target.name === 'debian').observations[0].statement, 'Image reference "debian" has no tag; Docker treats this as "latest".');
  assert.match(t.find((x) => x.target.name === 'node:latest').observations[0].statement, /uses the tag "latest"/);
  assert.ok(t.every((x) => x.limitations.some((l) => /build-time base image/.test(l))), 'a build base image is not claimed to be a running service');
  assert.strictEqual(notAssessed(a, 'T-001').length, 1);
  assert.match(notAssessed(a, 'T-001')[0].reason, /variable/);
  assert.ok(t.every((x) => architecture.components.some((c) => c.id === x.target.id && c.containerRole === 'build-base-image')));
});

test('T-001: a digest pins the image even when the tag is "latest" or absent (the digest wins)', async () => {
  const { a } = await run({ Dockerfile: 'FROM node:latest@sha256:abc123\nFROM debian@sha256:def456\nFROM nginx:1.25@sha256:fed789\nFROM ubuntu:latest\n' });
  assert.deepStrictEqual(ids(a, 'T-001').map((t) => t.target.name), ['ubuntu:latest'], 'only the digest-less latest tag is reported');
});

test('T-001: a build base image carries exactly ONE "not a running service" limitation (no duplicates from V0.4 uncertainty)', async () => {
  const { a } = await run({ Dockerfile: 'FROM node:latest\n' });
  const [t] = ids(a, 'T-001');
  assert.strictEqual(t.limitations.filter((l) => /not evidence of a running service/.test(l)).length, 1);
});

test('T-001 distinguishes a compose service from a build base image and covers database services', async () => {
  const { a } = await run({ 'docker-compose.yml': 'services:\n  db:\n    image: postgres\n  web:\n    image: nginx:1.25\n  cache:\n    image: redis:latest\n  app:\n    build: .\n' });
  const t = ids(a, 'T-001');
  assert.deepStrictEqual(t.map((x) => x.target.name).sort(), ['cache', 'db']);
  assert.ok(t.every((x) => /compose service/.test(x.description) && x.limitations.some((l) => /not verified; only its declaration is known/.test(l))));
});

test('T-002: unconstrained dependencies in Node/Python/Rust are OBSERVED, aggregated per manifest; ranges, Java, Go, local and git deps are excluded', async () => {
  const { a } = await run({
    'package.json': JSON.stringify({ dependencies: { a: '*', b: 'latest', c: '', d: '^1.0.0', e: '~2', f: '>=3 <4', g: 'file:../g', h: 'workspace:*', i: 'git+https://github.com/o/r.git', j: 'npm:real@^1' } }),
    'api/requirements.txt': 'flask\nrequests==2.31.0\ndjango>=4\n',
    'rs/Cargo.toml': '[dependencies]\nserde = "*"\ntokio = "1"\nlocal = { path = "../l" }\nws = { workspace = true }\n',
    'java/pom.xml': '<project><dependencies><dependency><groupId>g</groupId><artifactId>x</artifactId></dependency></dependencies></project>',
    'go/go.mod': 'module m\nrequire github.com/a/b v1.2.3\n',
  });
  const t = ids(a, 'T-002');
  assert.deepStrictEqual(t.map((x) => x.id.split('|')[2]).sort(), ['api/requirements.txt', 'package.json', 'rs/Cargo.toml']);
  assert.ok(t.every((x) => x.basis === 'observed' && x.assumptions.length === 0 && x.limitations.some((l) => /Lockfiles are not read/.test(l))));
  const names = (x) => x.observations.map((o) => o.statement.split(' ')[0]).sort();
  assert.deepStrictEqual(names(t.find((x) => x.id.endsWith('|package.json'))), ['a', 'b', 'c']);
  assert.deepStrictEqual(names(t.find((x) => x.id.endsWith('requirements.txt'))), ['flask']);
  assert.deepStrictEqual(names(t.find((x) => x.id.endsWith('Cargo.toml'))), ['serde']);
  assert.match(t.find((x) => x.id.endsWith('package.json')).title, /^3 dependencies without a version constraint in package\.json$/);
  assert.match(t.find((x) => x.id.endsWith('requirements.txt')).title, /^1 dependency without/);
  assert.ok(t.every((x) => x.target.kind === 'component' && x.relatedComponentIds.length === x.observations.length));
  assert.ok(t.every((x) => x.relatedRelationshipIds.length === x.observations.length), 'declaration relationships referenced');
});

test('T-003: unpinned git/URL dependencies are OBSERVED; a full commit pin, local paths, aliases and registry versions are not', async () => {
  const { a } = await run({
    'package.json': JSON.stringify({ dependencies: {
      g1: 'git+https://github.com/o/r.git', g2: 'github:o/r', g3: 'o/r#main', g4: 'https://example.com/x.tgz',
      pinned: 'git+https://github.com/o/r.git#0123456789abcdef0123456789abcdef01234567',
      loc1: 'file:../x', loc2: 'link:../y', ws: 'workspace:^', al: 'npm:real@^1.0.0', reg: '^1.2.3' } }),
    'requirements.txt': 'pkg @ https://example.com/p.whl\nplain==1.0\n',
    'Cargo.toml': '[dependencies]\nfromgit = { git = "https://example.com/x.git" }\nlocal = { path = "../l" }\n',
  });
  const t = ids(a, 'T-003');
  assert.deepStrictEqual(t.map((x) => x.id.split('|')[2]).sort(), ['Cargo.toml', 'package.json', 'requirements.txt']);
  const names = (src) => t.find((x) => x.id.endsWith(src)).observations.map((o) => o.statement.split(' ')[0]).sort();
  assert.deepStrictEqual(names('package.json'), ['g1', 'g2', 'g3', 'g4']);
  assert.deepStrictEqual(names('requirements.txt'), ['pkg']);
  assert.deepStrictEqual(names('Cargo.toml'), ['fromgit']);
  assert.ok(t.every((x) => x.basis === 'observed'));
  assert.ok(t.some((x) => x.limitations.some((l) => /exact reference .* is not recorded/.test(l))));
});

test('T-004: Database component (driver-inferred or compose service) => assumption-dependent integrity threat', async () => {
  const { a } = await run({ ...node({ pg: '^8' }), 'docker-compose.yml': 'services:\n  db:\n    image: postgres:16\n' });
  const t = ids(a, 'T-004');
  assert.deepStrictEqual(t.map((x) => x.target.name).sort(), ['PostgreSQL', 'db']);
  assert.ok(t.every((x) => x.basis === 'assumption-dependent' && x.assumptions.length >= 2));
  assert.match(t.find((x) => x.target.name === 'db').observations[0].statement, /declared as a compose service/);
  assert.match(t.find((x) => x.target.name === 'PostgreSQL').observations[0].statement, /identified from a declared client library/);
  assert.ok(!has((await run(node({ sequelize: '^6', typeorm: '^0.3' }))).a, 'T-004'), 'an ORM alone does not create a Database');
});

/* ------------------------------ REPUDIATION ------------------------------ */

test('R-001: Node/Rust backend without a recognised logging library => threat; with one => none; Python/Java/Go => NOT ASSESSED', async () => {
  assert.ok(has((await run(node({ express: '^4' }))).a, 'R-001'));
  assert.ok(!has((await run(node({ express: '^4', winston: '^3' }))).a, 'R-001'));
  assert.ok(!has((await run(node({ express: '^4', pino: '^8' }))).a, 'R-001'));
  assert.ok(has((await run({ 'Cargo.toml': '[dependencies]\naxum = "0.7"\n' })).a, 'R-001'));
  assert.ok(!has((await run({ 'Cargo.toml': '[dependencies]\naxum = "0.7"\ntracing = "0.1"\n' })).a, 'R-001'));
  for (const files of [{ 'requirements.txt': 'flask\n' }, { 'go.mod': 'module m\nrequire github.com/gin-gonic/gin v1.9.1\n' },
    { 'pom.xml': '<project><dependencies><dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId></dependency></dependencies></project>' }]) {
    const { a } = await run(files);
    assert.ok(!has(a, 'R-001'));
    assert.match(notAssessed(a, 'R-001')[0].reason, /standard-library logging/);
  }
});

test('R-002: Database component => assumption-dependent attribution threat', async () => {
  const { a } = await run({ 'docker-compose.yml': 'services:\n  db:\n    image: mysql:8\n' });
  const [t] = ids(a, 'R-002');
  assert.strictEqual(t.category, 'Repudiation');
  assert.ok(t.assumptions.length >= 2);
  assert.ok(!has((await run({ 'docker-compose.yml': 'services:\n  p:\n    image: nginx:1\n' })).a, 'R-002'), 'a non-database container is not a data store');
});

/* ------------------------------ INFORMATION DISCLOSURE ------------------------------ */

test('I-001 / I-002 / I-003: database confidentiality, client-library link (a RELATIONSHIP target), external credentials', async () => {
  const { a, architecture } = await run(node({ pg: '^8', stripe: '^14' }));
  assert.ok(has(a, 'I-001'));
  const links = ids(a, 'I-002');
  assert.deepStrictEqual(links.map((t) => t.target.name).sort(), ['pg → PostgreSQL', 'stripe → Stripe']);
  for (const t of links) {
    assert.strictEqual(t.target.kind, 'relationship');
    const r = architecture.relationships.find((x) => x.id === t.target.id);
    assert.strictEqual(r.type, 'client-library-for');
    assert.strictEqual(t.relatedComponentIds.length, 2);
    assert.ok(t.relatedRelationshipIds.every((id) => architecture.relationships.some((x) => x.id === id && x.type === 'declares-dependency')));
    assert.ok(t.limitations.some((l) => /not that the application connects to the target at runtime/.test(l)));
    assert.ok(t.assumptions.some((x) => /over a network \(not established by the model\)/.test(x)));
  }
  assert.strictEqual(ids(a, 'I-003')[0].target.name, 'Stripe');
  assert.ok(ids(a, 'I-003')[0].limitations.some((l) => /not read/.test(l)));
});

/* ------------------------------ DENIAL OF SERVICE ------------------------------ */

test('D-001: backend without a rate-limiting library => threat (all ecosystems); with one => none', async () => {
  assert.ok(has((await run(node({ express: '^4' }))).a, 'D-001'));
  assert.ok(!has((await run(node({ express: '^4', 'express-rate-limit': '^7' }))).a, 'D-001'));
  assert.ok(has((await run({ 'requirements.txt': 'flask\n' })).a, 'D-001'));
  assert.ok(!has((await run({ 'requirements.txt': 'flask\nflask-limiter\n' })).a, 'D-001'));
  assert.ok(has((await run({ 'go.mod': 'module m\nrequire github.com/gin-gonic/gin v1.9.1\n' })).a, 'D-001'));
  assert.ok(!has((await run({ 'go.mod': 'module m\nrequire github.com/gin-gonic/gin v1.9.1\nrequire golang.org/x/time v0.5.0\n' })).a, 'D-001'));
  assert.ok(has((await run({ 'Cargo.toml': '[dependencies]\naxum = "0.7"\n' })).a, 'D-001'));
});

test('D-002: dependency on a database / external service via a client library => relationship threat', async () => {
  const { a } = await run(node({ redis: '^4', openai: '^4' }));
  assert.deepStrictEqual(ids(a, 'D-002').map((t) => t.target.name).sort(), ['openai → OpenAI', 'redis → Redis']);
  assert.ok(ids(a, 'D-002').every((t) => t.target.kind === 'relationship' && t.assumptions.length >= 2));
});

/* ------------------------------ ELEVATION OF PRIVILEGE ------------------------------ */

test('E-001: backend without an authorization library => threat; casbin / Spring Security satisfy it; E-002 only for Database targets', async () => {
  assert.ok(has((await run(node({ express: '^4', passport: '^0.7' }))).a, 'E-001'), 'authentication alone is not authorization');
  assert.ok(!has((await run(node({ express: '^4', casbin: '^5' }))).a, 'E-001'));
  assert.ok(!has((await run(node({ express: '^4', '@casl/ability': '^6' }))).a, 'E-001'));
  const { a } = await run(node({ pg: '^8', stripe: '^14' }));
  assert.deepStrictEqual(ids(a, 'E-002').map((t) => t.target.name), ['pg → PostgreSQL'], 'External Service targets are excluded from E-002');
});

/* ------------------------------ all six categories, together ------------------------------ */

test('all six STRIDE categories are produced for a representative project, in STRIDE order', async () => {
  const { a } = await run({ ...node({ express: '^4', pg: '*', stripe: '^14' }), Dockerfile: 'FROM node:latest\n' });
  const cats = [...new Set(a.threats.map((t) => t.category))];
  assert.deepStrictEqual(cats, [...STRIDE_CATEGORIES]);
  const order = a.threats.map((t) => STRIDE_CATEGORIES.indexOf(t.category));
  assert.deepStrictEqual(order, [...order].sort((x, y) => x - y));
});

/* ------------------------------ negative cases ------------------------------ */

test('negatives: empty workspace, no manifests, library-only, frontend-only, dev-only and build-only produce no threats', async () => {
  for (const files of [{}, { 'src/a.txt': 'x' }, node({ 'left-pad': '^1.3.0', lodash: '4.17.21' }), node({ react: '^18', 'react-dom': '^18' }),
    { 'package.json': JSON.stringify({ devDependencies: { express: '^4', pg: '^8', stripe: '^14' } }) },
    { 'docker-compose.yml': 'services:\n  web:\n    build: .\n' }, { Dockerfile: 'FROM scratch\n' }]) {
    const { a } = await run(files);
    assert.deepStrictEqual(a.threats, [], JSON.stringify(Object.keys(files)));
    assert.deepStrictEqual(a.warnings, []);
  }
});

test('frontend components get no rules (not assessed globally), so a frontend never produces invented threats', async () => {
  const { a, architecture } = await run(node({ react: '^18' }));
  assert.ok(architecture.components.some((c) => c.type === 'Frontend'));
  assert.strictEqual(a.threats.length, 0);
  assert.ok(a.limitations.some((l) => /Frontend-specific threats/.test(l)));
});

test('no runtime connection, boundary, flow or topology is ever asserted in a threat', async () => {
  const { a } = await run({ ...node({ express: '^4', react: '^18', pg: '^8', stripe: '^14' }), 'docker-compose.yml': 'services:\n  db:\n    image: postgres\n' });
  assert.ok(a.threats.length > 10);
  for (const t of a.threats) {
    const text = [t.title, t.description, ...t.observations.map((o) => o.statement)].join(' ');
    assert.ok(!/trust boundar|data flow|network (segment|topology)|DMZ|internet-facing|publicly exposed/i.test(text), text);
    assert.ok(!t.relatedComponentIds.concat([t.target.id]).some((id) => /frontend:/.test(id) && /backend:/.test(t.target.id)));
  }
});

/* ------------------------------ invariants over varied projects ------------------------------ */

const BANNED = /\b(vulnerable|vulnerabilit\w*|exploit\w*|confirmed|proves?|proven|definitely|insecure)\b/i;
const OUT_OF_SCOPE = /\b(severity|likelihood|priority|risk score|CVE-\d+|mitigat\w*|recommend\w*|remediat\w*)\b/i;
const PROJECTS = {
  node: { ...node({ express: '^4', react: '^18', pg: '*', stripe: 'latest', priv: 'git+https://github.com/o/r.git' }), Dockerfile: 'FROM node:latest\nFROM nginx:1.25\n' },
  monorepo: { 'package.json': '{"dependencies":{"a":"*"}}', 'web/package.json': '{"dependencies":{"react":"^18","express":"^4"}}', 'api/requirements.txt': 'flask\nredis==5\n', 'svc/go.mod': 'module m\ngo 1.21\nrequire github.com/gin-gonic/gin v1.9.1\n', 'svc/Dockerfile': 'FROM golang\n' },
  compose: { 'docker-compose.yml': 'services:\n  db:\n    image: postgres\n  q:\n    image: rabbitmq:3\n  c:\n    image: redis:7\n' },
  malformed: { 'package.json': '{ nope', 'Cargo.toml': '[x', 'pom.xml': 'garbage', Dockerfile: 'FROM', 'requirements.txt': '\u0000\u0001' },
  mixed: { 'package.json': '{"dependencies":{"express":"^4"}}', 'bad/package.json': '{', 'Dockerfile': 'FROM node:${V}\n' },
};
for (const [name, files] of Object.entries(PROJECTS)) {
  test(`invariants hold for project "${name}"`, async () => {
    const root = makeProject(files);
    const r = await analyzeProject(root, 'proj');
    const a = analyzeStride(r.architecture);
    const m = r.architecture;
    const elementIds = new Set([...m.components.map((c) => c.id), ...m.relationships.map((x) => x.id)]);
    const known = new Set([...r.scan.files, '.']);
    assert.strictEqual(new Set(a.threats.map((t) => t.id)).size, a.threats.length, 'unique threat ids');
    for (const t of a.threats) {
      assert.match(t.id, /^threat:STRIDE-[STRIDE]-\d{3}\|/);
      assert.ok(t.id.startsWith(`threat:${t.ruleId}|${t.target.id}`));
      assert.ok(STRIDE_CATEGORIES.includes(t.category) && t.title && t.description);
      assert.ok(elementIds.has(t.target.id), `${t.id}: target in model`);
      for (const id of [...t.relatedComponentIds, ...t.relatedRelationshipIds]) assert.ok(elementIds.has(id), `${t.id}: related ${id}`);
      assert.ok(t.observations.length >= 1 && t.limitations.length >= 1);
      if (t.basis === 'assumption-dependent') {
        assert.ok(t.assumptions.length >= 1, `${t.id}: assumptions`);
        assert.match(t.description, /\b(if|could|might|may)\b/i, `${t.id}: conditional wording`);
      }
      for (const o of t.observations) {
        assert.ok(o.statement.length > 0 && o.evidence.length >= 1);
        for (const e of o.evidence) {
          assert.ok(known.has(e.source), `${t.id}: evidence source ${e.source}`);
          assert.ok(!path.isAbsolute(e.source) && !e.source.includes('\\') && e.rule && e.description);
        }
      }
      assert.strictEqual(new Set(t.limitations).size, t.limitations.length, `${t.id}: duplicate limitation`);
      assert.strictEqual(new Set(t.assumptions).size, t.assumptions.length, `${t.id}: duplicate assumption`);
      for (const o of t.observations) assert.ok((o.statement.match(/\binferred\b/gi) ?? []).length <= 1, `${t.id}: wording repeats "inferred": ${o.statement}`);
      const all = [t.title, t.description, ...t.observations.map((o) => o.statement), ...t.assumptions, ...t.limitations].join('\n');
      assert.ok(!BANNED.test(all), `banned wording in ${t.id}: ${all.match(BANNED)}`);
      assert.ok(!OUT_OF_SCOPE.test(all), `out-of-scope wording in ${t.id}: ${all.match(OUT_OF_SCOPE)}`);
      assert.ok(!all.includes(root) && !/[\u0000-\u001f]/.test(all.replace(/\n/g, ' ')));
    }
    for (const n of a.notAssessed) {
      assert.ok(STRIDE_RULES.some((x) => x.id === n.ruleId) && n.reason.length > 10);
    }
    assert.deepStrictEqual(a.limitations, [...GLOBAL_LIMITATIONS]);
  });
}

test('malformed projects: analysis still runs, warns that the model is incomplete, and never crashes', async () => {
  const { a } = await run(PROJECTS.malformed);
  assert.ok(a.warnings.some((w) => /may be incomplete/.test(w)));
  assert.ok(a.threats.every((t) => t.ruleId));
});

test('threat evidence is a copy: mutating the analysis never alters the architecture model', async () => {
  const r = await analyzeProject(makeProject(node({ express: '^4' })), 'p');
  const before = JSON.stringify(r.architecture);
  const a = analyzeStride(r.architecture);
  assert.strictEqual(JSON.stringify(r.architecture), before, 'analysis does not mutate the model');
  for (const t of a.threats) for (const o of t.observations) for (const e of o.evidence) { e.description = 'MUTATED'; if (e.detail) e.detail.name = 'MUTATED'; }
  assert.strictEqual(JSON.stringify(r.architecture), before, 'mutating threat evidence does not leak into the model');
});

/* ------------------------------ determinism ------------------------------ */

function permute(arr, seed) { // deterministic pseudo-random permutation
  const out = [...arr]; let s = seed;
  for (let i = out.length - 1; i > 0; i--) { s = (s * 1103515245 + 12345) & 0x7fffffff; const j = s % (i + 1); [out[i], out[j]] = [out[j], out[i]]; }
  return out;
}

test('identical inputs give identical output; output is independent of model array order and of workspace location', async () => {
  const files = { ...PROJECTS.monorepo, ...PROJECTS.compose, ...PROJECTS.node };
  const r1 = await analyzeProject(makeProject(files), 'proj');
  const r2 = await analyzeProject(makeProject(Object.fromEntries([...Object.entries(files)].reverse())), 'proj');
  const base = JSON.stringify(analyzeStride(r1.architecture));
  assert.ok(analyzeStride(r1.architecture).threats.length > 20);
  assert.strictEqual(JSON.stringify(analyzeStride(r1.architecture)), base, 'same model twice');
  assert.strictEqual(JSON.stringify(analyzeStride(r2.architecture)), base, 'different location and creation order');
  for (const seed of [1, 7, 42, 1234]) {
    const shuffled = { ...r1.architecture, components: permute(r1.architecture.components, seed), relationships: permute(r1.architecture.relationships, seed + 1) };
    assert.strictEqual(JSON.stringify(analyzeStride(shuffled)), base, `shuffled model (seed ${seed})`);
  }
});

test('output order does not depend on the order in which rules are evaluated', async () => {
  const r = await analyzeProject(makeProject({ ...PROJECTS.monorepo, ...PROJECTS.compose, ...PROJECTS.node }), 'proj');
  const base = JSON.stringify(analyzeStride(r.architecture));
  assert.strictEqual(JSON.stringify(analyzeStride(r.architecture, [...STRIDE_RULES].reverse())), base);
  assert.strictEqual(JSON.stringify(analyzeStride(r.architecture, permute(STRIDE_RULES, 99))), base);
});

/* ------------------------------ engine robustness (hand-built models) ------------------------------ */

test('empty model => no threats, a warning, global limitations still reported', () => {
  const a = analyzeStride(model([]));
  assert.deepStrictEqual(a.threats, []);
  assert.match(a.warnings[0], /model is empty/);
  assert.deepStrictEqual(a.limitations, [...GLOBAL_LIMITATIONS]);
});

test('missing information is reported as NOT ASSESSED, not guessed: backend without module / without framework / dangling relationship', () => {
  const noModule = analyzeStride(model([comp('backend:.', 'Backend', 'Backend (Express)', { technologies: [expressTech] })]));
  assert.ok(!has(noModule, 'S-001'));
  assert.match(notAssessed(noModule, 'S-001')[0].reason, /no containing module/);

  const noTech = analyzeStride(model([comp('app:.', 'Application', 'proj'), comp('backend:.', 'Backend', 'B')], [rel('contains', 'app:.', 'backend:.')]));
  assert.ok(!has(noTech, 'S-001'));
  assert.match(notAssessed(noTech, 'S-001')[0].reason, /no identifying framework dependency/);

  const dangling = analyzeStride(model([comp('lib:x', 'Library/Dependency', 'x')], [rel('client-library-for', 'lib:x', 'db:missing')]));
  assert.ok(!has(dangling, 'I-002'));
  assert.match(notAssessed(dangling, 'I-002')[0].reason, /missing from the model/);
});

test('hand-built model: a Backend inside a module with no auth library is reported; adding one removes the threat', () => {
  const base = [comp('app:.', 'Application', 'proj', { evidence: [{ kind: 'manifest-file', source: 'package.json', rule: 'project-manifest', description: 'Project manifest package.json is present.' }] }), comp('backend:.', 'Backend', 'Backend (Express)', { technologies: [expressTech] })];
  const rels = [rel('contains', 'app:.', 'backend:.')];
  assert.ok(has(analyzeStride(model(base, rels)), 'S-001'));
  const passport = comp('lib:passport', 'Library/Dependency', 'passport', { technologies: [{ ...expressTech, name: 'passport', version: '^0.7' }] });
  assert.ok(!has(analyzeStride(model([...base, passport], [...rels, rel('declares-dependency', 'app:.', 'lib:passport')])), 'S-001'));
});

test('a throwing rule is isolated: a warning is recorded and every other rule still reports', () => {
  const boom = { id: 'STRIDE-X-999', category: 'Spoofing', basis: 'observed', summary: 'x', evaluate() { throw new Error("boom at /home/bob/p/secret.txt"); } };
  const r = analyzeStride(model([comp('app:.', 'Application', 'proj'), comp('db:x', 'Database', 'PG')]), [boom, ...STRIDE_RULES]);
  assert.ok(r.warnings.some((w) => /Rule STRIDE-X-999 could not be evaluated: boom at <path>/.test(w)), 'error text sanitised');
  assert.ok(r.threats.some((t) => t.ruleId === 'STRIDE-T-004'), 'other rules unaffected');
});

test('engine enforces the invariants: incomplete or dangling threats are dropped with a warning, never emitted', () => {
  const mk = (patch) => ({ id: 'STRIDE-X-001', category: 'Tampering', basis: 'assumption-dependent', summary: 'x', evaluate: () => [{
    kind: 'threat', target: { kind: 'component', id: 'app:.', name: 'proj' }, title: 't', description: 'd',
    observations: [{ statement: 's', evidence: [ev()] }], assumptions: ['a'], limitations: ['l'], ...patch }] });
  const m = model([comp('app:.', 'Application', 'proj')]);
  assert.strictEqual(analyzeStride(m, [mk({})]).threats.length, 1, 'a complete threat passes');
  for (const [patch, why] of [
    [{ observations: [] }, /no evidenced observation/], [{ observations: [{ statement: 's', evidence: [] }] }, /no evidenced observation/],
    [{ limitations: [] }, /states no limitation/], [{ assumptions: [] }, /states no assumption/],
    [{ relatedComponentIds: ['ghost'] }, /not in the model/], [{ target: { kind: 'component', id: 'ghost', name: 'g' } }, /not in the model/],
  ]) {
    const r = analyzeStride(m, [mk(patch)]);
    assert.strictEqual(r.threats.length, 0, why.source);
    assert.ok(r.warnings.some((w) => why.test(w)), why.source);
  }
  const dup = { id: 'STRIDE-X-002', category: 'Tampering', basis: 'observed', summary: 'x', evaluate: () => { const f = mk({}).evaluate()[0]; return [f, f]; } };
  const r = analyzeStride(m, [dup]);
  assert.strictEqual(r.threats.length, 1);
  assert.ok(r.warnings.some((w) => /identifier is not unique/.test(w)));
});

test('model warnings propagate as an analysis warning (uncertainty is not hidden)', () => {
  const a = analyzeStride(model([comp('app:.', 'Application', 'proj')], [], ['Manifest x could not be read']));
  assert.ok(a.warnings.some((w) => /1 warning\(s\) and may be incomplete/.test(w)));
});

/* ------------------------------ summary + formatting ------------------------------ */

test('summarizeStride counts agree with the threats', async () => {
  const { a } = await run(PROJECTS.node);
  const s = summarizeStride(a);
  assert.strictEqual(s.threatCount, a.threats.length);
  assert.strictEqual(Object.values(s.byCategory).reduce((x, y) => x + y, 0), a.threats.length);
  assert.strictEqual(Object.values(s.byBasis).reduce((x, y) => x + y, 0), a.threats.length);
  assert.strictEqual(s.notAssessedCount, a.notAssessed.length);
});

test('report: states these are candidates, groups by category, separates observed/assumed/limitation, lists not-assessed and limitations', async () => {
  const { a } = await run({ ...PROJECTS.node, 'dj/requirements.txt': 'django\n' });
  const text = formatStrideReport(a).join('\n');
  assert.match(text, /^STRIDE Threat Analysis/);
  assert.match(text, /not confirmed vulnerabilities, and they are not prioritised or scored/);
  assert.match(text, new RegExp(`Candidate Threats \\(${a.threats.length}\\):`));
  for (const c of STRIDE_CATEGORIES) assert.match(text, new RegExp(`${c}: \\d+`));
  assert.match(text, /Basis: \d+ observed condition\(s\), \d+ assumption-dependent/);
  assert.match(text, /• STRIDE-T-001  Container image reference is mutable: node:latest/);
  assert.match(text, /basis: observed/);
  assert.match(text, /\n {6}observed: /);
  assert.match(text, /\n {8}evidence: .*\[rule: /);
  assert.match(text, /\n {6}assumed: /);
  assert.match(text, /\n {6}limitation: /);
  assert.match(text, /Not Assessed \(\d+\) — required information is missing:/);
  assert.match(text, /Django includes built-in authentication facilities/);
  assert.match(text, /Analysis Limitations:\n {2}• The architecture model establishes no data flows and no trust boundaries/);
  assert.match(text, /STRIDE analysis completed successfully\.$/);
  assert.match(formatStrideSummary(a), new RegExp(`^STRIDE: ${a.threats.length} candidate threats for review\\.$`));
  assert.match(formatStrideSummary(emptyStrideAnalysis('x')), /^STRIDE: 0 candidate threats for review\.$/);
});

test('report: empty analysis and warnings are rendered honestly', () => {
  const text = formatStrideReport(emptyStrideAnalysis('boom')).join('\n');
  assert.match(text, /Candidate Threats \(0\):\n {2}None/);
  assert.match(text, /• boom/);
  assert.match(text, /completed with warnings; no candidate threats were produced\./);
});

test('report: very long listings are capped with an explicit count; control characters in names cannot forge lines', async () => {
  const compose = ['services:']; for (let i = 0; i < 70; i++) compose.push(`  s${i}:`, `    image: busybox`);
  const big = (await run({ 'docker-compose.yml': compose.join('\n') })).a;
  assert.ok(big.threats.length >= 70);
  const text = formatStrideReport(big).join('\n');
  assert.match(text, /… and \d+ more candidate threat\(s\) not listed\./);
  assert.strictEqual((text.match(/• STRIDE-T-001 /g) ?? []).length, 60);

  const evil = 'evil\nSTRIDE analysis completed successfully.\u001b[2J';
  const hostile = (await run({ 'package.json': JSON.stringify({ dependencies: { [evil]: '*' } }) })).a;
  assert.ok(hostile.threats.some((t) => t.observations.some((o) => o.statement.includes('\n'))), 'raw data does contain the newline');
  const lines = formatStrideReport(hostile);
  assert.ok(lines.every((l) => !/[\u0000-\u001f]/.test(l)));
  assert.strictEqual(lines.filter((l) => l === 'STRIDE analysis completed successfully.').length, 1);
});

/* ============================== integration: pipeline + command ============================== */

const Module = require('module');
const fs = require('fs');

async function runCommand(folders, { patch } = {}) {
  const ui = { out: [], info: [], warn: [], err: [] };
  let handler;
  const mock = {
    window: {
      createOutputChannel: () => ({ appendLine: (l) => ui.out.push(l), clear: () => { ui.out.length = 0; }, show() {}, dispose() {} }),
      showInformationMessage: (m) => ui.info.push(m), showWarningMessage: (m) => ui.warn.push(m), showErrorMessage: (m) => ui.err.push(m),
    },
    workspace: { workspaceFolders: folders },
    commands: { registerCommand: (id, h) => { assert.strictEqual(id, 'securityArchitectureAssessment.analyzeProject'); handler = h; return { dispose() {} }; } },
  };
  const originalLoad = Module._load;
  Module._load = function (request, ...rest) { return request === 'vscode' ? mock : originalLoad.call(this, request, ...rest); };
  const restore = patch ? patch() : () => {};
  try {
    delete require.cache[require.resolve(path.join(OUT, 'extension.js'))];
    require(path.join(OUT, 'extension.js')).activate({ subscriptions: [] });
    await handler();
  } finally { restore(); Module._load = originalLoad; }
  return ui;
}
const stub = (modulePath, name, impl) => () => {
  const mod = require(path.join(OUT, modulePath));
  const original = mod[name];
  Object.defineProperty(mod, name, { value: impl, configurable: true });
  return () => Object.defineProperty(mod, name, { value: original, configurable: true });
};
const folderFor = (files, name = 'proj') => [{ name, uri: { scheme: 'file', fsPath: makeProject(files) } }];

test('analyzeProject exposes the V0.5 analysis, identical to analyzing its own architecture model', async () => {
  const r = await analyzeProject(makeProject(PROJECTS.node), 'proj');
  assert.ok(r.stride && Array.isArray(r.stride.threats) && r.stride.threats.length > 5);
  assert.deepStrictEqual(r.stride, analyzeStride(r.architecture));
  assert.ok(r.scan && r.technology && r.architecture, 'V0.2-V0.4 results are still present');
});

test('a V0.5 failure never discards V0.2-V0.4 results: empty analysis with a warning, no exception', async () => {
  const restore = stub('stride/strideAnalyzer.js', 'analyzeStride', () => { throw new Error('analyzer bug in /home/bob/p/x.json'); })();
  let r;
  try {
    delete require.cache[require.resolve(path.join(OUT, 'analyzeProject.js'))];
    r = await require(path.join(OUT, 'analyzeProject.js')).analyzeProject(makeProject(node({ express: '^4' })), 'p');
  } finally { restore(); delete require.cache[require.resolve(path.join(OUT, 'analyzeProject.js'))]; }
  assert.strictEqual(r.scan.fileCount, 1);
  assert.strictEqual(r.technology.dependencies.length, 1);
  assert.ok(r.architecture.components.length >= 2);
  assert.deepStrictEqual(r.stride.threats, []);
  assert.match(r.stride.warnings[0], /STRIDE analysis failed unexpectedly: analyzer bug in <path>/);
});

test('a V0.4 failure leaves V0.2/V0.3 results and yields an honest "model is empty" STRIDE result', async () => {
  const restore = stub('architecture/architectureModelBuilder.js', 'buildArchitectureModel', () => { throw new Error('builder bug'); })();
  let r;
  try {
    delete require.cache[require.resolve(path.join(OUT, 'analyzeProject.js'))];
    r = await require(path.join(OUT, 'analyzeProject.js')).analyzeProject(makeProject(node({ express: '^4' })), 'p');
  } finally { restore(); delete require.cache[require.resolve(path.join(OUT, 'analyzeProject.js'))]; }
  assert.strictEqual(r.technology.dependencies.length, 1);
  assert.deepStrictEqual(r.stride.threats, []);
  assert.match(r.stride.warnings[0], /model is empty/);
});

test('command: the STRIDE section follows the architecture section; the toast reports the candidate-threat count', async () => {
  const ui = await runCommand(folderFor(PROJECTS.node));
  const text = ui.out.join('\n');
  const at = (re) => text.search(re);
  assert.ok(at(/Security Architecture Scan/) < at(/Technology \/ Dependency Detection/));
  assert.ok(at(/Technology \/ Dependency Detection/) < at(/Security Architecture Model/));
  assert.ok(at(/Security Architecture Model/) < at(/STRIDE Threat Analysis/));
  assert.match(text, /Candidate Threats \(\d+\):/);
  assert.match(text, /STRIDE analysis completed successfully\./);
  assert.match(ui.info[ui.info.length - 1], /STRIDE: \d+ candidate threats for review\.$/);
  assert.match(ui.info[0], /Architecture model: \d+ components, \d+ relationships\. STRIDE: /);
  assert.strictEqual(ui.err.length, 0);
});

test('command: empty workspace and no workspace behave safely', async () => {
  const empty = await runCommand(folderFor({}));
  assert.match(empty.out.join('\n'), /Candidate Threats \(0\):\n {2}None/);
  assert.strictEqual(empty.err.length, 0);
  const none = await runCommand(undefined);
  assert.deepStrictEqual(none.warn, ['Please open a workspace before running the security analysis.']);
});

test('command: an analyzer failure shows the earlier sections and a warning, with no error toast', async () => {
  const ui = await runCommand(folderFor(node({ express: '^4' })), { patch: stub('stride/strideAnalyzer.js', 'analyzeStride', () => { throw new Error('boom'); }) });
  const text = ui.out.join('\n');
  assert.match(text, /Security Architecture Scan/);
  assert.match(text, /Security Architecture Model/);
  assert.match(text, /STRIDE analysis failed unexpectedly: boom/);
  assert.match(text, /completed with warnings; no candidate threats were produced\./);
  assert.strictEqual(ui.err.length, 0);
  assert.strictEqual(ui.info.length, 1);
});

test('command: a STRIDE formatter failure is replaced by a notice; earlier sections and the toast survive', async () => {
  const ui = await runCommand(folderFor(node({ express: '^4' })), { patch: stub('stride/formatStrideAnalysis.js', 'formatStrideReport', () => { throw new Error('formatter bug'); }) });
  const text = ui.out.join('\n');
  assert.match(text, /Security Architecture Scan/);
  assert.match(text, /Architecture model built successfully\./);
  assert.match(text, /STRIDE threat analysis: this section could not be displayed \(formatter bug\)/);
  assert.strictEqual(ui.err.length, 0);
  assert.strictEqual(ui.info.length, 1);
  assert.match(ui.info[0], /STRIDE: \d+ candidate threats/);
});

test('command: hostile names cannot forge lines in the STRIDE section; no absolute path is shown', async () => {
  const evil = 'evil\nSTRIDE analysis completed successfully.\u001b[2J';
  const folders = folderFor({ 'package.json': JSON.stringify({ dependencies: { [evil]: '*' } }) });
  const ui = await runCommand(folders);
  assert.ok(ui.out.every((l) => !/[\u0000-\u001f]/.test(l)));
  assert.strictEqual(ui.out.filter((l) => l === 'STRIDE analysis completed successfully.').length, 1);
  assert.ok(![...ui.out, ...ui.info].join('\n').includes(folders[0].uri.fsPath));
});

test('secrets: values from compose environment, Dockerfile ENV/ARG, .env files and URL credentials never reach STRIDE output', async () => {
  const files = {
    'package.json': JSON.stringify({ dependencies: { express: '^4', priv: 'git+https://user:ghp_STRIDESECRET1@github.com/o/r.git', pg: '*' } }),
    'docker-compose.yml': 'services:\n  db:\n    image: postgres\n    environment:\n      POSTGRES_PASSWORD: STRIDESECRET2\n    env_file: .env\n',
    Dockerfile: 'FROM node:latest\nENV API_TOKEN=STRIDESECRET3\nARG NPM_TOKEN=STRIDESECRET4\n',
    '.env': 'DB_PASSWORD=STRIDESECRET5\n',
  };
  const r = await analyzeProject(makeProject(files), 'proj');
  assert.ok(r.stride.threats.length > 5);
  assert.ok(!/STRIDESECRET/.test(JSON.stringify(r.stride) + formatStrideReport(r.stride).join('\n')));
  const ui = await runCommand(folderFor(files));
  assert.ok(!/STRIDESECRET/.test([...ui.out, ...ui.info].join('\n')));
});

test('V0.5 stays offline and read-only: no network/process modules and no file writes in src/stride', () => {
  const dir = path.join(__dirname, '..', 'src', 'stride');
  for (const f of fs.readdirSync(dir).filter((x) => x.endsWith('.ts'))) {
    const src = fs.readFileSync(path.join(dir, f), 'utf8');
    assert.ok(!/require\(['"](https?|net|dgram|child_process|tls|dns|fs)['"]\)|from ['"](https?|net|dgram|child_process|tls|dns|fs|node:\w+)['"]|\bfetch\(|XMLHttpRequest|writeFile|appendFile/.test(src), `forbidden API in ${f}`);
  }
});

/* ============================== documentation + version ============================== */

test('docs/stride-rules.md documents every rule, category, recognised control library and global limitation', () => {
  const doc = fs.readFileSync(path.join(__dirname, '..', 'docs', 'stride-rules.md'), 'utf8');
  for (const r of STRIDE_RULES) assert.ok(doc.includes(`\`${r.id}\``), `rule ${r.id} missing from the docs`);
  for (const c of STRIDE_CATEGORIES) assert.ok(doc.includes(c), `category ${c} missing`);
  for (const [kind, byEco] of Object.entries(CONTROL_LIBRARIES)) {
    assert.ok(doc.includes(`### ${kind}`), `control section ${kind}`);
    for (const [eco, entry] of Object.entries(byEco)) {
      assert.ok(doc.includes(`**${eco}**`));
      for (const n of entry.exact ?? []) assert.ok(doc.includes(`\`${n}\``), `${kind}/${eco}: ${n} missing from the docs`);
      for (const n of entry.prefix ?? []) assert.ok(doc.includes(`\`${n}…\` (prefix)`), `${kind}/${eco}: prefix ${n} missing from the docs`);
    }
  }
  for (const l of GLOBAL_LIMITATIONS) assert.ok(doc.includes(l), `limitation missing: ${l.slice(0, 50)}`);
  assert.match(doc, /not\*\* a confirmed vulnerability/);
  assert.ok(!/\bTODO\b|\bTBD\b/.test(doc));
  // every table row has the same number of unescaped separators as its header
  const rows = doc.split('\n').filter((l) => /^\| /.test(l));
  const count = (l) => (l.match(/(^|[^\\])\|/g) ?? []).length;
  const rulesTable = rows.filter((l) => /^\| `STRIDE-/.test(l) || /^\| Rule /.test(l));
  assert.ok(rulesTable.length === 16 && new Set(rulesTable.map(count)).size === 1, 'rule table rows are well-formed');
});

test('the extension version is 0.5.0 in package.json and package-lock.json, and npm test runs every suite', () => {
  const pkg = require('../package.json');
  const lock = require('../package-lock.json');
  assert.strictEqual(pkg.version, '0.5.0');
  assert.strictEqual(lock.version, '0.5.0');
  assert.strictEqual(lock.packages[''].version, '0.5.0');
  for (const f of ['v02-regression', 'v03-technology', 'v04-architecture', 'v04-audit', 'v05-stride']) assert.ok(pkg.scripts.test.includes(`test/${f}.test.js`), `${f} is part of npm test`);
});
