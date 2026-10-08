import { DetectedDependency, DetectedTechnology, ManifestParseError, ManifestParser, emptyOutput } from '../types';

/* ============================== pom.xml ============================== */
/*
 * Targeted text extraction (no XML library, no external entities, no network).
 * Handles: <parent>, <dependencies>, <dependencyManagement>, plugin dependencies,
 * <exclusions> (ignored), XML comments, and ${property} versions defined in the same file.
 * Does NOT resolve parent POMs, imported BOMs or inherited versions.
 */

interface Range {
  start: number;
  end: number;
}

export const parsePom: ManifestParser = (content, source) => {
  const xml = content.replace(/^\uFEFF/, '').replace(/<!--[\s\S]*?-->/g, (m) => ' '.repeat(m.length));
  if (!/<project[\s>]/.test(xml)) {
    throw new ManifestParseError('Not a Maven POM (no <project> element found).');
  }

  const out = emptyOutput();
  const properties = readProperties(xml);
  const managed = ranges(xml, 'dependencyManagement');
  const plugins = ranges(xml, 'plugin');
  const inside = (list: Range[], index: number): boolean => list.some((r) => index >= r.start && index < r.end);

  // <parent>
  const parentMatch = /<parent>([\s\S]*?)<\/parent>/.exec(xml);
  if (parentMatch) {
    const dep = toDependency(parentMatch[1], 'parent', source, properties);
    if (dep) out.dependencies.push(dep);
  }

  let skipped = 0;
  const depRegex = /<dependency>([\s\S]*?)<\/dependency>/g;
  for (let m = depRegex.exec(xml); m !== null; m = depRegex.exec(xml)) {
    const body = m[1].replace(/<exclusions>[\s\S]*?<\/exclusions>/g, '');
    let category: string | undefined;
    if (inside(managed, m.index)) category = 'dependencyManagement';
    else if (inside(plugins, m.index)) category = 'plugin-dependency';
    const dep = toDependency(body, category, source, properties);
    if (dep) out.dependencies.push(dep);
    else skipped++;
  }
  if (skipped > 0) {
    out.warnings.push(`${source}: ${skipped} <dependency> entr${skipped === 1 ? 'y' : 'ies'} without groupId/artifactId skipped.`);
  }

  const javaTech = readJavaVersion(properties, source);
  if (javaTech) out.technologies.push(javaTech);
  return out;
};

function ranges(xml: string, tag: string): Range[] {
  const found: Range[] = [];
  const regex = new RegExp(`<${tag}[\\s>][\\s\\S]*?</${tag}>`, 'g');
  for (let m = regex.exec(xml); m !== null; m = regex.exec(xml)) {
    found.push({ start: m.index, end: m.index + m[0].length });
  }
  return found;
}

function tagValue(body: string, tag: string): string | undefined {
  const m = new RegExp(`<${tag}>\\s*([^<]*?)\\s*</${tag}>`).exec(body);
  return m && m[1] !== '' ? m[1] : undefined;
}

function toDependency(
  body: string,
  forcedCategory: string | undefined,
  source: string,
  properties: Map<string, string>
): DetectedDependency | undefined {
  const groupId = tagValue(body, 'groupId');
  const artifactId = tagValue(body, 'artifactId');
  if (!groupId || !artifactId) {
    return undefined;
  }
  const version = tagValue(body, 'version') ?? null;
  const scope = tagValue(body, 'scope');
  const notes: string[] = [];
  if (forcedCategory === 'dependencyManagement' && scope) notes.push(`scope=${scope}`);
  if (version === null && forcedCategory !== 'parent') notes.push('no version declared (may be managed elsewhere)');

  const dep: DetectedDependency = {
    name: `${groupId}:${artifactId}`,
    version,
    ecosystem: 'Java',
    category: forcedCategory ?? scope ?? 'dependencies',
    source,
  };
  const propertyRef = version === null ? null : /^\$\{([^}]+)\}$/.exec(version);
  if (propertyRef) {
    const resolved = properties.get(propertyRef[1]);
    if (resolved !== undefined && !resolved.includes('${')) {
      dep.resolvedVersion = resolved;
    } else {
      notes.push(`property "${propertyRef[1]}" not defined with a literal value in this file`);
    }
  }
  if (notes.length > 0) dep.notes = notes.join('; ');
  return dep;
}

function readProperties(xml: string): Map<string, string> {
  const map = new Map<string, string>();
  const block = /<properties>([\s\S]*?)<\/properties>/.exec(xml);
  if (block) {
    const entry = /<([A-Za-z0-9_.-]+)>\s*([^<]*?)\s*<\/\1>/g;
    for (let m = entry.exec(block[1]); m !== null; m = entry.exec(block[1])) {
      map.set(m[1], m[2]);
    }
  }
  return map;
}

function readJavaVersion(properties: Map<string, string>, source: string): DetectedTechnology | undefined {
  for (const key of ['maven.compiler.release', 'java.version', 'maven.compiler.source']) {
    const value = properties.get(key);
    if (value) {
      return { name: 'Java', version: value, ecosystem: 'Java', source, reference: key };
    }
  }
  return undefined;
}

/* ===================== build.gradle / build.gradle.kts ===================== */
/*
 * Regex extraction of the common dependency notations:
 *   implementation 'g:a:v'  |  implementation("g:a:v")  |  implementation platform("g:a:v")
 *   implementation group: 'g', name: 'a', version: 'v'
 * Version catalogs (libs.foo), project(...) and files(...) are not resolvable here.
 */

const GRADLE_CONFIGURATIONS = [
  'implementation', 'api', 'compileOnly', 'runtimeOnly', 'compile', 'runtime',
  'testImplementation', 'testCompileOnly', 'testRuntimeOnly', 'testCompile', 'testRuntime',
  'annotationProcessor', 'testAnnotationProcessor', 'kapt', 'ksp', 'classpath',
  'developmentOnly', 'providedCompile', 'providedRuntime', 'debugImplementation',
  'releaseImplementation', 'androidTestImplementation', 'compileOnlyApi',
];
const CONFIG_ALT = GRADLE_CONFIGURATIONS.join('|');

const STRING_NOTATION = new RegExp(
  `\\b(${CONFIG_ALT})\\s*\\(?\\s*((?:enforced)?[Pp]latform\\s*\\(\\s*)?(['"])([^'"\\r\\n]+)\\3`,
  'g'
);
const MAP_NOTATION = new RegExp(
  `\\b(${CONFIG_ALT})\\s*\\(?\\s*group\\s*[:=]\\s*['"]([^'"]+)['"]\\s*,\\s*name\\s*[:=]\\s*['"]([^'"]+)['"](?:\\s*,\\s*version\\s*[:=]\\s*['"]([^'"]+)['"])?`,
  'g'
);
const CATALOG_REFERENCE = new RegExp(`\\b(?:${CONFIG_ALT})\\s*\\(?\\s*(?:platform\\s*\\(\\s*)?libs\\.[\\w.]+`, 'g');

export const parseGradle: ManifestParser = (content, source) => {
  const text = content
    .replace(/^\uFEFF/, '')
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^:])\/\/.*$/gm, '$1');
  const out = emptyOutput();
  STRING_NOTATION.lastIndex = 0;
  MAP_NOTATION.lastIndex = 0;

  for (let m = STRING_NOTATION.exec(text); m !== null; m = STRING_NOTATION.exec(text)) {
    const parts = m[4].split(':');
    if (parts.length < 2 || !parts[0] || !parts[1] || /\s/.test(parts[0])) {
      continue; // not a Maven coordinate
    }
    let version: string | null = parts[2] ? parts[2] : null;
    const notes: string[] = [];
    if (version && version.includes('@')) {
      const [v, ext] = version.split('@');
      version = v || null;
      notes.push(`artifact type: ${ext}`);
    }
    if (m[2]) notes.push('platform/BOM');
    out.dependencies.push({
      name: `${parts[0]}:${parts[1]}`,
      version,
      ecosystem: 'Java',
      category: m[1],
      source,
      ...(notes.length > 0 ? { notes: notes.join('; ') } : {}),
    });
  }

  for (let m = MAP_NOTATION.exec(text); m !== null; m = MAP_NOTATION.exec(text)) {
    out.dependencies.push({
      name: `${m[2]}:${m[3]}`,
      version: m[4] ?? null,
      ecosystem: 'Java',
      category: m[1],
      source,
    });
  }

  const catalogRefs = (text.match(CATALOG_REFERENCE) ?? []).length;
  if (catalogRefs > 0) {
    out.warnings.push(`${source}: ${catalogRefs} version-catalog reference(s) (libs.*) not resolved.`);
  }
  return out;
};
