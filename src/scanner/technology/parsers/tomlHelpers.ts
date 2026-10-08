import { parse as parseToml } from 'smol-toml';
import { DetectedDependency, Ecosystem, ManifestParseError } from '../types';
import { firstLine, isRecord, stripBom } from './common';

/** Parse TOML, converting parser failures into a ManifestParseError without echoing file content. */
export function parseTomlOrThrow(content: string): Record<string, unknown> {
  try {
    return parseToml(stripBom(content));
  } catch (error) {
    const e = error as { message?: string; line?: number; column?: number };
    const where = e.line !== undefined ? ` (line ${e.line}, column ${e.column ?? '?'})` : '';
    const reason = firstLine(e.message ?? String(error)).replace(/^Invalid TOML document:\s*/i, '');
    throw new ManifestParseError(`Invalid TOML: ${reason}${where}`);
  }
}

/** Walk a path of keys through nested tables; undefined if any step is missing or not a table. */
export function getPath(root: unknown, keys: readonly string[]): unknown {
  let current: unknown = root;
  for (const key of keys) {
    if (!isRecord(current)) {
      return undefined;
    }
    current = current[key];
  }
  return current;
}

/**
 * Turn a { name: spec } TOML table into dependencies. A spec is:
 *   - a string               -> that string is the declared version (kept exactly)
 *   - a table                -> `version` if it is a string; otherwise a note says why there is none
 *   - an array (Poetry)      -> one dependency per alternative constraint
 * Used for Cargo, Pipfile and Poetry, whose dependency tables share this shape.
 */
export function dependenciesFromTable(
  table: unknown,
  ecosystem: Ecosystem,
  category: string,
  source: string,
  warnings: string[],
  skipNames: readonly string[] = []
): DetectedDependency[] {
  if (table === undefined) {
    return [];
  }
  if (!isRecord(table)) {
    warnings.push(`${source}: "${category}" is not a table; skipped.`);
    return [];
  }

  const found: DetectedDependency[] = [];
  for (const [key, spec] of Object.entries(table)) {
    if (skipNames.includes(key)) {
      continue;
    }
    const specs = Array.isArray(spec) ? spec : [spec];
    for (const single of specs) {
      found.push(dependencyFromSpec(key, single, ecosystem, category, source));
    }
  }
  return found;
}

function dependencyFromSpec(
  key: string,
  spec: unknown,
  ecosystem: Ecosystem,
  category: string,
  source: string
): DetectedDependency {
  const base = { name: key, version: null as string | null, ecosystem, category, source };

  if (typeof spec === 'string') {
    return { ...base, version: spec };
  }
  if (!isRecord(spec)) {
    return { ...base, notes: 'unsupported dependency value type' };
  }

  const notes: string[] = [];
  let name = key;
  if (typeof spec.package === 'string' && spec.package !== key) {
    name = spec.package; // Cargo: `alias = { package = "real-crate" }`
    notes.push(`declared as "${key}"`);
  }

  let version: string | null = null;
  if (typeof spec.version === 'string') {
    version = spec.version;
  } else {
    if (spec.workspace === true) notes.push('version managed by workspace');
    if (typeof spec.git === 'string') notes.push('git dependency');
    if (typeof spec.path === 'string') notes.push('path dependency');
    if (typeof spec.url === 'string') notes.push('URL dependency');
    if (notes.length === 0) notes.push('no version declared');
  }

  return { ...base, name, version, ...(notes.length > 0 ? { notes: notes.join('; ') } : {}) };
}
