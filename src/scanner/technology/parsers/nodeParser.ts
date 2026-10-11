import { DetectedDependency, ManifestParseError, ManifestParser, emptyOutput } from '../types';
import { redactCredentials } from '../../../common/sanitize';
import { isRecord, stripBom } from './common';

const DEPENDENCY_SECTIONS = [
  'dependencies',
  'devDependencies',
  'peerDependencies',
  'optionalDependencies',
] as const;

/** Specifiers that do not point at the npm registry, so a version cannot be matched against registry data. */
const NON_REGISTRY = /^(file:|link:|workspace:|git\+|git:|github:|gitlab:|bitbucket:|https?:\/\/)/i;
const GITHUB_SHORTHAND = /^[\w.-]+\/[\w.-]+(#.*)?$/;

/** package.json: the four dependency sections plus engines.node. Versions are kept verbatim. */
export const parsePackageJson: ManifestParser = (content, source) => {
  let data: unknown;
  try {
    data = JSON.parse(stripBom(content));
  } catch (error) {
    // Node's JSON error text can quote a slice of the file (possibly a secret); report only the position.
    const position = /at position (\d+)/.exec(error instanceof Error ? error.message : '');
    throw new ManifestParseError(`Invalid JSON (syntax error${position ? ` at position ${position[1]}` : ''})`);
  }
  if (!isRecord(data)) {
    throw new ManifestParseError('package.json root is not a JSON object.');
  }

  const out = emptyOutput();

  for (const section of DEPENDENCY_SECTIONS) {
    const value = data[section];
    if (value === undefined) {
      continue;
    }
    if (!isRecord(value)) {
      out.warnings.push(`${source}: "${section}" is not an object; skipped.`);
      continue;
    }
    for (const [name, spec] of Object.entries(value)) {
      out.dependencies.push(toDependency(name, spec, section, source));
    }
  }

  const engines = data.engines;
  if (isRecord(engines) && typeof engines.node === 'string') {
    out.technologies.push({
      name: 'Node.js',
      version: engines.node,
      ecosystem: 'Node.js',
      source,
      reference: 'engines.node',
    });
  }

  return out;
};

function toDependency(name: string, spec: unknown, category: string, source: string): DetectedDependency {
  const base = { name, ecosystem: 'Node.js' as const, category, source };
  if (typeof spec !== 'string') {
    return { ...base, version: null, notes: 'unsupported version value type' };
  }
  // npm specifiers can embed credentials ("git+https://user:token@host/..."); keep everything else exact.
  const version = redactCredentials(spec);
  const notes = [specifierNote(spec), version !== spec ? 'credentials in the specifier were redacted' : undefined].filter(Boolean);
  return { ...base, version, ...(notes.length > 0 ? { notes: notes.join('; ') } : {}) };
}

function specifierNote(spec: string): string | undefined {
  if (spec.startsWith('npm:')) {
    return `alias for ${spec.slice(4)}`;
  }
  if (NON_REGISTRY.test(spec) || GITHUB_SHORTHAND.test(spec)) {
    return 'non-registry specifier';
  }
  return undefined;
}
