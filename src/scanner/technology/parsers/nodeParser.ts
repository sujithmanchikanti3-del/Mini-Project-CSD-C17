import { DetectedDependency, ManifestParseError, ManifestParser, emptyOutput } from '../types';
import { describeError, isRecord, stripBom } from './common';

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
    throw new ManifestParseError(`Invalid JSON: ${describeError(error)}`);
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
  const note = specifierNote(spec);
  return { ...base, version: spec, ...(note ? { notes: note } : {}) };
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
