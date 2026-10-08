import { DetectedDependency, DetectedTechnology, ManifestParser, ParseOutput, emptyOutput } from '../types';
import { isRecord } from './common';
import { dependenciesFromTable, getPath, parseTomlOrThrow } from './tomlHelpers';

/* ------------------------------------------------------------------ */
/* PEP 508 requirement strings (shared by requirements.txt + pyproject) */
/* ------------------------------------------------------------------ */

export interface ParsedRequirement {
  name: string;
  /** Version specifier exactly as written (">=3.0.0,<4", "==2.31.0"); null if none. */
  version: string | null;
  notes?: string;
}

const NAME_AND_REST = /^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(\[[^\]]*\])?\s*(.*)$/;
const VERSION_SPEC_START = /^(?:===|==|!=|~=|<=|>=|<|>)/;

/** Parse one requirement ("flask[async]>=3.0 ; python_version>'3.8'"). Returns null if unsupported. */
export function parseRequirement(raw: string): ParsedRequirement | null {
  const match = NAME_AND_REST.exec(raw.trim());
  if (!match) {
    return null;
  }
  const name = match[1];
  let rest = match[3].trim();

  if (rest.startsWith('@')) {
    // Direct reference ("pkg @ https://..."): never echo the URL, it may hold credentials.
    return { name, version: null, notes: 'direct URL reference' };
  }

  const semicolon = rest.indexOf(';'); // drop environment marker
  if (semicolon !== -1) {
    rest = rest.slice(0, semicolon).trim();
  }
  if (rest.startsWith('(') && rest.endsWith(')')) {
    rest = rest.slice(1, -1).trim(); // legacy "name (>=1.0)" form
  }

  if (rest === '') {
    return { name, version: null };
  }
  if (!VERSION_SPEC_START.test(rest)) {
    return null;
  }
  return { name, version: rest };
}

function toDependency(
  req: ParsedRequirement,
  category: string,
  source: string
): DetectedDependency {
  return {
    name: req.name,
    version: req.version,
    ecosystem: 'Python',
    category,
    source,
    ...(req.notes ? { notes: req.notes } : {}),
  };
}

/* ------------------------------ requirements.txt ------------------------------ */

export const parseRequirementsTxt: ManifestParser = (content, source) => {
  const out = emptyOutput();
  const lines = content.replace(/^\uFEFF/, '').split(/\r?\n/);
  let unsupported = 0;
  let includes = 0;

  for (let i = 0; i < lines.length; i++) {
    let line = lines[i];
    // Join "\" continuation lines.
    while (line.endsWith('\\') && i + 1 < lines.length) {
      line = line.slice(0, -1) + lines[++i];
    }
    line = line.replace(/(^|\s)#.*$/, '').trim(); // comments start at "#" after whitespace
    if (line === '') {
      continue;
    }
    if (line.startsWith('-')) {
      // Options (-r, -c, -e, --index-url, ...). Never echoed: they can carry credentials.
      if (/^(-r|-c|--requirement|--constraint)\b/.test(line)) includes++;
      else if (/^(-e|--editable)\b/.test(line)) unsupported++;
      continue;
    }
    line = line.split(/\s+--/)[0].trim(); // trailing per-requirement options such as --hash=...
    const req = parseRequirement(line);
    if (req) {
      out.dependencies.push(toDependency(req, 'requirements', source));
    } else {
      unsupported++;
    }
  }

  if (includes > 0) {
    out.warnings.push(`${source}: ${includes} "-r/-c" include line(s) not followed.`);
  }
  if (unsupported > 0) {
    out.warnings.push(`${source}: ${unsupported} line(s) with unsupported syntax (URL, VCS, path or editable) skipped.`);
  }
  return out;
};

/* ------------------------------ pyproject.toml ------------------------------ */

export const parsePyproject: ManifestParser = (content, source) => {
  const data = parseTomlOrThrow(content);
  const out = emptyOutput();
  let unsupported = 0;

  const addRequirements = (value: unknown, category: string): void => {
    if (value === undefined) return;
    if (!Array.isArray(value)) {
      out.warnings.push(`${source}: "${category}" is not an array; skipped.`);
      return;
    }
    for (const item of value) {
      if (typeof item !== 'string') {
        // PEP 735 {include-group = "..."} entries etc. carry no package.
        if (!(isRecord(item) && 'include-group' in item)) unsupported++;
        continue;
      }
      const req = parseRequirement(item);
      if (req) out.dependencies.push(toDependency(req, category, source));
      else unsupported++;
    }
  };

  // PEP 621
  addRequirements(getPath(data, ['project', 'dependencies']), 'dependencies');
  const optional = getPath(data, ['project', 'optional-dependencies']);
  if (isRecord(optional)) {
    for (const [group, list] of Object.entries(optional)) {
      addRequirements(list, `optional-dependencies:${group}`);
    }
  }
  const requiresPython = getPath(data, ['project', 'requires-python']);
  if (typeof requiresPython === 'string') {
    out.technologies.push(pythonTech(requiresPython, source, 'project.requires-python'));
  }

  // PEP 735
  const groups = data['dependency-groups'];
  if (isRecord(groups)) {
    for (const [group, list] of Object.entries(groups)) {
      addRequirements(list, `dependency-groups:${group}`);
    }
  }

  // PEP 517/518
  addRequirements(getPath(data, ['build-system', 'requires']), 'build-system');

  // Poetry
  const poetry = getPath(data, ['tool', 'poetry']);
  if (isRecord(poetry)) {
    const poetryTables: Array<[string, unknown]> = [
      ['dependencies', poetry.dependencies],
      ['dev-dependencies', poetry['dev-dependencies']],
    ];
    const poetryGroups = poetry.group;
    if (isRecord(poetryGroups)) {
      for (const [group, body] of Object.entries(poetryGroups)) {
        poetryTables.push([`group:${group}`, isRecord(body) ? body.dependencies : undefined]);
      }
    }
    for (const [category, table] of poetryTables) {
      out.dependencies.push(
        ...dependenciesFromTable(table, 'Python', category, source, out.warnings, ['python'])
      );
    }
    const poetryDeps = poetry.dependencies;
    if (isRecord(poetryDeps) && typeof poetryDeps.python === 'string') {
      out.technologies.push(pythonTech(poetryDeps.python, source, 'tool.poetry.dependencies.python'));
    }
  }

  if (unsupported > 0) {
    out.warnings.push(`${source}: ${unsupported} requirement(s) with unsupported syntax skipped.`);
  }
  return out;
};

/* ------------------------------ Pipfile ------------------------------ */

export const parsePipfile: ManifestParser = (content, source) => {
  const data = parseTomlOrThrow(content);
  const out: ParseOutput = emptyOutput();

  out.dependencies.push(
    ...dependenciesFromTable(data.packages, 'Python', 'packages', source, out.warnings),
    ...dependenciesFromTable(data['dev-packages'], 'Python', 'dev-packages', source, out.warnings)
  );

  const requires = data.requires;
  if (isRecord(requires)) {
    const version = requires.python_full_version ?? requires.python_version;
    if (typeof version === 'string') {
      const key = requires.python_full_version !== undefined ? 'python_full_version' : 'python_version';
      out.technologies.push(pythonTech(version, source, `requires.${key}`));
    }
  }
  return out;
};

function pythonTech(version: string, source: string, reference: string): DetectedTechnology {
  return { name: 'Python', version, ecosystem: 'Python', source, reference };
}
