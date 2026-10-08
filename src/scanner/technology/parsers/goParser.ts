import { ManifestParser, emptyOutput } from '../types';

/** go.mod: `go` directive plus `require` lines/blocks. replace/exclude directives are not applied. */
export const parseGoMod: ManifestParser = (content, source) => {
  const out = emptyOutput();
  let inRequireBlock = false;
  let sawDirective = false;
  let malformed = 0;

  for (const rawLine of content.replace(/^\uFEFF/, '').split(/\r?\n/)) {
    const indirect = /\/\/\s*indirect\b/.test(rawLine);
    const line = rawLine.replace(/\/\/.*$/, '').trim();
    if (line === '') {
      continue;
    }

    if (inRequireBlock) {
      if (line === ')') {
        inRequireBlock = false;
        continue;
      }
      if (!addRequirement(line, indirect)) malformed++;
      continue;
    }

    if (/^require\s*\($/.test(line)) {
      sawDirective = true;
      inRequireBlock = true;
    } else if (/^require\s+/.test(line)) {
      sawDirective = true;
      if (!addRequirement(line.replace(/^require\s+/, ''), indirect)) malformed++;
    } else if (/^go\s+\S+/.test(line)) {
      sawDirective = true;
      out.technologies.push({
        name: 'Go',
        version: line.split(/\s+/)[1],
        ecosystem: 'Go',
        source,
        reference: 'go directive',
      });
    } else if (/^(module|toolchain|replace|exclude|retract|godebug|tool|ignore)\b/.test(line)) {
      sawDirective = true;
    }
  }

  function addRequirement(spec: string, isIndirect: boolean): boolean {
    const parts = spec.split(/\s+/).map((p) => p.replace(/^"|"$/g, ''));
    if (parts.length < 2 || !parts[0] || !parts[1]) {
      return false;
    }
    out.dependencies.push({
      name: parts[0],
      version: parts[1], // e.g. "v1.2.3" or a pseudo-version, kept exactly
      ecosystem: 'Go',
      category: isIndirect ? 'require (indirect)' : 'require',
      source,
    });
    return true;
  }

  if (!sawDirective && content.trim() !== '') {
    out.warnings.push(`${source}: no recognisable go.mod directives found.`);
  }
  if (malformed > 0) {
    out.warnings.push(`${source}: ${malformed} malformed require line(s) skipped.`);
  }
  return out;
};
