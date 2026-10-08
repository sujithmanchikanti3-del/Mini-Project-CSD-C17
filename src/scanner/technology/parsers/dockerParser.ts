import { DetectedTechnology, ManifestParser, emptyOutput } from '../types';

/* ============================== image references ============================== */

export interface ImageReference {
  /** Repository as written, without tag/digest ("node", "mcr.microsoft.com/dotnet/aspnet"). */
  name: string;
  tag: string | null;
  digest: string | null;
}

/** Split "registry:5000/team/app:1.2@sha256:abc" into name / tag / digest without altering any part. */
export function parseImageReference(ref: string): ImageReference {
  let rest = ref;
  let digest: string | null = null;
  const at = rest.indexOf('@');
  if (at !== -1) {
    digest = rest.slice(at + 1);
    rest = rest.slice(0, at);
  }
  // A ":" only starts a tag if it comes after the last "/" (otherwise it is a registry port).
  const colon = rest.lastIndexOf(':');
  if (colon !== -1 && colon > rest.lastIndexOf('/')) {
    return { name: rest.slice(0, colon), tag: rest.slice(colon + 1), digest };
  }
  return { name: rest, tag: null, digest };
}

function toTechnology(ref: string, source: string, extraNote?: string): DetectedTechnology {
  const parsed = parseImageReference(ref);
  const notes: string[] = [];
  if (parsed.tag === null && parsed.digest === null) notes.push('no tag (Docker treats this as "latest")');
  if (parsed.tag === null && parsed.digest !== null) notes.push('pinned by digest');
  if (/\$\{?\w/.test(ref)) notes.push('uses a variable; value not resolved');
  if (extraNote) notes.push(extraNote);
  return {
    name: parsed.name,
    version: parsed.tag ?? parsed.digest,
    ecosystem: 'Docker',
    source,
    reference: ref,
    ...(notes.length > 0 ? { notes: notes.join('; ') } : {}),
  };
}

/* ============================== Dockerfile ============================== */

/** Reads FROM lines only. Multi-stage references to earlier stages and `scratch` are not images. */
export const parseDockerfile: ManifestParser = (content, source) => {
  const out = emptyOutput();
  const lines = content.replace(/^\uFEFF/, '').split(/\r?\n/);
  const stages = new Set<string>();
  let stageNumber = 0;

  for (let i = 0; i < lines.length; i++) {
    let line = lines[i];
    while (line.trimEnd().endsWith('\\') && i + 1 < lines.length) {
      line = line.trimEnd().slice(0, -1) + ' ' + lines[++i];
    }
    line = line.trim();
    if (line === '' || line.startsWith('#')) {
      continue;
    }
    const match = /^FROM\s+(.+)$/i.exec(line);
    if (!match) {
      continue;
    }
    stageNumber++;
    const tokens = match[1].replace(/\s+#.*$/, '').split(/\s+/).filter((t) => !t.startsWith('--'));
    if (tokens.length === 0) {
      out.warnings.push(`${source}: FROM instruction #${stageNumber} has no image; skipped.`);
      continue;
    }
    const image = tokens[0];
    const isEarlierStage = stages.has(image.toLowerCase()); // "FROM builder" is not an image
    const asIndex = tokens.findIndex((t) => t.toUpperCase() === 'AS');
    if (asIndex !== -1 && tokens[asIndex + 1]) {
      stages.add(tokens[asIndex + 1].toLowerCase());
    }
    if (image.toLowerCase() === 'scratch' || isEarlierStage) {
      continue;
    }
    out.technologies.push(toTechnology(image, source, `build stage ${stageNumber}`));
  }
  return out;
};

/* ============================== docker-compose / compose ============================== */

/**
 * Reads `image:` values per service, using indentation (no YAML library).
 * Services that only use `build:` have no image and are not reported.
 */
export const parseCompose: ManifestParser = (content, source) => {
  const out = emptyOutput();
  const lines = content.replace(/^\uFEFF/, '').split(/\r?\n/);

  let servicesIndent = -1;
  let serviceKeyIndent = -1;
  let propertyIndent = -1; // indentation of a service's own keys (image, build, environment, ...)
  let currentService: string | undefined;

  for (const rawLine of lines) {
    const line = rawLine.replace(/\s+#.*$/, '');
    if (line.trim() === '' || line.trim().startsWith('#')) {
      continue;
    }
    const indent = line.length - line.trimStart().length;
    const trimmed = line.trim();

    if (servicesIndent === -1) {
      if (/^services:\s*$/.test(trimmed)) servicesIndent = indent;
      continue;
    }
    if (indent <= servicesIndent) {
      servicesIndent = /^services:\s*$/.test(trimmed) ? indent : -1; // left the services block
      serviceKeyIndent = -1;
      propertyIndent = -1;
      currentService = undefined;
      continue;
    }
    if (serviceKeyIndent === -1) {
      serviceKeyIndent = indent;
    }
    if (indent === serviceKeyIndent) {
      const key = /^([^:#\s][^:]*):\s*$/.exec(trimmed);
      currentService = key ? key[1].replace(/^["']|["']$/g, '') : undefined;
      propertyIndent = -1;
      continue;
    }
    if (propertyIndent === -1) {
      propertyIndent = indent;
    }
    const image = /^image:\s*(.+)$/.exec(trimmed);
    if (image && currentService !== undefined && indent === propertyIndent) {
      const ref = image[1].trim().replace(/^["']|["']$/g, '');
      if (ref !== '') {
        out.technologies.push(toTechnology(ref, source, `service "${currentService}"`));
      }
    }
  }
  return out;
};
