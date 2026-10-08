import { DetectedDependency, ManifestParser, emptyOutput } from '../types';
import { isRecord } from './common';
import { dependenciesFromTable, getPath, parseTomlOrThrow } from './tomlHelpers';

const KINDS = ['dependencies', 'dev-dependencies', 'build-dependencies'] as const;

/** Cargo.toml: dependency tables (incl. target-specific and workspace) plus package.rust-version. */
export const parseCargoToml: ManifestParser = (content, source) => {
  const data = parseTomlOrThrow(content);
  const out = emptyOutput();
  const add = (table: unknown, category: string): void => {
    const deps: DetectedDependency[] = dependenciesFromTable(table, 'Rust', category, source, out.warnings);
    out.dependencies.push(...deps);
  };

  for (const kind of KINDS) {
    add(data[kind], kind);
  }
  add(getPath(data, ['workspace', 'dependencies']), 'workspace.dependencies');

  const targets = data.target;
  if (isRecord(targets)) {
    for (const [cfg, body] of Object.entries(targets)) {
      if (!isRecord(body)) continue;
      for (const kind of KINDS) {
        add(body[kind], `target.${cfg}.${kind}`);
      }
    }
  }

  const rustVersion = getPath(data, ['package', 'rust-version']);
  if (typeof rustVersion === 'string') {
    out.technologies.push({
      name: 'Rust',
      version: rustVersion,
      ecosystem: 'Rust',
      source,
      reference: 'package.rust-version',
    });
  }
  return out;
};
