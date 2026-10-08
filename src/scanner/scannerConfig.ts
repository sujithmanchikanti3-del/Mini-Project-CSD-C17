import { ProjectType } from './types';

/** Directory names that are never traversed. Edit this list to change exclusions. */
export const DEFAULT_EXCLUDED_DIRECTORIES: ReadonlySet<string> = new Set([
  'node_modules',
  '.git',
  '.vscode',
  'out',
  'dist',
  'build',
  'coverage',
]);

/** Safety cap so a huge workspace cannot hang the extension host. */
export const DEFAULT_MAX_ENTRIES = 50_000;

/**
 * Project type -> file names that indicate it.
 * Matching is by file name at any depth (so monorepo sub-projects are found).
 * Existence only; file contents are never read in V0.2.
 */
export const PROJECT_TYPE_RULES: ReadonlyArray<{ type: ProjectType; fileNames: readonly string[] }> = [
  { type: 'Node.js', fileNames: ['package.json'] },
  { type: 'Python', fileNames: ['requirements.txt', 'pyproject.toml', 'Pipfile'] },
  { type: 'Java', fileNames: ['pom.xml', 'build.gradle', 'build.gradle.kts'] },
  { type: 'Go', fileNames: ['go.mod'] },
  { type: 'Rust', fileNames: ['Cargo.toml'] },
  {
    type: 'Docker',
    fileNames: [
      'Dockerfile',
      'docker-compose.yml',
      'docker-compose.yaml',
      'compose.yml',
      'compose.yaml',
    ],
  },
];

/** Every file name that counts as an "important configuration file". Derived from the rules above. */
export const CONFIGURATION_FILE_NAMES: ReadonlySet<string> = new Set(
  PROJECT_TYPE_RULES.flatMap((rule) => rule.fileNames)
);
