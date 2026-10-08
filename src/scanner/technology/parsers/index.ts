import { Ecosystem, ManifestParser } from '../types';
import { parseCompose, parseDockerfile } from './dockerParser';
import { parseGoMod } from './goParser';
import { parseGradle, parsePom } from './javaParser';
import { parsePackageJson } from './nodeParser';
import { parsePipfile, parsePyproject, parseRequirementsTxt } from './pythonParser';
import { parseCargoToml } from './rustParser';

/**
 * Manifest file name -> ecosystem + parser. To support another file, add one line here.
 * Keys match the V0.2 scanner's configuration file names.
 */
export const MANIFEST_PARSERS: Readonly<Record<string, { ecosystem: Ecosystem; parser: ManifestParser }>> = {
  'package.json': { ecosystem: 'Node.js', parser: parsePackageJson },
  'requirements.txt': { ecosystem: 'Python', parser: parseRequirementsTxt },
  'pyproject.toml': { ecosystem: 'Python', parser: parsePyproject },
  Pipfile: { ecosystem: 'Python', parser: parsePipfile },
  'pom.xml': { ecosystem: 'Java', parser: parsePom },
  'build.gradle': { ecosystem: 'Java', parser: parseGradle },
  'build.gradle.kts': { ecosystem: 'Java', parser: parseGradle },
  'go.mod': { ecosystem: 'Go', parser: parseGoMod },
  'Cargo.toml': { ecosystem: 'Rust', parser: parseCargoToml },
  Dockerfile: { ecosystem: 'Docker', parser: parseDockerfile },
  'docker-compose.yml': { ecosystem: 'Docker', parser: parseCompose },
  'docker-compose.yaml': { ecosystem: 'Docker', parser: parseCompose },
  'compose.yml': { ecosystem: 'Docker', parser: parseCompose },
  'compose.yaml': { ecosystem: 'Docker', parser: parseCompose },
};
