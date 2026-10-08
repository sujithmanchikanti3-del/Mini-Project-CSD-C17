import { ProjectType } from '../types';

/**
 * Types for V0.3 — Technology / Dependency / Version Detection.
 *
 * Everything here is derived from files already in the workspace. Nothing is
 * downloaded, resolved against a registry, or invented: when a file does not
 * declare a version, `version` is null.
 */

/** Same vocabulary as V0.2 project types. */
export type Ecosystem = ProjectType;

/** A declared package/library dependency. */
export interface DetectedDependency {
  /** Package name as written (Maven: "groupId:artifactId", Go: module path). */
  name: string;
  /**
   * Declared version or range EXACTLY as written in the file ("^4.18.2", ">=3.0.0",
   * "v1.2.3", "${spring.version}"). Never normalised. null = none declared.
   */
  version: string | null;
  ecosystem: Ecosystem;
  /** Where in the manifest it was declared (e.g. "devDependencies", "require (indirect)", "test"). */
  category: string;
  /** Workspace-relative POSIX path of the declaring file. */
  source: string;
  /**
   * Maven only: value of `version` when it is a "${property}" defined with a literal value in the
   * same pom.xml. Kept separate so `version` still shows what was declared.
   */
  resolvedVersion?: string;
  /** Short factual remark about the entry (e.g. "git dependency", "direct URL reference"). */
  notes?: string;
}

/** A runtime / platform / base image the project declares (not a library dependency). */
export interface DetectedTechnology {
  /** Runtime name or image repository as written ("Node.js", "Python", "node", "postgres"). */
  name: string;
  /** Declared version / constraint / image tag exactly as written. null = none declared. */
  version: string | null;
  ecosystem: Ecosystem;
  source: string;
  /** Raw declaration, e.g. the image reference "node:20-alpine" or "engines.node". */
  reference?: string;
  notes?: string;
}

export type ManifestStatus = 'parsed' | 'partial' | 'error';

/** Per-file outcome, so the user can see what was and was not read. */
export interface ManifestSource {
  path: string;
  ecosystem: Ecosystem;
  status: ManifestStatus;
  dependencyCount: number;
  technologyCount: number;
  /** Present when status is 'partial' or 'error'. Never contains file content. */
  message?: string;
}

export interface TechnologyInventory {
  technologies: DetectedTechnology[];
  dependencies: DetectedDependency[];
  /** Every manifest that was examined. */
  sources: ManifestSource[];
  /** Non-fatal problems, never containing file content. */
  warnings: string[];
}

/** What a single manifest parser returns. */
export interface ParseOutput {
  dependencies: DetectedDependency[];
  technologies: DetectedTechnology[];
  warnings: string[];
}

/** Pure function: file content in, findings out. Must not touch the filesystem or network. */
export type ManifestParser = (content: string, source: string) => ParseOutput;

/** Thrown by a parser when the file is unusable (invalid JSON/TOML, not a POM, ...). */
export class ManifestParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ManifestParseError';
  }
}

export function emptyOutput(): ParseOutput {
  return { dependencies: [], technologies: [], warnings: [] };
}
