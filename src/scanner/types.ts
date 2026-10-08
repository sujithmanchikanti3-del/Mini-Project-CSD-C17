/**
 * Types for the V0.2 workspace scanner.
 *
 * This is a filesystem-level scan result only. It is NOT the architecture
 * model (components, data flows, trust boundaries) — that is a later milestone.
 */

export type ProjectType = 'Node.js' | 'Python' | 'Java' | 'Go' | 'Rust' | 'Docker';

export interface WorkspaceScanResult {
  workspaceName: string;
  workspacePath: string;
  /** Detected project types, in a stable order. Empty if none recognised. */
  projectTypes: ProjectType[];
  fileCount: number;
  directoryCount: number;
  /** Important config files found, as workspace-relative POSIX paths (e.g. "backend/pom.xml"). */
  configurationFiles: string[];
  /** All scanned files, workspace-relative POSIX paths, sorted. */
  files: string[];
  /** All scanned directories, workspace-relative POSIX paths, sorted. */
  directories: string[];
  /** Excluded directories that were found and deliberately NOT traversed. */
  excludedDirectories: string[];
  /** Non-fatal problems (e.g. unreadable subdirectory). Scan continues past these. */
  warnings: string[];
  /** True if the scan stopped early because the entry limit was reached. */
  truncated: boolean;
}

export interface ScanOptions {
  /** Directory names (not paths) that are never traversed. */
  excludedDirectories?: ReadonlySet<string>;
  /** Safety cap on files + directories recorded. */
  maxEntries?: number;
}

/** Thrown only when the workspace root itself cannot be scanned. */
export class WorkspaceScanError extends Error {
  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = 'WorkspaceScanError';
  }
}
