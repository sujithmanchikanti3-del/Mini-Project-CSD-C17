import { promises as fs, Dirent } from 'fs';
import * as path from 'path';
import {
  CONFIGURATION_FILE_NAMES,
  DEFAULT_EXCLUDED_DIRECTORIES,
  DEFAULT_MAX_ENTRIES,
  PROJECT_TYPE_RULES,
} from './scannerConfig';
import { ProjectType, ScanOptions, WorkspaceScanError, WorkspaceScanResult } from './types';

/**
 * V0.2 workspace scanner.
 *
 * Filesystem-level only: walks the directory tree, counts files/directories,
 * detects project types and important config files by NAME.
 * Never reads file contents, never parses dependencies, no network access.
 *
 * Deliberately independent of the `vscode` module so it can be unit-tested
 * and reused by later milestones (e.g. a backend service).
 */
export async function scanWorkspace(
  rootPath: string,
  workspaceName: string = path.basename(rootPath),
  options: ScanOptions = {}
): Promise<WorkspaceScanResult> {
  const excluded = options.excludedDirectories ?? DEFAULT_EXCLUDED_DIRECTORIES;
  const maxEntries = options.maxEntries ?? DEFAULT_MAX_ENTRIES;

  await assertReadableDirectory(rootPath);

  const files: string[] = [];
  const directories: string[] = [];
  const excludedDirectories: string[] = [];
  const warnings: string[] = [];
  let truncated = false;

  // Iterative traversal (avoids deep-recursion stack issues). Entries are relative POSIX paths; '' is the root.
  const pending: string[] = [''];

  while (pending.length > 0 && !truncated) {
    const relDir = pending.pop() as string;
    const absDir = path.join(rootPath, relDir);

    let entries: Dirent[];
    try {
      entries = await fs.readdir(absDir, { withFileTypes: true });
    } catch (error) {
      if (relDir === '') {
        throw new WorkspaceScanError(`Cannot read workspace folder: ${describe(error)}`, error);
      }
      warnings.push(`Skipped unreadable directory "${relDir}": ${describe(error)}`);
      continue;
    }

    for (const entry of entries) {
      const relPath = relDir === '' ? entry.name : `${relDir}/${entry.name}`;

      // Symlinks are not followed (prevents cycles and escaping the workspace) and are not counted.
      if (entry.isSymbolicLink()) {
        continue;
      }

      if (entry.isDirectory()) {
        if (excluded.has(entry.name)) {
          excludedDirectories.push(relPath);
          continue;
        }
        directories.push(relPath);
        pending.push(relPath);
      } else if (entry.isFile()) {
        files.push(relPath);
      }

      if (files.length + directories.length >= maxEntries) {
        truncated = true;
        warnings.push(`Scan stopped after ${maxEntries} entries; results are partial.`);
        break;
      }
    }
  }

  files.sort();
  directories.sort();
  excludedDirectories.sort();

  const configurationFiles = files.filter((file) => CONFIGURATION_FILE_NAMES.has(baseName(file)));

  return {
    workspaceName,
    workspacePath: rootPath,
    projectTypes: detectProjectTypes(configurationFiles),
    fileCount: files.length,
    directoryCount: directories.length,
    configurationFiles,
    files,
    directories,
    excludedDirectories,
    warnings,
    truncated,
  };
}

/** Project types implied by the detected configuration files, in rule order. */
function detectProjectTypes(configurationFiles: readonly string[]): ProjectType[] {
  const names = new Set(configurationFiles.map(baseName));
  return PROJECT_TYPE_RULES.filter((rule) => rule.fileNames.some((name) => names.has(name))).map(
    (rule) => rule.type
  );
}

async function assertReadableDirectory(rootPath: string): Promise<void> {
  try {
    const stats = await fs.stat(rootPath);
    if (!stats.isDirectory()) {
      throw new WorkspaceScanError(`Workspace path is not a directory: ${rootPath}`);
    }
  } catch (error) {
    if (error instanceof WorkspaceScanError) {
      throw error;
    }
    throw new WorkspaceScanError(`Cannot access workspace folder: ${describe(error)}`, error);
  }
}

function baseName(relPath: string): string {
  return relPath.slice(relPath.lastIndexOf('/') + 1);
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
