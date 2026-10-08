import { promises as fs } from 'fs';
import * as path from 'path';
import { WorkspaceScanResult } from '../types';
import { MANIFEST_PARSERS } from './parsers';
import { describeError } from './parsers/common';
import { ManifestSource, ManifestParseError, TechnologyInventory } from './types';

/** Manifests larger than this are skipped rather than read into memory. */
export const MAX_MANIFEST_BYTES = 2 * 1024 * 1024;

/**
 * V0.3 technology / dependency / version detection.
 *
 * Consumes the V0.2 WorkspaceScanResult: only files the scanner already identified as
 * configuration files are opened, read-only, as text. Nothing is executed, installed,
 * downloaded, or sent anywhere. A broken manifest is reported and skipped; it never throws.
 */
export async function detectTechnologies(scan: WorkspaceScanResult): Promise<TechnologyInventory> {
  const inventory: TechnologyInventory = { technologies: [], dependencies: [], sources: [], warnings: [] };

  for (const relPath of scan.configurationFiles) {
    const entry = MANIFEST_PARSERS[baseName(relPath)];
    if (!entry) {
      continue; // scanner and parser registry out of sync; nothing to do for this file
    }

    const source: ManifestSource = {
      path: relPath,
      ecosystem: entry.ecosystem,
      status: 'parsed',
      dependencyCount: 0,
      technologyCount: 0,
    };

    try {
      const content = await readManifest(path.join(scan.workspacePath, relPath));
      const result = entry.parser(content, relPath);
      inventory.dependencies.push(...result.dependencies);
      inventory.technologies.push(...result.technologies);
      inventory.warnings.push(...result.warnings);
      source.dependencyCount = result.dependencies.length;
      source.technologyCount = result.technologies.length;
      if (result.warnings.length > 0) {
        source.status = 'partial';
        source.message = `${result.warnings.length} warning(s)`;
      }
    } catch (error) {
      source.status = 'error';
      source.message = error instanceof ManifestParseError ? error.message : `Could not read file: ${describeError(error)}`;
      inventory.warnings.push(`${relPath}: ${source.message}`);
    }
    inventory.sources.push(source);
  }

  return inventory;
}

async function readManifest(absPath: string): Promise<string> {
  const stats = await fs.stat(absPath);
  if (!stats.isFile()) {
    throw new Error('not a regular file');
  }
  if (stats.size > MAX_MANIFEST_BYTES) {
    throw new Error(`file is larger than ${MAX_MANIFEST_BYTES} bytes`);
  }
  return fs.readFile(absPath, 'utf8');
}

function baseName(relPath: string): string {
  return relPath.slice(relPath.lastIndexOf('/') + 1);
}
