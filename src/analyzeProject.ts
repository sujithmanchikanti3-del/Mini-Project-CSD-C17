import { scanWorkspace } from './scanner/workspaceScanner';
import { detectTechnologies } from './scanner/technology/technologyDetector';
import { TechnologyInventory } from './scanner/technology/types';
import { WorkspaceScanResult } from './scanner/types';
import { describeError } from './scanner/technology/parsers/common';

/** Combined result of the analysis pipeline so far. Later milestones add fields here. */
export interface ProjectAnalysisResult {
  scan: WorkspaceScanResult; // V0.2
  technology: TechnologyInventory; // V0.3
}

/**
 * Pipeline: V0.2 workspace scan -> V0.3 technology detection.
 * A V0.2 failure (unreadable workspace) throws WorkspaceScanError exactly as before.
 * A V0.3 failure never discards the scan: it is reported as a warning on an empty inventory.
 * Independent of the `vscode` module so it can be tested directly.
 */
export async function analyzeProject(rootPath: string, workspaceName?: string): Promise<ProjectAnalysisResult> {
  const scan = await scanWorkspace(rootPath, workspaceName);

  let technology: TechnologyInventory;
  try {
    technology = await detectTechnologies(scan);
  } catch (error) {
    technology = {
      technologies: [],
      dependencies: [],
      sources: [],
      warnings: [`Technology detection failed unexpectedly: ${describeError(error)}`],
    };
  }
  return { scan, technology };
}
