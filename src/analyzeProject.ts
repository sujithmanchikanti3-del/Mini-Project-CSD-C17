import { buildArchitectureModel, emptyArchitectureModel } from './architecture/architectureModelBuilder';
import { ArchitectureModel } from './architecture/types';
import { analyzeStride, emptyStrideAnalysis } from './stride/strideAnalyzer';
import { StrideAnalysis } from './stride/types';
import { scanWorkspace } from './scanner/workspaceScanner';
import { detectTechnologies } from './scanner/technology/technologyDetector';
import { TechnologyInventory } from './scanner/technology/types';
import { WorkspaceScanResult } from './scanner/types';
import { describeError } from './scanner/technology/parsers/common';

/** Combined result of the analysis pipeline so far. Later milestones add fields here. */
export interface ProjectAnalysisResult {
  scan: WorkspaceScanResult; // V0.2
  technology: TechnologyInventory; // V0.3
  architecture: ArchitectureModel; // V0.4
  stride: StrideAnalysis; // V0.5
}

/**
 * Pipeline: V0.2 workspace scan -> V0.3 technology detection -> V0.4 architecture model -> V0.5 STRIDE analysis.
 * A V0.2 failure (unreadable workspace) throws WorkspaceScanError exactly as before.
 * A V0.3 failure never discards the scan: it is reported as a warning on an empty inventory.
 * A V0.4 failure never discards V0.2/V0.3 results: it yields an empty model carrying a warning.
 * A V0.5 failure never discards V0.2-V0.4 results: it yields an empty analysis carrying a warning.
 * Independent of the `vscode` module so it can be tested directly.
 */
export async function analyzeProject(rootPath: string, workspaceName?: string): Promise<ProjectAnalysisResult> {
  const scan = await scanWorkspace(rootPath, workspaceName);

  let technology: TechnologyInventory;
  let technologyFailed = false;
  try {
    technology = await detectTechnologies(scan);
  } catch (error) {
    technologyFailed = true;
    technology = {
      technologies: [],
      dependencies: [],
      sources: [],
      warnings: [`Technology detection failed unexpectedly: ${describeError(error)}`],
    };
  }

  let architecture: ArchitectureModel;
  try {
    architecture = buildArchitectureModel(scan, technology);
  } catch (error) {
    architecture = emptyArchitectureModel(
      scan.workspaceName,
      `Architecture model construction failed unexpectedly: ${describeError(error)}`
    );
  }

  if (technologyFailed) {
    // The model was built from an empty inventory; say so instead of reporting a clean build.
    const note = 'Technology detection failed, so this model contains no dependency or technology information.';
    architecture.warnings.push(note);
    const root = architecture.components.find((c) => c.type === 'Application');
    if (root) root.uncertainty.push(note);
  }

  let stride: StrideAnalysis;
  try {
    stride = analyzeStride(architecture);
  } catch (error) {
    stride = emptyStrideAnalysis(`STRIDE analysis failed unexpectedly: ${describeError(error)}`);
  }
  return { scan, technology, architecture, stride };
}
