import * as vscode from 'vscode';
import { analyzeProject } from './analyzeProject';
import { formatArchitectureReport, formatArchitectureSummary } from './architecture/formatArchitectureModel';
import { formatScanReport, formatScanSummary } from './scanner/formatScanResult';
import { formatStrideReport, formatStrideSummary } from './stride/formatStrideAnalysis';
import { formatTechnologyReport, formatTechnologySummary } from './scanner/technology/formatTechnologyInventory';
import { sanitizeErrorMessage, stripControlCharacters } from './common/sanitize';
import { WorkspaceScanError } from './scanner/types';

/**
 * V0.5 — Deterministic STRIDE threat analysis (on top of V0.2 scan, V0.3 detection and V0.4 model)
 *
 * Command flow:
 *   VS Code Command -> V0.2 Workspace Scan -> V0.3 Technology Detection -> V0.4 Architecture Model
 *                   -> V0.5 STRIDE Analysis -> Result Display
 *
 * Deliberately NOT implemented (future milestones): risk scoring, NVD/CVE, XAI,
 * LLM, database, dashboard, reports, Vision AI.
 */

let outputChannel: vscode.OutputChannel;

const COMMAND_ID = 'securityArchitectureAssessment.analyzeProject';

export function activate(context: vscode.ExtensionContext): void {
  outputChannel = vscode.window.createOutputChannel('Security Architecture');
  context.subscriptions.push(outputChannel);

  log('Extension activated.');

  const disposable = vscode.commands.registerCommand(COMMAND_ID, async () => {
    try {
      await runAnalyzeProjectCommand();
    } catch (error) {
      const message = sanitizeErrorMessage(error);
      log(`ERROR: ${message}`);
      vscode.window.showErrorMessage(`Security Architecture: ${message}`);
    }
  });

  context.subscriptions.push(disposable);
}

export function deactivate(): void {
  log('Extension deactivated.');
}

/** Handler for "Security Architecture: Analyze Project". */
async function runAnalyzeProjectCommand(): Promise<void> {
  log(`Command "${COMMAND_ID}" invoked.`);

  const workspaceFolders = vscode.workspace.workspaceFolders;

  if (!workspaceFolders || workspaceFolders.length === 0) {
    log('No workspace folder is open. Aborting.');
    vscode.window.showWarningMessage('Please open a workspace before running the security analysis.');
    return;
  }

  // Multi-root workspaces: only the first folder is scanned for now.
  const folder = workspaceFolders[0];

  if (folder.uri.scheme !== 'file') {
    log(`Unsupported workspace scheme: ${folder.uri.scheme}`);
    vscode.window.showErrorMessage(
      'Security Architecture: only local workspace folders can be scanned (remote/virtual workspaces are not supported yet).'
    );
    return;
  }

  log(`Scanning workspace "${folder.name}".`);

  try {
    const { scan, technology, architecture, stride } = await analyzeProject(folder.uri.fsPath, folder.name);

    // Each section is rendered independently: a failure in a later section must not hide earlier valid results.
    const reportLines = [
      ...renderSection('Workspace scan', () => formatScanReport(scan)),
      '',
      ...renderSection('Technology / dependency detection', () => formatTechnologyReport(technology)),
      '',
      ...renderSection('Architecture model', () => formatArchitectureReport(architecture)),
      '',
      ...renderSection('STRIDE threat analysis', () => formatStrideReport(stride)),
    ];

    outputChannel.clear();
    for (const line of reportLines) {
      // Names come from the scanned project (untrusted): no embedded newlines/escape codes in the output.
      outputChannel.appendLine(stripControlCharacters(line));
    }
    outputChannel.show(true); // reveal without stealing editor focus

    // Keep the report clean: post-scan diagnostics go to the Debug Console, not the channel.
    console.log(`[Security Architecture] Scan finished: ${scan.fileCount} files, ${scan.directoryCount} directories, ${technology.dependencies.length} dependencies, ${architecture.components.length} components, ${stride.threats.length} candidate threats.`);

    vscode.window.showInformationMessage(
      stripControlCharacters(
        [
          renderText(() => formatScanSummary(scan)),
          renderText(() => formatTechnologySummary(technology)),
          renderText(() => formatArchitectureSummary(architecture)),
          renderText(() => formatStrideSummary(stride)),
        ]
          .filter(Boolean)
          .join(' ')
      )
    );
  } catch (error) {
    if (error instanceof WorkspaceScanError) {
      const message = sanitizeErrorMessage(error);
      log(`ERROR: ${message}`);
      vscode.window.showErrorMessage(`Security Architecture: ${message}`);
      return;
    }
    throw error; // unexpected: handled by the command wrapper
  }
}

/** Build one report section; if formatting fails, say so in place of the section instead of losing the whole report. */
function renderSection(title: string, build: () => string[]): string[] {
  try {
    return build();
  } catch (error) {
    console.error(`[Security Architecture] Could not format "${title}": ${sanitizeErrorMessage(error)}`);
    return [`${title}: this section could not be displayed (${sanitizeErrorMessage(error)}).`];
  }
}

function renderText(build: () => string): string {
  try {
    return build();
  } catch {
    return '';
  }
}

function log(message: string): void {
  // Minimal timestamped logging. Note: the channel is cleared when a scan report is written.
  outputChannel.appendLine(`[${new Date().toISOString()}] ${message}`);
}
