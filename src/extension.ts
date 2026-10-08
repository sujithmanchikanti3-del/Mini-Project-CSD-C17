import * as vscode from 'vscode';
import { analyzeProject } from './analyzeProject';
import { formatScanReport, formatScanSummary } from './scanner/formatScanResult';
import { formatTechnologyReport, formatTechnologySummary } from './scanner/technology/formatTechnologyInventory';
import { WorkspaceScanError } from './scanner/types';

/**
 * V0.3 — Technology / Dependency / Version Detection (on top of the V0.2 Workspace Scanner)
 *
 * Command flow:
 *   VS Code Command -> V0.2 Workspace Scan -> V0.3 Technology Detection -> Result Display
 *
 * Deliberately NOT implemented (future milestones): architecture model, STRIDE,
 * NVD/CVE, risk engine, XAI, LLM, database, dashboard, reports, Vision AI.
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
      const message = error instanceof Error ? error.message : String(error);
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

  log(`Scanning workspace: ${folder.uri.fsPath}`);

  try {
    const { scan, technology } = await analyzeProject(folder.uri.fsPath, folder.name);

    outputChannel.clear();
    for (const line of [...formatScanReport(scan), '', ...formatTechnologyReport(technology)]) {
      outputChannel.appendLine(line);
    }
    outputChannel.show(true); // reveal without stealing editor focus

    // Keep the report clean: post-scan diagnostics go to the Debug Console, not the channel.
    console.log(`[Security Architecture] Scan finished: ${scan.fileCount} files, ${scan.directoryCount} directories, ${technology.dependencies.length} dependencies.`);

    vscode.window.showInformationMessage(`${formatScanSummary(scan)} ${formatTechnologySummary(technology)}`);
  } catch (error) {
    if (error instanceof WorkspaceScanError) {
      log(`ERROR: ${error.message}`);
      vscode.window.showErrorMessage(`Security Architecture: ${error.message}`);
      return;
    }
    throw error; // unexpected: handled by the command wrapper
  }
}

function log(message: string): void {
  // Minimal timestamped logging. Note: the channel is cleared when a scan report is written.
  outputChannel.appendLine(`[${new Date().toISOString()}] ${message}`);
}
