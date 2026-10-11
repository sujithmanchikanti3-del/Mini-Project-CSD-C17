import { stripControlCharacters } from '../common/sanitize';
import { WorkspaceScanResult } from './types';

const RULE = '────────────────────────────';

/** Multi-line report for the Output Channel. */
export function formatScanReport(result: WorkspaceScanResult): string[] {
  const lines: string[] = [
    'Security Architecture Scan',
    RULE,
    '',
    `Workspace: ${result.workspaceName}`,
    '',
    'Project Types:',
    ...bullets(result.projectTypes, 'None detected'),
    '',
    `Files: ${result.fileCount}`,
    `Directories: ${result.directoryCount}`,
    '',
    'Configuration Files:',
    ...bullets(result.configurationFiles, 'None found'),
    '',
    'Excluded Directories (not scanned):',
    ...bullets(result.excludedDirectories, 'None found'),
  ];

  if (result.warnings.length > 0) {
    lines.push('', 'Warnings:', ...bullets(result.warnings, ''));
  }

  lines.push('', result.truncated ? 'Workspace scan finished with partial results.' : 'Workspace scan completed successfully.');
  return lines.map(stripControlCharacters); // paths come from the scanned project: no forged lines
}

/** One-line summary for the notification toast. */
export function formatScanSummary(result: WorkspaceScanResult): string {
  const types = result.projectTypes.length > 0 ? result.projectTypes.join(', ') : 'no recognised project type';
  return (
    `Scan of "${result.workspaceName}" complete: ${types} — ` +
    `${result.fileCount} files, ${result.directoryCount} directories, ` +
    `${result.configurationFiles.length} configuration file(s).`
  );
}

function bullets(items: readonly string[], emptyText: string): string[] {
  return items.length > 0 ? items.map((item) => `  • ${item}`) : [`  ${emptyText}`];
}
