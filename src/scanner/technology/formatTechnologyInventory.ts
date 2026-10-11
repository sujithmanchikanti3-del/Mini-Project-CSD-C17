import { stripControlCharacters } from '../../common/sanitize';
import { DetectedDependency, TechnologyInventory } from './types';

const RULE = '────────────────────────────';

/** Multi-line report section for the Output Channel (appended after the V0.2 scan report). */
export function formatTechnologyReport(inventory: TechnologyInventory): string[] {
  const lines: string[] = ['Technology / Dependency Detection', RULE, ''];

  lines.push('Manifests Analysed:');
  if (inventory.sources.length === 0) {
    lines.push('  None found');
  }
  for (const s of inventory.sources) {
    const detail =
      s.status === 'error'
        ? `FAILED — ${s.message ?? 'unknown error'}`
        : `${s.dependencyCount} ${plural(s.dependencyCount, 'dependency', 'dependencies')}, ` +
          `${s.technologyCount} ${plural(s.technologyCount, 'technology', 'technologies')}`;
    lines.push(`  • ${s.path} (${s.ecosystem}): ${detail}`);
  }

  lines.push('', 'Technologies:');
  if (inventory.technologies.length === 0) {
    lines.push('  None detected');
  }
  for (const t of inventory.technologies) {
    const where = [t.reference, t.notes].filter(Boolean).join(' — ');
    lines.push(`  • ${t.name} ${displayVersion(t.version)}  [${where ? where + ', ' : ''}${t.source}]`);
  }

  lines.push('', `Dependencies (${inventory.dependencies.length}):`);
  if (inventory.dependencies.length === 0) {
    lines.push('  None detected');
  }
  lines.push(...groupedDependencyLines(inventory.dependencies));

  if (inventory.warnings.length > 0) {
    lines.push('', 'Warnings:', ...inventory.warnings.map((w) => `  • ${w}`));
  }

  const failed = inventory.sources.filter((s) => s.status === 'error').length;
  lines.push(
    '',
    failed > 0
      ? `Technology detection completed with ${failed} unreadable manifest(s).`
      : inventory.warnings.length > 0
        ? 'Technology detection completed with warnings.'
        : 'Technology detection completed successfully.'
  );
  return lines.map(stripControlCharacters); // names come from the scanned project: no forged lines
}

/** Short sentence for the notification toast. */
export function formatTechnologySummary(inventory: TechnologyInventory): string {
  const failed = inventory.sources.filter((s) => s.status === 'error').length;
  const base =
    `${inventory.dependencies.length} ${plural(inventory.dependencies.length, 'dependency', 'dependencies')}, ` +
    `${inventory.technologies.length} ${plural(inventory.technologies.length, 'technology', 'technologies')} detected`;
  return failed > 0 ? `${base}; ${failed} manifest(s) could not be read.` : `${base}.`;
}

/** Ecosystem -> source file -> category, keeping declaration order. */
function groupedDependencyLines(dependencies: readonly DetectedDependency[]): string[] {
  const groups = new Map<string, Map<string, DetectedDependency[]>>();
  for (const dep of dependencies) {
    const fileKey = `${dep.ecosystem} — ${dep.source}`;
    const byCategory = groups.get(fileKey) ?? new Map<string, DetectedDependency[]>();
    const list = byCategory.get(dep.category) ?? [];
    list.push(dep);
    byCategory.set(dep.category, list);
    groups.set(fileKey, byCategory);
  }

  const lines: string[] = [];
  for (const [fileKey, byCategory] of groups) {
    lines.push(`  ${fileKey}`);
    for (const [category, list] of byCategory) {
      lines.push(`    ${category}:`);
      for (const dep of list) {
        lines.push(`      • ${dep.name} ${describeVersion(dep)}`);
      }
    }
  }
  return lines;
}

function describeVersion(dep: DetectedDependency): string {
  let text = displayVersion(dep.version);
  if (dep.resolvedVersion !== undefined) text += ` (property resolves to ${dep.resolvedVersion})`;
  if (dep.notes) text += ` — ${dep.notes}`;
  return text;
}

function displayVersion(version: string | null): string {
  if (version === null) return '(no version declared)';
  return version === '' ? '(empty)' : version;
}

function plural(count: number, one: string, many: string): string {
  return count === 1 ? one : many;
}
