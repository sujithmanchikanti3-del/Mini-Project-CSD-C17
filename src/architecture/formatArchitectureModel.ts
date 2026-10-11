import { stripControlCharacters } from '../common/sanitize';
import { summarizeArchitecture } from './architectureModelBuilder';
import {
  ArchitectureComponent,
  ArchitectureModel,
  COMPONENT_TYPES,
  RELATIONSHIP_TYPES,
} from './types';

const RULE = '────────────────────────────';
const CONTAINER_ROLE_LABEL = { 'build-base-image': 'build base image', 'compose-service': 'compose service' } as const;
/** Upper bound on individually listed components / relationships, to keep the channel readable. */
const MAX_LISTED = 60;

/** Multi-line report section for the Output Channel (appended after the V0.3 report). */
export function formatArchitectureReport(model: ArchitectureModel): string[] {
  const summary = summarizeArchitecture(model);
  const names = new Map(model.components.map((c) => [c.id, c.name]));
  const lines: string[] = ['Security Architecture Model', RULE, ''];

  lines.push(`Components (${summary.componentCount}):`);
  if (summary.componentCount === 0) {
    lines.push('  None');
  }
  for (const type of COMPONENT_TYPES) {
    const n = summary.componentsByType[type];
    if (n) lines.push(`  ${type}: ${n}`);
  }

  lines.push('', `Relationships (${summary.relationshipCount}):`);
  if (summary.relationshipCount === 0) {
    lines.push('  None');
  }
  for (const type of RELATIONSHIP_TYPES) {
    const n = summary.relationshipsByType[type];
    if (n) lines.push(`  ${type}: ${n}`);
  }

  // Library/Dependency components are already itemised by the V0.3 report; list everything else with its evidence.
  const notable = model.components.filter((c) => c.type !== 'Library/Dependency');
  const libraryCount = summary.componentsByType['Library/Dependency'] ?? 0;
  lines.push('', 'Component Details:');
  if (notable.length === 0) {
    lines.push('  None');
  }
  for (const c of notable.slice(0, MAX_LISTED)) {
    lines.push(...componentLines(c));
  }
  if (notable.length > MAX_LISTED) {
    lines.push(`  … and ${notable.length - MAX_LISTED} more component(s) not listed.`);
  }
  if (libraryCount > 0) {
    lines.push(`  (${libraryCount} Library/Dependency component(s) not repeated here; see the dependency list above.)`);
  }

  const listed = model.relationships.filter((r) => r.type !== 'declares-dependency');
  const declaredDependencies = summary.relationshipsByType['declares-dependency'] ?? 0;
  lines.push('', 'Relationship Details:');
  if (listed.length === 0) {
    lines.push('  None');
  }
  for (const r of listed.slice(0, MAX_LISTED)) {
    lines.push(`  • ${names.get(r.sourceId) ?? r.sourceId} —${r.type}→ ${names.get(r.targetId) ?? r.targetId}`);
    lines.push(`      evidence: ${evidenceSummary(r.evidence)}`);
  }
  if (listed.length > MAX_LISTED) {
    lines.push(`  … and ${listed.length - MAX_LISTED} more relationship(s) not listed.`);
  }
  if (declaredDependencies > 0) {
    lines.push(`  (${declaredDependencies} declares-dependency relationship(s) not repeated here.)`);
  }

  if (model.warnings.length > 0) {
    lines.push('', 'Model Warnings:', ...model.warnings.map((w) => `  • ${w}`));
  }

  lines.push(
    '',
    'Note: relationships are limited to declarations found in scanned files (dependencies, base images,',
    'compose services). Runtime connections, network topology and trust boundaries are NOT inferred.',
    '',
    model.components.length === 0
      ? 'Architecture model is empty.'
      : model.warnings.length > 0
        ? 'Architecture model built with warnings.'
        : 'Architecture model built successfully.'
  );
  return lines.map(stripControlCharacters); // names come from the scanned project: no forged lines
}

/** Short sentence for the notification toast. */
export function formatArchitectureSummary(model: ArchitectureModel): string {
  const s = summarizeArchitecture(model);
  return `Architecture model: ${s.componentCount} ${s.componentCount === 1 ? 'component' : 'components'}, ${s.relationshipCount} ${s.relationshipCount === 1 ? 'relationship' : 'relationships'}.`;
}

function componentLines(c: ArchitectureComponent): string[] {
  const role = c.containerRole ? ` — ${CONTAINER_ROLE_LABEL[c.containerRole]}` : '';
  const lines = [`  • [${c.type}] ${c.name} (${c.certainty})${role}`];
  lines.push(`      id: ${c.id}`);
  lines.push(`      evidence: ${evidenceSummary(c.evidence)}`);
  for (const u of c.uncertainty) {
    lines.push(`      uncertainty: ${u}`);
  }
  return lines;
}

function evidenceSummary(evidence: ReadonlyArray<{ source: string; rule: string; description: string }>): string {
  if (evidence.length === 0) return '(none)';
  const first = evidence[0];
  const more = evidence.length > 1 ? ` (+${evidence.length - 1} more)` : '';
  return `${first.description} [rule: ${first.rule}]${more}`;
}
